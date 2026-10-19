// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2026, SCANOSS
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/settings"
)

// resolveSettings picks the scanoss.json to use: --settings when given, otherwise whatever
// autodetection finds next to the target. No file is not an error — it returns a nil Settings,
// which every consumer of one already accepts.
//
// The priority is the CLI's, so it lives here. pkg/settings offers the two primitives it composes
// (Detect and Load) and knows nothing about flags — a library function whose first parameter is a
// flag value leaves an SDK consumer passing "" to say "I have no flags".
func resolveSettings(settingsFlag, targetPath string) (*settings.Settings, error) {
	if settingsFlag == "" {
		path := settings.Detect(targetPath)
		if path == "" {
			return nil, nil
		}
		return settings.Load(path)
	}

	// An explicit path is checked before loading, so a typo reports the path it looked for
	// rather than a parse failure on a file that is not there.
	//
	// Only a relative path is made absolute. filepath.Abs cleans as it goes, and cleaning
	// resolves ".." by editing the string: through a symlinked directory that names a different
	// file than the one the OS would open, and the error would name a path the user never typed.
	path := settingsFlag
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("error resolving settings path: %w", err)
		}
		path = abs
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("settings file not found: %s", path)
	}
	return settings.Load(path)
}

// usageError shows a command's help and returns an error naming what it was missing. It is how a
// command reports being invoked without the input it needs.
//
// Both halves matter. The help goes to stderr because the command produced no result, and help
// written to stdout lands wherever the results were meant to: `scan $DIR --output r.json` with an
// empty variable would otherwise fill the pipe with usage text. And returning an error is what
// makes the exit code non-zero — without it a CI step that scanned nothing reports success, which
// for a compliance gate is the one failure nobody notices.
//
// A parent command invoked with no subcommand is not this case: it was not asked to do anything,
// so it prints its help and succeeds.
func usageError(cmd *cobra.Command, format string, args ...any) error {
	restore := cmd.OutOrStdout()
	cmd.SetOut(cmd.ErrOrStderr())
	_ = cmd.Help()
	cmd.SetOut(restore)
	return fmt.Errorf(format, args...)
}

// validateOutputTarget rejects an --output path that cannot be written to.
//
// It runs from the root's PersistentPreRunE, so every command is covered without each one
// remembering to ask — which is how `scan` came to fingerprint, upload and poll a whole tree
// before discovering the directory did not exist, throwing away the time, the API call and the
// result it had just computed. A command with no --output flag reads an empty path and passes.
//
// The file is not created here. A run that fails later should leave nothing behind rather than an
// empty file where results were expected. Only the directory is checked — the mistake that
// actually happens is a typo, or a directory nobody made — so this is a pre-flight check and not a
// promise: permissions can still refuse the write when it comes.
func validateOutputTarget(cmd *cobra.Command) error {
	path, _ := cmd.Flags().GetString("output")
	if path == "" {
		return nil // stdout, or a command with no --output at all
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cannot write to %s: %s is not a directory", path, dir)
	}
	return nil
}

// createCancellableContext creates a context that can be cancelled with CTRL+C
func createCancellableContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling for graceful cancellation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprint(os.Stderr, "\n\n")
		warnf("Received interrupt signal. Cancelling...")
		cancel()
	}()

	return ctx, cancel
}

// validateSizeBounds checks the --min-size / --max-size pair before any file is
// read. On either bound, 0 means "no bound" (no minimum / unlimited), so 0 is
// always valid
func validateSizeBounds(min, max int64) error {
	if min < 0 {
		return fmt.Errorf("--min-size must not be negative (got %d); the default 0 admits every file", min)
	}
	if max < 0 {
		return fmt.Errorf("--max-size must not be negative (got %d); use 0 for unlimited", max)
	}
	if max > 0 && min > max {
		return fmt.Errorf("--min-size (%d) must not exceed --max-size (%d): no file could match", min, max)
	}
	return nil
}

// dependencyCollectOptions is the Dependencies profile as the dependency stage collects with
// it: the built-in file rules off, because that list drops .lock and .yaml and would hide
// Cargo.lock, pnpm-lock.yaml, poetry.lock and composer.lock. The stage selects its files by
// name afterwards (sbom/depsource.Select), so the extension list has nothing to decide for it.
func dependencyCollectOptions(s *settings.Settings) filter.Options {
	o := filter.Dependencies(s)
	o.BuiltinFileRules = false
	return o
}

// applyCollectFlags layers the collection flags onto o, whichever profile it came from.
// Every stage that collects files honours the same flags, so they are applied in one
// place rather than restated per stage — and a stage's own profile decisions survive,
// because nothing here is copied from another stage's options.
func applyCollectFlags(o *filter.Options, minSize, maxSize int64, allExtensions, allFolders, gitignore, allHidden bool) {
	o.MinSize, o.MaxSize = minSize, maxSize

	// These four only ever remove rules, so they are applied as opt-outs rather than
	// assigned. Assigning them lets a flag left at its default overwrite a profile that
	// switched something off deliberately — which is how the manifest stage came to
	// inherit the scanning folder lists and prune the examples/ directory a manifest
	// legitimately lives in.
	if allExtensions {
		o.BuiltinFileRules = false
	}
	if allFolders {
		o.BuiltinFolderRules = false
		// The built-in lists and a profile's own are separate sources, so switching the
		// built-ins off does not reach the Dependencies profile, which carries its
		// directory rules in SkipDirs. Leaving them would keep pruning dist/, build/ and
		// target/ for a caller who asked for every folder. Clearing is safe here because
		// nothing in the CLI puts a user's own rules in these two fields — scanoss.json
		// skip patterns land in SkipPatterns.
		o.SkipDirs, o.SkipDirExts = nil, nil
	}
	if !gitignore {
		o.GitIgnore = false
	}
	if allHidden {
		o.IncludeHidden = true
	}
}
