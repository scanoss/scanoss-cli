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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/internal/config"
	"github.com/scanoss/scanoss.go/internal/output"
	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/wfp"
)

var wfpCmd = &cobra.Command{
	Use:   "wfp <path>",
	Short: "Generate WFP fingerprints from a file or folder",
	Long: `The wfp command scans a file or recursively scans a folder, generates WFP
(Winnowing Fingerprint) fingerprints for each valid file and displays
the results on standard output.

This command is useful for:
  - Inspecting generated fingerprints
  - Debugging
  - Generating WFP files for offline processing`,
	Args: cobra.MaximumNArgs(1),
	RunE: runWFP,
}

func init() {
	rootCmd.AddCommand(wfpCmd)

	// Optional flags
	wfpCmd.Flags().IntP("threads", "t", config.DefaultThreads, "Number of parallel threads")
	wfpCmd.Flags().StringP("output", "o", "", "Output file (empty = stdout)")
	wfpCmd.Flags().Int64("min-size", filter.DefaultMinFileSize, "Minimum file size in bytes to scan")
	wfpCmd.Flags().Int64("max-size", filter.DefaultMaxFileSize, "Maximum file size in bytes to scan (0 = unlimited)")
	wfpCmd.Flags().String("settings", "", "Path to settings file (scanoss.json/settings.json)")
	wfpCmd.Flags().Bool("all-extensions", false, "Fingerprint every file extension: do not apply the built-in file skip lists")
	wfpCmd.Flags().Bool("all-folders", false, "Fingerprint every folder: do not apply the built-in directory skip lists")
	wfpCmd.Flags().Bool("gitignore", true, "Honor .gitignore files when collecting files")
	wfpCmd.Flags().Bool("all-hidden", false, "Include hidden files and folders, version-control metadata included")
	wfpCmd.Flags().Bool("enable-wfp2", false, "Also emit token-aware (wfp2) fingerprint blocks alongside the classic ones")
	addSkipHeaderFlags(wfpCmd)
}

func runWFP(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usageError(cmd, "a path to fingerprint is required")
	}
	targetPath := args[0]

	// Verify that the path exists (can be a file or folder)
	info, err := os.Stat(targetPath)
	if err != nil {
		return fmt.Errorf("error accessing path: %w", err)
	}

	// Get configuration from flags
	threads, _ := cmd.Flags().GetInt("threads")
	outputFile, _ := cmd.Flags().GetString("output")
	minSize, _ := cmd.Flags().GetInt64("min-size")
	maxSize, _ := cmd.Flags().GetInt64("max-size")
	settingsFlag, _ := cmd.Flags().GetString("settings")
	allExtensions, _ := cmd.Flags().GetBool("all-extensions")
	allFolders, _ := cmd.Flags().GetBool("all-folders")
	applyGitignore, _ := cmd.Flags().GetBool("gitignore")
	allHidden, _ := cmd.Flags().GetBool("all-hidden")
	enableWFP2, _ := cmd.Flags().GetBool("enable-wfp2")

	// Validate configuration
	if threads < 1 {
		threads = config.DefaultThreads
	}
	if err := validateSizeBounds(minSize, maxSize); err != nil {
		return err
	}

	// Fingerprinting rules, not scanning ones: scanoss.json keeps the two
	// operations apart, and this command only fingerprints.
	wfpSettings, err := resolveSettings(settingsFlag, targetPath)
	if err != nil {
		return fmt.Errorf("error loading settings: %w", err)
	}

	skipHeaders, skipHeadersLimit := resolveSkipHeaders(cmd, wfpSettings)

	// Report WFP paths relative to the scanned root (a folder, or the file's
	// directory for a single-file target), matching the `scan` command.
	scanRoot := targetPath
	if !info.IsDir() {
		scanRoot = filepath.Dir(targetPath)
	}
	if abs, absErr := filepath.Abs(scanRoot); absErr == nil {
		scanRoot = abs
	}

	// Collect files with the same inputs `scan` uses, so a WFP generated here
	// covers exactly the files a scan of the same tree would upload.
	collectOpts := filter.Fingerprinting(wfpSettings)
	applyCollectFlags(&collectOpts, minSize, maxSize, allExtensions, allFolders, applyGitignore, allHidden)
	res, err := filter.Collect(targetPath, collectOpts)
	if err != nil {
		return fmt.Errorf("error collecting files: %w", err)
	}
	files := res.Files
	// Say what was dropped, as `scan` does: a filtered file that goes unreported
	// looks like a file that was never there.
	if res.SkippedCount > 0 {
		infof("Filtered %d files", res.SkippedCount)
	}

	if len(files) == 0 {
		warnf("No valid files found to process")
		return nil
	}

	// Create output writer
	writer, err := output.NewWriter(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output writer: %w", err)
	}
	defer func() { _ = writer.Close() }()

	// Create progress bar
	p := newProgress()
	bar := addBar(p, len(files), "Processing files")

	// Generate the WFP through the shared path (same as `scan`), with paths
	// relative to the scan root. --enable-wfp2 appends a wfp2= block per file, so the
	// saved WFP can later be scanned with `scan wfp --enable-wfp2`.
	wfpOpts := fingerprintOptions(skipHeaders, skipHeadersLimit)
	if enableWFP2 {
		wfpOpts = append(wfpOpts, wfp.WithWFP2())
	}
	fp := wfp.Files(files, threads, scanRoot, func(done, total int) {
		bar.SetCurrent(int64(done))
	}, wfpOpts...)
	bar.SetCurrent(int64(len(files)))
	p.Wait()

	if err := writer.Write(string(fp.WFP)); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing: %v\n", err)
	}
	if len(fp.Errors) > 0 {
		warnf("Completed with %d errors", len(fp.Errors))
	}

	return nil
}
