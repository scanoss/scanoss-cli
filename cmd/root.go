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
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/internal/logging"
	"github.com/scanoss/scanoss.go/internal/version"
)

var rootCmd = &cobra.Command{
	Use:   "scanoss-cli",
	Short: "SCANOSS CLI - Code scanning tool",
	Long: `SCANOSS CLI is a command-line tool for scanning source code projects
and detecting open source components.

Supports fingerprinting (WFP) and full scanning with API submission.`,
	Version: version.Version(),
	// PersistentPreRunE runs before every subcommand: it configures the logger from --verbose so
	// diagnostics honor the flag everywhere, and rejects an unwritable --output before the command
	// does the work whose result was going to go there.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		verbose, _ := cmd.Flags().GetBool("verbose")
		logging.Configure(verbose)
		slog.Debug("verbose logging enabled")
		return validateOutputTarget(cmd)
	},
}

// Execute runs the root command
func Execute() {
	// Runtime errors are not usage errors: print them ourselves (below) without
	// cobra's usage dump.
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	if err := rootCmd.Execute(); err != nil {
		// The no-key guard has already printed its banner; just set the exit code.
		if !errors.Is(err, errNoAPIKey) {
			fmt.Fprintln(os.Stderr, err)
		}
		code := 1
		var exit *exitError
		if errors.As(err, &exit) {
			code = exit.code
		}
		os.Exit(code)
	}
}

// exitError is an error that ends the process with a code other than 1: 2 when --fail-on
// trips, 3 when the rules a command needs are unavailable.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func init() {
	// `scanoss-cli --version` → "scanoss-cli <version>"
	rootCmd.SetVersionTemplate("scanoss-cli {{.Version}}\n")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
}
