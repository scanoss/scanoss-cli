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
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/internal/config"
	"github.com/scanoss/scanoss.go/internal/output"
	"github.com/scanoss/scanoss.go/pkg/aiusage"
	"github.com/scanoss/scanoss.go/pkg/sbom"
)

var aiUsageCmd = &cobra.Command{
	Use:   "ai-usage [path]",
	Short: "Report AI usage in source code",
	Long: `The ai-usage command reports where source code uses AI: the model and provider of
each AI SDK call, model loading that runs code, and LLM output reaching a shell, eval or SQL.
It builds the code's call graph and matches AI detection rules against its call sites.
An imported SDK alone is not a finding.

Languages: Python, JavaScript and TypeScript.

Examples:
  # Report AI usage with a local rules directory
  scanoss-cli ai-usage ./my-project --rules-dir ./ai_rules

  # Python only, written to a file
  scanoss-cli ai-usage ./my-project --rules-dir ./ai_rules --languages python -o ai.json`,
	Args: cobra.ExactArgs(1),
	RunE: runAIUsage,
}

func init() {
	rootCmd.AddCommand(aiUsageCmd)
	fs := aiUsageCmd.Flags()
	fs.String("rules-dir", "", "Directory of AI rule card files, one subdirectory per language (python/, javascript/)")
	fs.StringSlice("languages", nil, "Languages to scan (comma-separated): python, javascript, typescript (default: all)")
	fs.StringP("format", "f", config.FormatRaw, "Result output format: raw")
	fs.Bool("include-tests", false, "Also scan test files")
	fs.StringP("output", "o", "", "Output file (default: stdout)")
}

func runAIUsage(cmd *cobra.Command, args []string) error {
	rulesDir, _ := cmd.Flags().GetString("rules-dir")
	if rulesDir == "" {
		return usageError(cmd, "--rules-dir is required")
	}
	format, _ := cmd.Flags().GetString("format")
	if format != config.FormatRaw {
		return usageError(cmd, "unsupported --format %q for ai-usage (want raw)", format)
	}
	languages, _ := cmd.Flags().GetStringSlice("languages")
	includeTests, _ := cmd.Flags().GetBool("include-tests")
	outputFile, _ := cmd.Flags().GetString("output")

	report, err := aiusage.Scan(args[0], aiusage.Options{RulesDir: rulesDir, Languages: languages, IncludeTests: includeTests})
	if err != nil {
		return err
	}
	project := args[0]
	if abs, err := filepath.Abs(args[0]); err == nil {
		project = filepath.Base(abs)
	}
	doc := sbom.NewRawDocument(sbom.Inventory{}, sbom.RawMetadata{Tool: config.AppName, ToolVersion: config.AppVersion, Project: project})
	doc.AIUsage = report
	raw, err := doc.Marshal()
	if err != nil {
		return fmt.Errorf("error encoding results: %w", err)
	}
	w, err := output.NewWriter(outputFile)
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()
	return w.Write(raw + "\n")
}
