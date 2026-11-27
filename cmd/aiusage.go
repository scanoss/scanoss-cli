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
	"strings"

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

Without --rules-dir the AI rules are downloaded from the SCANOSS API (--ruleset), verified and
cached.

Examples:
  # Report AI usage with the rules the API serves for your key
  scanoss-cli ai-usage ./my-project --api-key $SCANOSS_API_KEY

  # Report AI usage with a local rules directory
  scanoss-cli ai-usage ./my-project --rules-dir ./ai_rules

  # Python only, written to a file
  scanoss-cli ai-usage ./my-project --rules-dir ./ai_rules --languages python -o ai.json

  # CycloneDX AIBOM, failing the build on a high or critical risk
  scanoss-cli ai-usage ./my-project --rules-dir ./ai_rules -f cyclonedx --fail-on high

Exit codes: 0 ok, 1 error, 2 a finding at or above --fail-on, 3 AI rules unavailable.`,
	Args: cobra.ExactArgs(1),
	RunE: runAIUsage,
}

func init() {
	rootCmd.AddCommand(aiUsageCmd)
	fs := aiUsageCmd.Flags()
	fs.String("rules-dir", "", "Directory of AI rule card files, one subdirectory per language (python/, javascript/)")
	fs.StringSlice("languages", nil, "Languages to scan (comma-separated): python, javascript, typescript (default: all)")
	fs.StringP("format", "f", config.FormatRaw, "Result output format: raw, cyclonedx (alias aibom)")
	fs.String("fail-on", "", "Exit with code 2 when a finding has this risk or higher: critical, high, medium, low")
	fs.Bool("include-tests", false, "Also scan test files")
	fs.Bool("reachability", true, "Decide for each finding whether it runs from an entry point")
	addAIRulesFlags(aiUsageCmd)
	addAPIFlags(aiUsageCmd)
}

func runAIUsage(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	if format == "aibom" {
		format = string(sbom.FormatCycloneDX)
	}
	if format != config.FormatRaw && format != string(sbom.FormatCycloneDX) {
		return usageError(cmd, "unsupported --format %q for ai-usage (want raw or cyclonedx)", format)
	}
	failOn, _ := cmd.Flags().GetString("fail-on")
	threshold, ok := riskRank[strings.ToLower(failOn)]
	if failOn != "" && (!ok || threshold == riskRank["info"]) {
		return usageError(cmd, "unsupported --fail-on %q (want critical, high, medium or low)", failOn)
	}
	languages, _ := cmd.Flags().GetStringSlice("languages")
	includeTests, _ := cmd.Flags().GetBool("include-tests")
	withReachability, _ := cmd.Flags().GetBool("reachability")
	outputFile, _ := cmd.Flags().GetString("output")

	rules, err := resolveAIRules(cmd)
	if err != nil {
		return err
	}
	defer rules.close()
	report, err := aiusage.Scan(args[0], aiusage.Options{RulesDir: rules.dir, Rules: rules.info, Languages: languages, IncludeTests: includeTests, Reachability: withReachability})
	if err != nil {
		return err
	}
	project := args[0]
	if abs, err := filepath.Abs(args[0]); err == nil {
		project = filepath.Base(abs)
	}
	out, err := renderAIUsage(report, format, project)
	if err != nil {
		return err
	}
	w, err := output.NewWriter(outputFile)
	if err != nil {
		return err
	}
	defer func() { _ = w.Close() }()
	if err := w.Write(out + "\n"); err != nil {
		return err
	}
	if failOn != "" {
		if n := findingsAtOrAbove(report, threshold); n > 0 {
			return &exitError{code: 2, err: fmt.Errorf("ai-usage: %d finding(s) at or above %s risk", n, strings.ToLower(failOn))}
		}
	}
	return nil
}

// renderAIUsage renders a report as a raw document or a CycloneDX AIBOM.
func renderAIUsage(report *sbom.AIUsage, format, project string) (string, error) {
	if format == string(sbom.FormatCycloneDX) {
		out, err := sbom.Generate(sbom.Inventory{}, sbom.FormatCycloneDX, sbom.WithProjectName(project), sbom.WithAIUsage(report))
		if err != nil {
			return "", fmt.Errorf("error generating cyclonedx output: %w", err)
		}
		return out, nil
	}
	doc := sbom.NewRawDocument(sbom.Inventory{}, sbom.RawMetadata{Tool: config.AppName, ToolVersion: config.AppVersion, Project: project})
	doc.AIUsage = report
	raw, err := doc.Marshal()
	if err != nil {
		return "", fmt.Errorf("error encoding results: %w", err)
	}
	return raw, nil
}

// riskRank orders the risks a finding can carry.
var riskRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// findingsAtOrAbove counts the findings whose risk ranks at least threshold.
func findingsAtOrAbove(report *sbom.AIUsage, threshold int) int {
	n := 0
	for _, f := range report.Findings {
		meta, _ := f.Metadata[aiusage.MetadataKey].(map[string]any)
		risk, _ := meta["risk"].(string)
		if rank, ok := riskRank[strings.ToLower(risk)]; ok && rank >= threshold {
			n++
		}
	}
	return n
}
