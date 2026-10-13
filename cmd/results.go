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

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/internal/cliconfig"
	"github.com/scanoss/scanoss.go/internal/config"
	"github.com/scanoss/scanoss.go/pkg/sbom/scansource"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
	"github.com/scanoss/scanoss.go/pkg/scanpipeline"
)

var resultsCmd = &cobra.Command{
	Use:   "results <scan-id>",
	Short: "Retrieve results from a previous batch scan using its scan id",
	Long: `The results command resumes a previous v3 batch scan by its scan id and
polls the API until the results are ready.

Examples:
  # Get results from a previous scan
  scanoss-cli results 05b7ede7702c3a7c6ccec7f23252ce47

  # Get results and save to file
  scanoss-cli results 05b7ede7702c3a7c6ccec7f23252ce47 --output results.json

  # Get results with custom API URL
  scanoss-cli results 05b7ede7702c3a7c6ccec7f23252ce47 --api-url https://api.scanoss.com`,
	Args: cobra.MaximumNArgs(1),
	RunE: runResults,
}

func init() {
	rootCmd.AddCommand(resultsCmd)

	addAPIFlags(resultsCmd)
	resultsCmd.Flags().Duration("poll-interval", scanoss.DefaultScanPollInterval, "How often to poll for scan status")
	resultsCmd.Flags().StringP("format", "f", config.DefaultFormat, "Result output format: raw, spdx, cyclonedx")
	resultsCmd.Flags().StringSlice("include", nil, "Output layers to gather (comma-separated): vulns, licenses, crypto, geo")
	// A resumed scan must reach the same deliverable as a direct one, and the BOM rules are part
	// of that: without them, `results <id>` reported components the project's settings dismissed.
	resultsCmd.Flags().String("settings", "", "Path to settings file (scanoss.json/settings.json)")
	addBOMRuleFlags(resultsCmd)
	addRankingFlag(resultsCmd)
}

func runResults(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usageError(cmd, "a scan id is required")
	}
	if err := checkAuth(cmd); err != nil {
		return err
	}

	scanID := args[0]

	api, err := cliconfig.ResolveAPI(cmd.Flags())
	if err != nil {
		return err
	}
	pollInterval, _ := cmd.Flags().GetDuration("poll-interval")
	settingsFlag, _ := cmd.Flags().GetString("settings")

	// Checked before the scan is polled: waiting for a scan to finish only to reject a format that
	// was wrong from the start spends the wait for nothing.
	if err := validateOutputFormat(cmd); err != nil {
		return err
	}

	// Resuming by id reaches the server's result, not the tree that produced it, so declared
	// dependencies cannot be sourced. Its own help never offered deps; now the parser agrees.
	values, _ := cmd.Flags().GetStringSlice("include")
	layers, err := ParseLayers(values, PurlLayers())
	if err != nil {
		return err
	}
	outputFormat, _ := cmd.Flags().GetString("format")
	reportSkippedLayers(outputFormat, layers)
	layers = effectiveLayers(outputFormat, layers) // don't gather what this format can't render

	cfg, err := apiConfig(cmd)
	if err != nil {
		return err
	}

	prog := &scanProgress{}
	rep := scanpipeline.NewReporter(prog.layer)
	cfg.APIURL = api.URL
	cfg.APIKey = api.Key
	client, err := scanoss.New(cfg)
	if err != nil {
		return err
	}

	infof("Retrieving results for scan %s", scanID)

	ctx, cancel := createCancellableContext()
	defer cancel()

	// Resuming by id reaches a result, not the tree it came from, so the settings are looked for
	// in the working directory unless --settings names one.
	scanSettings, err := resolveSettings(settingsFlag, ".")
	if err != nil {
		return fmt.Errorf("error loading settings: %w", err)
	}
	scanSettings, err = mergeBOMRuleFlags(cmd, scanSettings)
	if err != nil {
		return err
	}

	var bom bomReport
	waitOpts := []scanoss.ScanOption{
		scanoss.WithPollInterval(pollInterval), scanoss.WithScanReporter(rep), bom.option(),
	}
	if scanSettings != nil && scanSettings.HasBOM() {
		waitOpts = append(waitOpts, scanoss.WithBOM(&scanSettings.BOM))
	}
	if threshold := resolveRankingThreshold(cmd, scanSettings); threshold > 0 {
		waitOpts = append(waitOpts, scanoss.WithRankingThreshold(threshold))
	}

	res, err := client.Scan.Wait(ctx, scanID, waitOpts...)
	if err != nil {
		return renderAPIError(fmt.Errorf("failed to retrieve results: %w", err))
	}
	if res.Result == nil {
		return fmt.Errorf("scan completed without a result")
	}

	// Assemble the same inventory `scan` produces, so a resumed scan reaches the
	// same deliverable: the raw envelope carries schema_version and metadata, and
	// the SBOM formats are convertible by `sbom`. Emitting the API response
	// verbatim made a resumed scan a dead end.
	inv := scansource.Inventory(res.Result, scansource.WithIdentified(bom.report.IsIdentified))
	enricher := scanpipeline.Enricher{Client: client, Services: servicesFor(layers), Reporter: rep}
	if err := enricher.Enrich(ctx, &inv); err != nil {
		warnf("Enrichment incomplete: %v", err)
	}
	// No source path here — the sbom module applies its default project name.
	return emitInventory(cmd, inv, "", scansource.Server(res.Result.Server))
}
