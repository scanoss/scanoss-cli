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

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/internal/config"
	"github.com/scanoss/scanoss.go/pkg/scanpipeline"
)

var enrichCmd = &cobra.Command{
	Use:   "enrich <input>",
	Short: "Decorate an existing inventory/SBOM with purl-keyed layers",
	Long: `The enrich command takes an existing inventory or SBOM — a scanoss raw inventory
(the scan raw output), a CycloneDX document, or an SPDX document — and decorates its
components with the requested purl-keyed layers (vulns, licenses, crypto, geo) through
the SCANOSS API, then renders the result in the chosen format.

It needs only the inventory: no source tree, no fingerprinting, no re-scan. Because it is
keyed purely by PURL, it is re-runnable (e.g. weekly) to refresh the layers against the
same file. The output format defaults to the input's format; use --format to convert in the
same pass. A layer the output format cannot represent is skipped with an up-front notice.

Examples:
  # Refresh vulns/licenses/crypto on a raw inventory (raw in, raw out)
  scanoss-cli enrich inv.json --include vulns,licenses,crypto > enriched.json

  # Enrich an SPDX document (spdx in, spdx out)
  scanoss-cli enrich sbom.spdx.json --include licenses > enriched.spdx.json

  # Enrich a CycloneDX document and convert to SPDX in one pass
  scanoss-cli enrich sbom.cdx.json --include licenses --format spdx > enriched.spdx.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runEnrich,
}

func init() {
	rootCmd.AddCommand(enrichCmd)
	addAPIFlags(enrichCmd)
	enrichCmd.Flags().StringP("format", "f", "", "Output format: raw, spdx, cyclonedx (default: same as input)")
	enrichCmd.Flags().StringSlice("include", nil, "Layers to gather (comma-separated): vulns, licenses, crypto, geo")
}

// runEnrich parses an inventory/SBOM, enriches its components with the requested purl-layers
// through the decoration pipeline, and renders the result. No scanning is involved: enrichment is
// the scan pipeline's format-blind tail stage (scanpipeline.Enricher) run on an inventory the
// command parsed itself.
func runEnrich(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usageError(cmd, "an SBOM file to enrich is required")
	}
	if err := checkAuth(cmd); err != nil {
		return err
	}

	// Only the PURL-keyed layers: enrich works from an SBOM file, and declared dependencies come
	// from manifests in a scanned tree it does not have. Stating that in the accepted set rather
	// than rejecting deps afterwards is what stops the two from disagreeing.
	values, _ := cmd.Flags().GetStringSlice("include")
	layers, err := ParseLayers(values, PurlLayers())
	if err != nil {
		return err
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}
	inv, inputFormat, err := identifyAndParse(data)
	if err != nil {
		return err
	}

	// Output format defaults to the input's; --format overrides (converting in the same pass).
	outputFormat, _ := cmd.Flags().GetString("format")
	if outputFormat == "" {
		outputFormat = inputFormat
	}
	switch outputFormat {
	case config.FormatRaw, config.FormatSPDX, config.FormatCycloneDX:
	default:
		return fmt.Errorf("invalid output format %q: must be raw, spdx, or cyclonedx", outputFormat)
	}
	_ = cmd.Flags().Set("format", outputFormat) // let emitInventory read the resolved format

	// Narrow to what the output format can render, reporting each skipped layer up front — the
	// same capability logic the scan command uses, so enrich never gathers a layer it would drop.
	reportSkippedLayers(outputFormat, layers)
	layers = effectiveLayers(outputFormat, layers)

	prog := &scanProgress{}
	client, err := buildScanClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := createCancellableContext()
	defer cancel()

	enricher := scanpipeline.Enricher{
		Client:   client,
		Services: servicesFor(layers),
		Reporter: scanpipeline.NewReporter(prog.layer),
	}
	enrichErr := enricher.Enrich(ctx, &inv)
	prog.finish()
	if enrichErr != nil {
		warnf("Enrichment incomplete: %v", enrichErr)
	}

	// No scan here — the inventory is parsed from an existing SBOM, so there is no server block.
	return emitInventory(cmd, inv, args[0], nil)
}
