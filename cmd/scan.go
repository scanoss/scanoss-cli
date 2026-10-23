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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"

	"github.com/scanoss/scanoss.go/internal/cliconfig"
	"github.com/scanoss/scanoss.go/internal/config"
	"github.com/scanoss/scanoss.go/internal/output"
	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/postprocess"
	"github.com/scanoss/scanoss.go/pkg/sbom"
	"github.com/scanoss/scanoss.go/pkg/sbom/scansource"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
	"github.com/scanoss/scanoss.go/pkg/scanpipeline"
	"github.com/scanoss/scanoss.go/pkg/settings"
	"github.com/scanoss/scanoss.go/pkg/wfp"
)

// scanProgress draws pipeline layers as terminal progress bars, one bar per layer in a shared mpb
// container, so layers that run concurrently render side by side. Layers are reported from several
// goroutines, so it is mutex-guarded.
type scanProgress struct {
	mu   sync.Mutex
	p    *mpb.Progress       // shared multi-bar container (lazily created on first update)
	bars map[string]*mpb.Bar // one live bar per phase/service, keyed by phase key or Service name
}

// layer renders one pipeline layer as a bar. Every layer is drawn the same way — the pipeline
// reports them all in the same shape, including the scan, whose server-side passes it has already
// folded into a counter that only grows.
func (s *scanProgress) layer(p scanpipeline.Progress) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Collection is reported as a layer like any other, but there is nothing to watch: it reports
	// once, on completion. Say what it excluded instead of drawing a bar that is born full.
	if p.Layer == scanpipeline.LayerCollect {
		if skipped := p.Total - p.Done; skipped > 0 {
			s.initLocked()
			_, _ = fmt.Fprintln(s.p, infoLine("Filtered %d files", skipped))
		}
		return
	}

	// The enrichment layers run after the scan; separate the two groups with a blank line the
	// first time one appears.
	if isEnrichmentLayer(p.Layer) {
		s.spacerLocked()
	}

	bar := s.barLocked(p.Layer, layerLabel(p.Layer), p.Total)
	if p.Total > 0 {
		bar.SetTotal(int64(p.Total), false)
	}
	bar.SetCurrent(int64(p.Done))

	// The status is what says a layer finished, not its counters: the scan is sampled by polling,
	// so its last pass is routinely still mid-count when the server reports the scan complete.
	if p.Status == scanpipeline.StatusCompleted && p.Total > 0 {
		bar.SetCurrent(int64(p.Total))
	}
}

// isEnrichmentLayer reports whether a layer is one of the purl-keyed enrichment services, which
// render below the scan rather than beside it. They are exactly the layers the pipeline names
// after an API service.
func isEnrichmentLayer(layer string) bool {
	switch layer {
	case scanpipeline.LayerFingerprint, scanpipeline.LayerManifests,
		scanpipeline.LayerUpload, scanpipeline.LayerScan:
		return false
	default:
		return layer != scanoss.ServiceDependencies.Name
	}
}

// initLocked creates the shared container on first use. Caller holds s.mu.
func (s *scanProgress) initLocked() {
	if s.p == nil {
		s.p = newProgress()
		s.bars = make(map[string]*mpb.Bar)
	}
}

// spacerLocked adds a blank line once, separating the scan-phase bars (fingerprint, upload,
// scan, dependency resolution) from the enrichment layer bars below. It is a completed no-op bar,
// so it just occupies an empty line and never blocks Wait. Caller holds s.mu.
func (s *scanProgress) spacerLocked() {
	s.initLocked()
	if _, ok := s.bars["_spacer"]; ok {
		return
	}
	bar := s.p.New(1, mpb.NopStyle())
	bar.SetCurrent(1)
	s.bars["_spacer"] = bar
}

// barLocked returns the bar for key, creating it in the shared container on first use. Caller
// holds s.mu.
func (s *scanProgress) barLocked(key, label string, total int) *mpb.Bar {
	s.initLocked()
	bar, ok := s.bars[key]
	if !ok {
		bar = addBar(s.p, total, label)
		s.bars[key] = bar
	}
	return bar
}

// writeLine prints a line above the running bars (e.g. the scan-id notice) without corrupting the
// bar area — mpb's *Progress is an io.Writer that interleaves the line at the next refresh.
func (s *scanProgress) writeLine(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initLocked()
	_, _ = fmt.Fprintln(s.p, msg)
}

// finish finalizes all progress once the pipeline returns: any bar that never reached its total
// (e.g. a service that errored) is aborted so the container's render goroutine can flush and stop.
func (s *scanProgress) finish() {
	s.mu.Lock()
	p, bars := s.p, s.bars
	s.mu.Unlock()

	if p == nil {
		return
	}
	for _, b := range bars {
		if !b.Completed() {
			b.Abort(false)
		}
	}
	p.Wait()
}

// layerLabel maps a pipeline layer to the phrase shown on its bar. Naming is the CLI's business:
// the pipeline reports stable layer ids and says nothing about how they should read.
func layerLabel(service string) string {
	switch service {
	case scanpipeline.LayerFingerprint:
		return "Fingerprinting"
	case scanpipeline.LayerManifests:
		return "Parsing dependencies"
	case scanpipeline.LayerUpload:
		return "Uploading WFP"
	case scanpipeline.LayerScan:
		return "Scanning"
	case scanoss.ServiceLicenses.Name:
		return "Licenses"
	case scanoss.ServiceVulnerabilities.Name:
		return "Vulnerabilities"
	case scanoss.ServiceCryptographyAlgorithms.Name:
		return "Cryptography"
	case scanoss.ServiceGeoprovenanceOrigin.Name:
		return "Geoprovenance"
	case scanoss.ServiceDependencies.Name:
		return "Resolving dependencies"
	default:
		return service
	}
}

// formatLayers lists which --include layers each output format can render. deps and licenses are
// representable everywhere (as components / package licenses); vulnerabilities in raw + cyclonedx;
// cryptography and geoprovenance only in raw.
var formatLayers = map[string]map[Layer]bool{
	config.FormatRaw:       {LayerDeps: true, LayerLicenses: true, LayerVulns: true, LayerCrypto: true, LayerGeo: true},
	config.FormatCycloneDX: {LayerDeps: true, LayerLicenses: true, LayerVulns: true},
	config.FormatSPDX:      {LayerDeps: true, LayerLicenses: true},
}

// layerName is the readable name of a layer, for warnings.
func layerName(l Layer) string {
	switch l {
	case LayerVulns:
		return "vulnerabilities"
	case LayerCrypto:
		return "cryptography"
	case LayerGeo:
		return "geoprovenance"
	case LayerDeps:
		return "dependencies"
	default:
		return string(l) // licenses
	}
}

// unsupportedLayers returns the requested layers the format cannot render, in a stable order.
func unsupportedLayers(format string, layers Set) []Layer {
	caps := formatLayers[format]
	var out []Layer
	for _, l := range []Layer{LayerDeps, LayerLicenses, LayerVulns, LayerCrypto, LayerGeo} {
		if layers.Has(l) && !caps[l] {
			out = append(out, l)
		}
	}
	return out
}

// effectiveLayers returns the requested layers the format can actually render
// (requested ∩ capabilities) — the set the fused scan command gathers, so it never fetches a
// layer this format would drop.
func effectiveLayers(format string, layers Set) Set {
	caps := formatLayers[format]
	eff := make(Set, len(layers))
	for l := range layers {
		if caps[l] {
			eff[l] = true
		}
	}
	return eff
}

// reportSkippedLayers tells the user, up front, which requested layers the chosen format cannot
// represent and so will not be gathered — grouped into a single warning rather than one line per
// layer.
func reportSkippedLayers(format string, layers Set) {
	skipped := unsupportedLayers(format, layers)
	if len(skipped) == 0 {
		return
	}
	names := make([]string, len(skipped))
	for i, l := range skipped {
		names[i] = layerName(l)
	}
	warnf("%s can't render %s — skipped", format, strings.Join(names, ", "))
}

// buildResultsCommand constructs the resume command printed for recovery.
func buildResultsCommand(scanID, apiURL, apiKey string) string {
	cmd := fmt.Sprintf("  scanoss-cli results %s", scanID)
	if apiURL != config.DefaultAPIURL {
		cmd += fmt.Sprintf(" --api-url %s", apiURL)
	}
	if apiKey != "" {
		cmd += " --api-key ***" // masked — never echo the real key to the terminal/logs
	}
	return cmd
}

// printErrorSummary prints a summary if any files failed to fingerprint.
// printErrorSummary reports the files that could not be fingerprinted. The count is the headline;
// the reasons follow at Debug, where a run being diagnosed will show them.
func printErrorSummary(processErrors []error) {
	if len(processErrors) == 0 {
		return
	}
	warnf("Completed with %d processing errors", len(processErrors))
	for _, err := range processErrors {
		slog.Debug("file could not be fingerprinted", "err", err)
	}
}

// validateOutputFormat checks the --format flag up front so an invalid value fails
// fast, before any fingerprinting or upload.
func validateOutputFormat(cmd *cobra.Command) error {
	format, _ := cmd.Flags().GetString("format")
	switch format {
	case config.FormatRaw, config.FormatSPDX, config.FormatCycloneDX:
		return nil
	default:
		return fmt.Errorf("invalid output format %q: must be raw, spdx, or cyclonedx", format)
	}
}

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Scan a file or folder and send results to the SCANOSS API",
	Long: `The scan command scans a single file or recursively scans a folder, generates
WFP fingerprints, uploads them to the SCANOSS v3 batch scan API in parallel
chunks, and polls until the scan completes. To scan a pre-generated WFP file
instead, use the "wfp" subcommand.

The scan id is printed; if the scan is interrupted you can resume
it later with "scanoss-cli results <scan-id>".

Examples:
  # Scan a folder
  scanoss-cli scan ./my-project

  # Scan a single file
  scanoss-cli scan ./src/main.c

  # Scan with custom API URL and key
  scanoss-cli scan ./my-project --api-url https://api.scanoss.com --api-key TOKEN

  # Scan a pre-generated WFP file
  scanoss-cli scan wfp fingerprints.wfp

  # Save WFP fingerprints before sending to the API
  scanoss-cli scan ./my-project --save-wfp fingerprints.wfp`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var scanWFPCmd = &cobra.Command{
	Use:   "wfp <wfp-path>",
	Short: "Scan a pre-generated WFP fingerprint file",
	Long: `The wfp subcommand uploads an already-assembled WFP fingerprint file to the
SCANOSS v3 batch scan API and polls until the scan completes. No fingerprinting
is performed; the file is sent as-is.

Examples:
  # Scan a WFP file produced earlier (e.g. with --save-wfp or the wfp command)
  scanoss-cli scan wfp fingerprints.wfp

  # Scan a WFP file against a premium endpoint
  scanoss-cli scan wfp fingerprints.wfp --api-key TOKEN`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScanWFP,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanWFPCmd)

	// Shared flags (persistent → inherited by the wfp subcommand).
	addAPIFlags(scanCmd)
	scanCmd.PersistentFlags().StringP("format", "f", config.DefaultFormat, "Result output format: raw, spdx, cyclonedx")
	scanCmd.PersistentFlags().String("settings", "", "Path to settings file (scanoss.json/settings.json)")
	scanCmd.PersistentFlags().Int("chunk-size", scanoss.DefaultScanChunkBytes, "WFP upload chunk size in bytes")
	scanCmd.PersistentFlags().Duration("poll-interval", scanoss.DefaultScanPollInterval, "How often to poll for scan status")

	// --include is declared per command rather than inherited: the two accept different layers, and
	// an inherited help text would offer `wfp` a layer it cannot gather.
	scanCmd.Flags().StringSlice("include", nil, "Output layers to gather (comma-separated): deps, vulns, licenses, crypto, geo")
	scanWFPCmd.Flags().StringSlice("include", nil, "Output layers to gather (comma-separated): vulns, licenses, crypto, geo")

	// Fingerprinting flags (apply to `scan <path>` only).
	scanCmd.Flags().IntP("threads", "t", config.DefaultThreads, "Number of parallel fingerprint workers")
	scanCmd.Flags().String("save-wfp", "", "Save WFP fingerprints to file before sending to API")
	scanCmd.Flags().Int64("min-size", filter.DefaultMinFileSize, "Minimum file size in bytes to scan")
	scanCmd.Flags().Int64("max-size", filter.DefaultMaxFileSize, "Maximum file size in bytes to scan (0 = unlimited)")
	scanCmd.Flags().Bool("all-extensions", false, "Fingerprint every file extension: do not apply the built-in file skip lists")
	scanCmd.Flags().Bool("all-folders", false, "Fingerprint every folder: do not apply the built-in directory skip lists")
	scanCmd.Flags().Bool("gitignore", true, "Honor .gitignore files when collecting files")
	scanCmd.Flags().Bool("all-hidden", false, "Include hidden files and folders, version-control metadata included")
	addSkipHeaderFlags(scanCmd)

	// The BOM rule flags are declared on both, since either can apply them: `scan wfp` cannot
	// fingerprint, but it still post-processes a result.
	addBOMRuleFlags(scanCmd)
	addBOMRuleFlags(scanWFPCmd)
	addRankingFlag(scanCmd)
	addRankingFlag(scanWFPCmd)
	addComponentFlag(scanCmd)
	addComponentFlag(scanWFPCmd)
	addSkipHeaderFlags(scanWFPCmd) // declared so the flag is rejected with a reason, see runScanWFP
}

// runScan fingerprints a file or folder and scans it. Collection, fingerprinting, the scan, and
// enrichment all happen inside scanpipeline.Run; this command only gathers flags, renders
// progress, and writes the result.
func runScan(cmd *cobra.Command, args []string) error {
	// No path given: show usage rather than the auth banner, which would blame the wrong thing.
	if len(args) == 0 {
		return usageError(cmd, "a path to scan is required")
	}
	if err := checkAuth(cmd); err != nil {
		return err
	}
	if err := validateOutputFormat(cmd); err != nil {
		return err
	}
	components, err := resolveComponentLimit(cmd)
	if err != nil {
		return err
	}
	layers, err := scanLayers(cmd)
	if err != nil {
		return err
	}
	outputFormat, _ := cmd.Flags().GetString("format")
	reportSkippedLayers(outputFormat, layers)
	layers = effectiveLayers(outputFormat, layers) // don't gather what this format can't render

	targetPath := args[0]
	if _, err := os.Stat(targetPath); err != nil {
		return fmt.Errorf("error accessing path: %w", err)
	}

	threads, _ := cmd.Flags().GetInt("threads")
	if threads < 1 {
		threads = config.DefaultThreads
	}
	saveWFPFile, _ := cmd.Flags().GetString("save-wfp")
	settingsFlag, _ := cmd.Flags().GetString("settings")
	minSize, _ := cmd.Flags().GetInt64("min-size")
	maxSize, _ := cmd.Flags().GetInt64("max-size")
	if err := validateSizeBounds(minSize, maxSize); err != nil {
		return err
	}
	allExtensions, _ := cmd.Flags().GetBool("all-extensions")
	allFolders, _ := cmd.Flags().GetBool("all-folders")
	applyGitignore, _ := cmd.Flags().GetBool("gitignore")
	allHidden, _ := cmd.Flags().GetBool("all-hidden")

	// Settings drive file filtering and the BOM rules, which are applied SDK-side, post-scan,
	// via WithBOM. --identify and --ignore contribute to the same BOM.
	scanSettings, err := resolveSettings(settingsFlag, targetPath)
	if err != nil {
		return fmt.Errorf("error loading settings: %w", err)
	}
	scanSettings, err = mergeBOMRuleFlags(cmd, scanSettings)
	if err != nil {
		return err
	}
	skipHeaders, skipHeadersLimit := resolveSkipHeaders(cmd, scanSettings)

	prog := &scanProgress{}
	client, err := buildScanClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := createCancellableContext()
	defer cancel()

	// The profile says which rules apply; the flags say what the user asked for. The
	// two stages get their own, built from the same flags: the manifest stage is not the
	// scan's filters with a few fields swapped, and deriving one from the other is how a
	// profile's own decision used to get overwritten.
	collectOpts := filter.Scanning(scanSettings)
	applyCollectFlags(&collectOpts, minSize, maxSize, allExtensions, allFolders, applyGitignore, allHidden)

	depOpts := dependencyCollectOptions(scanSettings)
	applyCollectFlags(&depOpts, minSize, maxSize, allExtensions, allFolders, applyGitignore, allHidden)

	// The WFP copy streams to its destination while the scan generates it, so the file is
	// opened before the run and there is nothing left to save afterwards.
	var wfpOut *os.File
	if saveWFPFile != "" {
		wfpOut, err = os.Create(saveWFPFile)
		if err != nil {
			return fmt.Errorf("cannot create WFP file: %w", err)
		}
		// Safety net for the error paths; the success path closes explicitly below,
		// so this second Close is a harmless ErrClosed.
		defer func() { _ = wfpOut.Close() }()
	}

	result, err := scanpipeline.Run(ctx, scanpipeline.Options{
		Client:            client,
		Services:          servicesFor(layers),
		SourceDeclared:    layers.Has(LayerDeps),
		SourcePath:        targetPath,
		Threads:           threads,
		ScanFilters:       collectOpts,
		DependencyFilters: depOpts,
		ScanOptions:       scanTuning(cmd, scanSettings, prog, components),
		WFPOptions:        fingerprintOptions(skipHeaders, skipHeadersLimit),
		WFPWriter:         wfpWriterOrNil(wfpOut),
		OnProgress:        prog.layer,
	})
	prog.finish()
	if err != nil {
		return renderAPIError(fmt.Errorf("scan failed: %w", err))
	}
	// Close before claiming success: a buffered write error can surface only here,
	// and "saved" must not be printed over an incomplete file.
	if wfpOut != nil {
		if cerr := wfpOut.Close(); cerr != nil {
			warnf("failed to write WFP file: %v", cerr)
		} else {
			okf("WFP fingerprints saved to %s", saveWFPFile)
		}
	}

	if err := emitInventory(cmd, result.Inventory, targetPath); err != nil {
		return err
	}
	printErrorSummary(result.ProcessErrors)
	return nil
}

// wfpWriterOrNil keeps a nil *os.File from becoming a non-nil io.Writer: an interface
// holding a typed nil pointer is not nil, so the pipeline would write to it and panic.
func wfpWriterOrNil(f *os.File) io.Writer {
	if f == nil {
		return nil
	}
	return f
}

// runScanWFP scans a pre-generated WFP file directly (no fingerprinting). A bare WFP has no
// source tree, so the deps layer cannot be sourced; it assembles the inventory from the scan
// result and gathers the requested layers with a scanpipeline.Enricher.
func runScanWFP(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usageError(cmd, "a WFP file is required")
	}
	if err := checkAuth(cmd); err != nil {
		return err
	}
	if err := validateOutputFormat(cmd); err != nil {
		return err
	}
	components, err := resolveComponentLimit(cmd)
	if err != nil {
		return err
	}
	// A bare WFP has no source tree, so declared dependencies cannot be sourced. Rejecting deps
	// beats warning and carrying on: the output is an inventory the caller keeps, and one missing
	// the layer they asked for should not leave with a success code.
	values, _ := cmd.Flags().GetStringSlice("include")
	layers, err := ParseLayers(values, PurlLayers())
	if err != nil {
		return err
	}
	outputFormat, _ := cmd.Flags().GetString("format")
	reportSkippedLayers(outputFormat, layers)
	layers = effectiveLayers(outputFormat, layers) // don't gather what this format can't render

	wfpPath := args[0]
	info, err := os.Stat(wfpPath)
	if err != nil {
		return fmt.Errorf("error accessing WFP file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory; expected a WFP file", wfpPath)
	}
	wfp, err := os.ReadFile(wfpPath)
	if err != nil {
		return fmt.Errorf("error reading WFP file: %w", err)
	}
	if len(wfp) == 0 {
		return fmt.Errorf("WFP file %q is empty", wfpPath)
	}

	settingsFlag, _ := cmd.Flags().GetString("settings")
	scanSettings, err := resolveSettings(settingsFlag, filepath.Dir(wfpPath))
	if err != nil {
		return fmt.Errorf("error loading settings: %w", err)
	}
	scanSettings, err = mergeBOMRuleFlags(cmd, scanSettings)
	if err != nil {
		return err
	}
	// The header filter runs while fingerprinting, and this command is handed a WFP that is
	// already assembled. Rejecting beats ignoring: a user who passed it expects its effect, and
	// the file they should have filtered was written by an earlier command. Only an explicit
	// flag is rejected — the filter being on by default must not make this command unusable.
	if changed := cmd.Flags().Changed("skip-headers") || cmd.Flags().Changed("skip-headers-limit"); changed {
		return usageError(cmd, "--skip-headers applies while fingerprinting, not to an assembled WFP; regenerate it with \"scan\" or \"wfp\" (the filter is on by default there)")
	}

	prog := &scanProgress{}
	client, err := buildScanClient(cmd)
	if err != nil {
		return err
	}

	ctx, cancel := createCancellableContext()
	defer cancel()

	// One reporter for both halves: the scan's upload and server passes, and the enrichment that
	// follows. Without it this path draws the enrichment bars and nothing for the scan itself.
	rep := scanpipeline.NewReporter(prog.layer)

	var bom bomReport
	scanOpts := append(scanTuning(cmd, scanSettings, prog, components), scanoss.WithScanReporter(rep), bom.option())
	res, err := client.Scan.WFP(ctx, wfp, scanOpts...)
	if err != nil {
		return renderAPIError(fmt.Errorf("scan failed: %w", err))
	}
	if res.Result == nil {
		return fmt.Errorf("scan completed without a result")
	}

	inv := scansource.Inventory(res.Result, scansource.WithIdentified(bom.report.IsIdentified))
	enricher := scanpipeline.Enricher{Client: client, Services: servicesFor(layers), Reporter: rep}
	enrichErr := enricher.Enrich(ctx, &inv)
	prog.finish()
	if enrichErr != nil {
		warnf("Enrichment incomplete: %v", enrichErr)
	}
	return emitInventory(cmd, inv, wfpPath)
}

// buildScanClient constructs the SDK client from the shared scan flags. Nothing per-call is
// wired here: reporters and the scan-id notification travel with the call, so a caller
// registers them where it makes it — see scanTuning.
func buildScanClient(cmd *cobra.Command) (*scanoss.Client, error) {
	cfg, err := apiConfig(cmd)
	if err != nil {
		return nil, err
	}
	return scanoss.New(cfg)
}

// scanTuning builds the per-scan options — chunk size, poll interval, the component limit, the BOM rules, the ranking
// threshold and the scan-id notice — from the flags and settings.
func scanTuning(cmd *cobra.Command, scanSettings *settings.Settings, prog *scanProgress, components scanoss.ComponentLimit) []scanoss.ScanOption {
	chunkSize, _ := cmd.Flags().GetInt("chunk-size")
	pollInterval, _ := cmd.Flags().GetDuration("poll-interval")
	if chunkSize < 1024 {
		chunkSize = scanoss.DefaultScanChunkBytes
	}
	api, _ := cliconfig.ResolveAPI(cmd.Flags())

	scanOpts := []scanoss.ScanOption{
		scanoss.WithChunkBytes(chunkSize),
		scanoss.WithPollInterval(pollInterval),
		scanoss.WithMaxComponents(components),
		scanoss.WithScanIDNotify(func(id string) {
			prog.writeLine("") // separate the scan-id block from the filter/skip notices above
			prog.writeLine(infoLine("Scan id: %s", id))
			// The resume hint carries the resolved endpoint, so it still works in a
			// shell without the environment variable that produced it.
			prog.writeLine("  If interrupted, resume with:\n  " + buildResultsCommand(id, api.URL, api.Key))
			prog.writeLine("") // separate the resume hint from the progress bars below
		}),
	}
	if scanSettings != nil && scanSettings.HasBOM() {
		scanOpts = append(scanOpts, scanoss.WithBOM(&scanSettings.BOM))
	}
	if threshold := resolveRankingThreshold(cmd, scanSettings); threshold > 0 {
		scanOpts = append(scanOpts, scanoss.WithRankingThreshold(threshold))
	}
	return scanOpts
}

// bomReport collects what the BOM selection rules concluded during a scan, so the inventory
// adapter can mark the components the user declared. It exists because the verdict cannot travel
// on the scan envelope: that is an API SDK type, carrying what the server said.
//
// The commands that drive a scan themselves need this; `scan <path>` does not, because
// scanpipeline collects the same verdict internally.
type bomReport struct{ report postprocess.Report }

// option registers the collector with a scan. Safe to pass when no BOM rules are set: it simply
// never fires, and the zero Report answers "not identified" for everything.
func (b *bomReport) option() scanoss.ScanOption {
	return scanoss.WithBOMReport(func(r postprocess.Report) { b.report = r })
}

// fingerprintOptions maps the resolved header-filter settings onto the fingerprinting options.
// Both states are passed explicitly: pkg/wfp filters by default too, so leaving the option out
// when the user turned the filter off would switch it back on.
func fingerprintOptions(skipHeaders bool, limit int) []wfp.Option {
	if !skipHeaders {
		return []wfp.Option{wfp.WithoutSkipHeaders()}
	}
	return []wfp.Option{wfp.WithSkipHeaders(limit)}
}

// emitInventory renders inv in the --format and writes it to the --output target. scanPath names
// the SBOM project.
func emitInventory(cmd *cobra.Command, inv sbom.Inventory, scanPath string) error {
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")

	writer, err := output.NewWriter(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output writer: %w", err)
	}
	defer func() { _ = writer.Close() }()

	projectName := filepath.Base(scanPath)
	if projectName == "." || projectName == "/" {
		projectName = "" // let the sbom module apply its default
	}
	out, err := renderInventory(inv, outputFormat, projectName)
	if err != nil {
		return err
	}
	if err := writer.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing: %v\n", err)
	} else if outputFile != "" {
		okf("Results written to %s", outputFile)
	}
	return nil
}

// scanLayers reads and validates the --include flag into a scanpipeline layer set. Gathering
// is driven by this set — never by the output format.
//
// Only `scan <path>` accepts every layer: it walks a tree, so declared dependencies can be read
// from the manifests in it. The commands that start from a result or an SBOM parse their own,
// against the PURL-keyed layers alone.
func scanLayers(cmd *cobra.Command) (Set, error) {
	values, _ := cmd.Flags().GetStringSlice("include")
	return ParseLayers(values, AllLayers())
}

// renderInventory renders a gathered inventory in the requested format. raw wraps the inventory
// in the versioned envelope (sbom.RawDocument) as JSON; cyclonedx/spdx project it to an SBOM,
// dropping what they cannot represent.
func renderInventory(inv sbom.Inventory, format, projectName string) (string, error) {
	if format == config.FormatRaw {
		doc := sbom.NewRawDocument(inv, sbom.RawMetadata{
			Tool: config.AppName, ToolVersion: config.AppVersion, Project: projectName,
		})
		raw, err := doc.Marshal()
		if err != nil {
			return "", fmt.Errorf("error encoding results: %w", err)
		}
		return raw, nil
	}
	out, err := sbom.Generate(inv, sbom.Format(format), sbom.WithProjectName(projectName))
	if err != nil {
		return "", fmt.Errorf("error generating %s output: %w", format, err)
	}
	return out, nil
}
