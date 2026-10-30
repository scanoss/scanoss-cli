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

// Package scanpipeline runs the scan pipeline that assembles a neutral sbom.Inventory. Run is
// the full flow over a source path: collect files → fingerprint → scan → source declared
// dependencies from the same tree (the lockfile graph, and the manifests no lockfile covers,
// via sbom/depsource) → gather + enrich the requested layers via the SDK's decoration pipeline
// (scanoss.DecorationPipeline). Enricher is the gathering half on its own,
// for callers that already have an inventory (a scan result, or a parsed SBOM). Rendering
// is left to sbom.Generate — this package does not render. Layers to gather are driven by the
// caller's request, never by any output format.
package scanpipeline

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	scanossapi "github.com/scanoss/scanoss.api-sdk"

	"github.com/scanoss/scanoss.go/internal/logging"
	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/postprocess"
	"github.com/scanoss/scanoss.go/pkg/sbom"
	"github.com/scanoss/scanoss.go/pkg/sbom/depsource"
	"github.com/scanoss/scanoss.go/pkg/sbom/scansource"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
	"github.com/scanoss/scanoss.go/pkg/snippetmatch"
	"github.com/scanoss/scanoss.go/pkg/wfp"
)

// Options configures Run, the full scan pipeline over a source path. Every layer reports through
// OnProgress — the steps the pipeline runs itself and the ones it delegates to the SDK alike, so
// a caller listens on one channel rather than reconciling two.
type Options struct {
	Client *scanoss.Client // required

	// Services are the decoration services to gather over the components. The caller resolves
	// these — from a flag, a config file, or nothing at all — and hands over the result: this
	// package knows services, not whatever vocabulary produced them.
	Services []scanoss.Service

	// SourceDeclared asks for declared dependencies to be sourced from the dependency manifests in
	// the same tree, and merged into the inventory alongside the scan's detected components. It is
	// not a decoration service: nothing is fetched, the manifests already carry resolved PURLs.
	SourceDeclared bool

	SourcePath string // file or directory to scan (required)
	Threads    int    // fingerprint workers (<1 => 1)
	// ScanFilters collects the files to fingerprint; DependencyFilters collects the
	// manifests, when SourceDeclared asks for them.
	//
	// Both are the caller's to build, because only the caller knows which of the values
	// in them came from a user flag and which from a profile. This package used to
	// derive the second from the first by copying selected fields, which meant a field
	// the dependency profile had deliberately set was overwritten by the scan's.
	ScanFilters       filter.Options
	DependencyFilters filter.Options
	ScanOptions       []scanoss.ScanOption // per-scan tuning (chunk size, poll interval, BOM, ...)
	// WFPOptions tunes how each file is fingerprinted (see wfp.Option) — today, whether the
	// leading licence header, comments and imports are dropped. Empty gets pkg/wfp's defaults,
	// which drop them; pass wfp.WithoutSkipHeaders to fingerprint files whole.
	WFPOptions []wfp.Option

	// WFPWriter, when set, receives the WFP as it is generated, block by block. It is how a
	// caller keeps the WFP: pass a file to save it, a bytes.Buffer to hold it in memory. Nil
	// discards it after upload, which costs nothing. Block order is completion order.
	WFPWriter io.Writer

	// OnProgress receives every layer's progress. Optional; nil reports nothing. The pipeline runs
	// layers concurrently, so it must be safe for concurrent use.
	OnProgress func(Progress)

	// ClassifySnippets asks for each snippet match in the inventory to be scored by the local
	// snippet classifier, which proposes whether the match is a false positive (its reported OSS
	// and local line ranges do not correspond). The verdict lands on each match's
	// FileEvidence.SnippetClassification; nothing is removed unless FilterFalsePositives says so.
	// It is opt-in because scoring fetches the matched OSS files over the network, so a bare scan
	// pays nothing for it.
	ClassifySnippets bool
	// ClassifyThreshold overrides the classifier's decision threshold (P(false positive) at or
	// above which a match is proposed as a false positive). 0 uses snippetmatch.DefaultThreshold
	// (0.7), tuned to propose for human confirmation.
	ClassifyThreshold float64
	// FilterFalsePositives removes the snippet matches the classifier proposed as false positives,
	// and any component left with no evidence (see sbom.Inventory.RemoveFalsePositiveSnippets).
	// Ignored unless ClassifySnippets is set.
	FilterFalsePositives bool
}

// ClassifySummary is what snippet classification did, for the caller to report: the
// classifier's own tally plus what the pipeline did around it.
type ClassifySummary struct {
	snippetmatch.Summary

	// Removed is how many snippet matches FilterFalsePositives removed.
	Removed int
	// DeniedStatus is the HTTP status (401 or 403) the API answered a file-contents request with,
	// or 0. Every match needs its OSS file, so a key without file-contents access scores nothing.
	DeniedStatus int
	// Err is set when the classifier could not start; nothing was scored.
	Err error
}

// Result is the outcome of Run: the gathered inventory, the files that could not be
// fingerprinted, and whether enrichment came back whole. The WFP is not here — it streams
// through a temporary file, and a caller that wants it passes Options.WFPWriter.
//
// What the filters excluded is not here: it is reported as the collect layer completing, while the
// scan is still ahead, rather than handed back once everything is over.
type Result struct {
	Inventory sbom.Inventory

	// ProcessErrors are the files that could not be fingerprinted, as pkg/wfp reported them.
	// A scan of 3000 files that skipped 3 unreadable ones still produced a usable WFP, so these
	// are not fatal — but which file failed and why is the caller's to judge, and a count alone
	// cannot answer it. Empty when every file was fingerprinted.
	ProcessErrors []error

	// EnrichError reports that the requested layers did not all come back. The pipeline stays
	// non-fatal — a service that fails does not discard a scan — so this is how a caller tells an
	// inventory with no licences because the project declares none from one with no licences
	// because every request failed. Nil when everything asked for arrived.
	EnrichError error

	// Classification reports the snippet classification. Nil unless Options.ClassifySnippets was
	// set and the scan produced an inventory.
	Classification *ClassifySummary
}

// Run executes the full pipeline over Options.SourcePath: collect the files (applying the
// filters for a directory), fingerprint them, scan, source declared dependencies from the same
// file set (when the deps layer is requested), and gather + enrich into an Inventory. It owns
// everything from file collection onward; the caller supplies only flag-derived configuration.
func Run(ctx context.Context, opts Options) (Result, error) {
	// Checked here rather than left to the first dereference: the client is used inside the scan
	// goroutine below, where a nil panics on a stack the caller cannot recover from, and Run's own
	// deferred Wait would hand back a nil error while the process is already being torn down.
	if opts.Client == nil {
		return Result{}, fmt.Errorf("a client is required (Options.Client)")
	}

	r := NewReporter(opts.OnProgress)
	emit := r.emit

	info, err := os.Stat(opts.SourcePath)
	if err != nil {
		return Result{}, fmt.Errorf("accessing path: %w", err)
	}

	// Collect the files to scan: a directory is filtered, a single file is taken as-is. The
	// scan root labels the WFP paths relative to it. Fingerprinting and dependency scanning need
	// different filters: the fingerprint filter drops dependency manifests (package.json, go.mod,
	// …) since they aren't useful for matching, so when the deps layer is requested we collect a
	// second time with a dependency-scoped filter and keep only the manifests and lockfiles the
	// dependency stage reads. The pipeline applies this second filter implicitly.
	var files []string
	var skipped int
	var manifestFiles []string
	scanRoot := opts.SourcePath
	if info.IsDir() {
		cr, collectErr := filter.Collect(opts.SourcePath, opts.ScanFilters)
		if collectErr != nil {
			return Result{}, fmt.Errorf("collecting files: %w", collectErr)
		}
		files, skipped = cr.Files, cr.SkippedCount

		if opts.SourceDeclared {
			// Collecting manifests is its own stage with its own rules, handed over
			// ready: nothing here reaches into the scan's to build them.
			dcr, depErr := filter.Collect(opts.SourcePath, opts.DependencyFilters)
			if depErr != nil {
				return Result{}, fmt.Errorf("collecting dependency manifests: %w", depErr)
			}
			manifestFiles = depsource.Select(dcr.Files)
		}
	} else {
		abs, absErr := filepath.Abs(opts.SourcePath)
		if absErr != nil {
			abs = opts.SourcePath
		}
		files = []string{abs}
		scanRoot = filepath.Dir(opts.SourcePath)
		if opts.SourceDeclared {
			manifestFiles = depsource.Select(files)
		}
	}
	if abs, absErr := filepath.Abs(scanRoot); absErr == nil {
		scanRoot = abs
	}
	// The walk has no incremental progress — its total is unknown until it ends — so it reports
	// once, on completion: how many files it kept out of how many it saw. A consumer wanting the
	// excluded count subtracts.
	emit(Progress{Layer: LayerCollect, Status: StatusCompleted, Done: len(files), Total: len(files) + skipped})

	threads := opts.Threads
	if threads < 1 {
		threads = 1
	}

	// Run the two independent halves concurrently: the scan (fingerprint → upload → server) and
	// the declared-dependency resolution (parse manifests → resolve). They hit different API
	// endpoints and share no state, so there is no reason to serialize them. Enrichment waits for
	// both, since it decorates detected and declared components together.
	var (
		scanResult     *scanossapi.ScanResult
		bomReport      postprocess.Report
		procErrors     []error
		scanErr        error
		fingerprintErr error
		declared       sbom.Inventory
		wg             sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Fingerprinting stays here rather than going through Scan.Folder, which would do it too:
		// this package already has the file list, the root and the worker count as plain values,
		// and handing them to the SDK instead would mean scan options existing for no reason but
		// to carry back what Stream already returns (per-file errors) and takes (the WFP tee).
		//
		// The WFP streams block by block into a temporary spill file — and into the caller's
		// WFPWriter when one is set — so it never sits in memory whole. The upload then reads
		// the spill in ranges; it is removed once the goroutine ends, since a resumable scan is
		// recovered by its id, never by re-reading the spill.
		spill, err := os.CreateTemp("", "scanoss-wfp-*")
		if err != nil {
			scanErr = fmt.Errorf("creating the WFP spill file: %w", err)
			return
		}
		defer func() {
			_ = spill.Close()
			_ = os.Remove(spill.Name())
		}()

		dest := io.Writer(spill)
		if opts.WFPWriter != nil {
			dest = io.MultiWriter(spill, opts.WFPWriter)
		}
		// Buffered so each ~2 KB fingerprint block does not become its own syscall. The flush
		// must land before Stat sizes the spill.
		buffered := bufio.NewWriterSize(dest, 64<<10)
		fileErrs, err := wfp.Stream(files, threads, scanRoot, buffered, r.Fingerprinting, opts.WFPOptions...)
		procErrors = fileErrs
		if err == nil {
			err = buffered.Flush()
		}
		if err != nil {
			scanErr = fmt.Errorf("writing the WFP: %w", err)
			emit(Progress{Layer: LayerFingerprint, Status: StatusFailed, Total: len(files)})
			return
		}

		info, err := spill.Stat()
		if err != nil {
			scanErr = fmt.Errorf("sizing the WFP spill file: %w", err)
			return
		}
		// An empty WFP is a failed stage, not a completed one: there is nothing to upload, so
		// the scan cannot run. A successfully fingerprinted file always writes bytes, so empty
		// separates all-files-failed from the filters having excluded every file.
		//
		// Whether that is fatal is not decided here: the manifest stage runs alongside, and a
		// project whose scannable files are all filtered can still have a dependency inventory
		// worth handing back. The verdict waits until both stages are in.
		if info.Size() == 0 {
			if len(fileErrs) > 0 {
				fingerprintErr = fmt.Errorf("no file could be fingerprinted (%d failed): %w",
					len(fileErrs), errors.Join(fileErrs...))
			} else {
				fingerprintErr = errors.New("no files to fingerprint: the filters excluded every file")
			}
			emit(Progress{Layer: LayerFingerprint, Status: StatusFailed, Total: len(files)})
			return
		}
		emit(Progress{Layer: LayerFingerprint, Status: StatusCompleted, Done: len(files), Total: len(files)})

		// The reporter travels with the call, not with the client: the client is the caller's, and a
		// reporter it registered for itself keeps working untouched.
		// A fresh slice rather than appending to the caller's: append writes into their array
		// whenever it has spare capacity, so the caller's Options would sprout an option it never
		// asked for. Options is exported, so the slice is theirs to reuse.
		scanOpts := make([]scanoss.ScanOption, 0, len(opts.ScanOptions)+2)
		scanOpts = append(scanOpts, opts.ScanOptions...)
		scanOpts = append(scanOpts, scanoss.WithScanReporter(r))
		// The BOM identify verdict cannot ride back on the envelope (an API SDK type), so it is
		// collected here and handed to the adapter below. Written from this goroutine and read
		// after wg.Wait, like scanResult itself.
		scanOpts = append(scanOpts, scanoss.WithBOMReport(func(rep postprocess.Report) {
			bomReport = rep
		}))

		res, err := opts.Client.Scan.WFPReader(ctx, spill, info.Size(), scanOpts...)
		if err != nil {
			scanErr = err
			return
		}
		if res.Result == nil {
			scanErr = fmt.Errorf("scan completed without a result")
			return
		}
		scanResult = res.Result
	}()

	// manifestFiles is populated only when the deps layer is requested (see the collection above).
	if len(manifestFiles) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			total := len(manifestFiles)
			emit(Progress{Layer: LayerManifests, Status: StatusRunning, Total: total}) // show it up front, alongside fingerprinting
			var failed map[string]error
			declared, failed = depsource.Inventory(scanRoot, manifestFiles)
			for path, readErr := range failed {
				logging.Warn("dependency file could not be read", "path", path, "err", readErr)
			}
			// All of them failing is a failed layer; some of them is a partial answer that
			// is still worth having. Reporting both the same way used to make an empty
			// result indistinguishable from a project that declares nothing.
			if len(failed) == total {
				emit(Progress{Layer: LayerManifests, Status: StatusFailed, Total: total})
				return
			}
			emit(Progress{Layer: LayerManifests, Status: StatusCompleted, Done: total, Total: total})
		}()
	}

	wg.Wait()
	if scanErr != nil {
		return Result{}, scanErr
	}
	// Nothing was fingerprinted. Fatal only when the manifest stage produced nothing either:
	// otherwise the declared components are a real inventory, and discarding them would throw
	// away work that succeeded because a different stage found nothing to do.
	if fingerprintErr != nil && len(declared.Components) == 0 {
		return Result{}, fingerprintErr
	}
	if scanResult == nil && len(declared.Components) == 0 {
		return Result{ProcessErrors: procErrors}, nil
	}

	// The enrichment layers report to r as well.
	inv := scansource.Inventory(scanResult, scansource.WithIdentified(bomReport.IsIdentified))
	inv.Add(declared.Components...)
	inv.Dependencies = declared.Dependencies

	// Snippet classification runs over the assembled inventory, before enrichment: a component the
	// filter removes is then never sent to the decoration services, so no advisory or licence is
	// gathered for it. Opt-in, and non-fatal like enrichment — a match that could not be scored is
	// simply left unannotated, and the summary says how many.
	var classification *ClassifySummary
	if opts.ClassifySnippets {
		classification = classifySnippets(ctx, opts, scanRoot, &inv, emit)
	}

	enrichErr := Enricher{Client: opts.Client, Services: opts.Services, Reporter: r}.Enrich(ctx, &inv)

	return Result{
		Inventory:      inv,
		ProcessErrors:  procErrors,
		EnrichError:    enrichErr,
		Classification: classification,
	}, nil
}

// classifySnippets scores the inventory's snippet matches in place, reporting progress under
// LayerClassify, and removes the proposed false positives when asked to. It is best-effort: a
// construction failure or a partly-failed run is reported in the summary, not returned, because
// a scan whose matches could not all be scored is still a usable scan.
func classifySnippets(ctx context.Context, opts Options, scanRoot string, inv *sbom.Inventory, emit func(Progress)) *ClassifySummary {
	emit(Progress{Layer: LayerClassify, Status: StatusRunning, Total: 0})
	// The fetch stage reports done/total as OSS files arrive; remember the total so completion
	// can fill the bar (a StatusCompleted with Total 0 would leave it aborted).
	var total int
	fetcher := &deniedRecorder{api: opts.Client.Contents}
	annotator, err := snippetmatch.New(snippetmatch.Options{
		Fetcher:   fetcher,
		ScanRoot:  scanRoot,
		Threshold: opts.ClassifyThreshold,
		Workers:   opts.Threads,
		OnProgress: func(done, t int) {
			total = t
			emit(Progress{Layer: LayerClassify, Status: StatusRunning, Done: done, Total: t})
		},
	})
	if err != nil {
		logging.Warn("snippet classification could not start", "err", err)
		emit(Progress{Layer: LayerClassify, Status: StatusFailed})
		return &ClassifySummary{Err: err}
	}
	sum, err := annotator.Annotate(ctx, inv)
	if err != nil {
		// Partial failures are already logged per match inside Annotate; this names the tally.
		logging.Warn("snippet classification incomplete", "err", err)
	}
	out := &ClassifySummary{Summary: sum, DeniedStatus: int(fetcher.status.Load())}
	if opts.FilterFalsePositives {
		out.Removed = inv.RemoveFalsePositiveSnippets()
	}
	emit(Progress{Layer: LayerClassify, Status: StatusCompleted, Done: total, Total: total})
	return out
}

// deniedRecorder passes file-contents requests through and remembers the first 401 or 403, so
// the summary can say the API key lacks file-contents access instead of only counting failures.
type deniedRecorder struct {
	api    scanoss.ContentsAPI
	status atomic.Int32
}

func (d *deniedRecorder) File(ctx context.Context, hash string, start, end int) ([]byte, error) {
	b, err := d.api.File(ctx, hash, start, end)
	var se *scanoss.StatusError
	if errors.As(err, &se) && (se.StatusCode == http.StatusUnauthorized || se.StatusCode == http.StatusForbidden) {
		d.status.CompareAndSwap(0, int32(se.StatusCode))
	}
	return b, err
}

// Enricher is what the requested layers are gathered with: a client to ask, the layers to ask
// for, and who to report progress to. Run builds one from its Options; a caller that already has
// an inventory — from a scan result, or parsed from an existing SBOM — builds one directly.
//
// The zero Services asks for nothing, which is not an error: a bare scan does no decoration work.
type Enricher struct {
	Client   *scanoss.Client
	Services []scanoss.Service
	Reporter scanoss.DecorationReporter
}

// Enrich attaches the requested purl-layers to the inventory's components in place —
// licenses/cryptography/geoprovenance inline on each component, vulnerabilities as the flat
// top-level list. It is format-blind, keyed purely by PURL (+ version).
//
// Enrichment is non-fatal, so the inventory is usable whatever this returns: a layer that failed
// is simply absent. The error names what did not arrive, which is the only way to tell an
// inventory with no licences because the project declares none from one with no licences because
// every request failed. With no layer requested, or no component to decorate, it makes no API
// call and returns nil.
func (e Enricher) Enrich(ctx context.Context, inv *sbom.Inventory) error {
	if len(e.Services) == 0 || len(inv.Components) == 0 {
		return nil
	}

	comps := make([]scanoss.Component, 0, len(inv.Components))
	for _, c := range inv.Components {
		comps = append(comps, scanoss.Component{Purl: c.Purl, Requirement: c.Version})
	}

	// Announce every layer before starting, so each is on screen from the outset rather than
	// appearing when its first response lands. The services run concurrently but answer at very
	// different speeds — one endpoint can take ten times longer per request than another — and a
	// layer that only shows up once it has an answer looks like a layer that started late.
	if e.Reporter != nil {
		for _, svc := range e.Services {
			e.Reporter.Decorating(svc.Name, 0, len(comps))
		}
	}

	res, err := e.Client.DecorationPipeline(e.Services...).Run(ctx, comps, scanoss.WithDecorationReporter(e.Reporter))
	if err != nil {
		logging.Warn("decoration pipeline failed", "err", err)
		return fmt.Errorf("gathering the requested layers: %w", err)
	}
	var layerErrs []error
	for name, svcErr := range res.Errors {
		logging.Warn("could not fetch a layer", "service", name, "err", svcErr)
		layerErrs = append(layerErrs, fmt.Errorf("%s: %w", name, svcErr))
	}

	// Per-component layers attach inline by PURL (+ version where the response echoes it).
	if lic := res.Licenses; lic != nil {
		warnPartial(scanoss.ServiceLicenses.Name, lic.Failed)
		byKey := scansource.Licenses(lic.Response)
		for i := range inv.Components {
			c := &inv.Components[i]
			c.Licenses = byKey[scansource.Key(c.Purl, c.Version)]
		}
	}
	if cry := res.Cryptography; cry != nil {
		warnPartial(scanoss.ServiceCryptographyAlgorithms.Name, cry.Failed)
		byKey := scansource.Cryptography(cry.Response)
		for i := range inv.Components {
			c := &inv.Components[i]
			c.Cryptography = byKey[scansource.Key(c.Purl, c.Version)]
		}
	}
	if geo := res.Geoprovenance; geo != nil {
		warnPartial(scanoss.ServiceGeoprovenanceOrigin.Name, geo.Failed)
		byPurl := scansource.Geoprovenance(geo.Response)
		for i := range inv.Components {
			c := &inv.Components[i]
			c.Geoprovenance = byPurl[c.Purl]
		}
	}

	// Vulnerabilities → flat top-level list joined by base PURL.
	if vul := res.Vulnerabilities; vul != nil {
		warnPartial(scanoss.ServiceVulnerabilities.Name, vul.Failed)
		inv.Vulnerabilities = scansource.Vulnerabilities(vul.Response)
	}

	// A layer that answered for some components but not all stays a warning: it answered. Only a
	// layer that did not answer at all is reported here.
	return errors.Join(layerErrs...)
}

// warnPartial reports a layer that arrived incomplete, naming the components it left out.
// Without it the gap is invisible: a component missing from a partial response is
// indistinguishable from one the service had nothing to say about.
func warnPartial(svc string, failed []scanoss.ChunkError) {
	if len(failed) == 0 {
		return
	}
	var purls []string
	for _, f := range failed {
		purls = append(purls, f.Purls...)
	}
	// Only the first few are named: the point is to say what is missing, not to fill a
	// terminal line when a whole scan's worth of components went unanswered. components
	// carries the total, so the count is never the part that gets truncated.
	first := purls
	if len(first) > 5 {
		first = first[:5]
	}
	logging.Warn("layer returned no data for some components",
		"service", svc, "components", len(purls), "first", first)
}
