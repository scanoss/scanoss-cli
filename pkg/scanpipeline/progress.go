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

package scanpipeline

import (
	"math"

	scanossapi "github.com/scanoss/scanoss.api-sdk"

	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

// Progress is one update from one pipeline layer, whether the pipeline ran that layer itself or
// delegated it to the SDK. Every field means the same thing for every layer, so a consumer can
// render any update without knowing which layer produced it, or how that layer works.
//
// Done and Total only ever grow within a layer. Where the underlying work says otherwise — the
// server-side scan runs in passes that each restart their own counter — it is normalised here, so
// that no consumer has to know.
type Progress struct {
	Layer  string // which layer is reporting; see the Layer* constants
	Status Status // where that layer is
	Done   int    // units done, only ever growing
	Total  int    // units in total; 0 when the layer cannot say
}

// Status is a layer's position in its lifecycle, normalised so that layers as different as a local
// file walk and a queued server-side scan are rendered the same way.
type Status string

const (
	StatusPending   Status = "pending" // known, not started: a queued scan, a layer awaiting its turn
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Layers the pipeline runs itself or delegates. Enrichment layers are not listed: they report
// under their API service name, which the SDK already supplies.
const (
	LayerCollect     = "collect"     // local: walking the tree and applying the filters
	LayerFingerprint = "fingerprint" // local: hashing the collected files
	LayerManifests   = "manifests"   // local: parsing dependency manifests
	LayerUpload      = "upload"      // remote: uploading the WFP
	LayerScan        = "scan"        // remote: the server-side scan
	LayerClassify    = "classify"    // remote+local: scoring snippet matches with the classifier
)

// scanPasses is how many equal segments the scan's progress is divided into, one per pass that can
// actually be observed running. Each pass restarts its own counter and counts something different
// from the last, so those numbers cannot drive one counter directly; a pass owns a segment instead,
// and its progress moves the bar inside it.
//
// Two, not three. The server runs three passes — match files, match snippets, resolve components —
// but the third has only ever been seen arriving in the envelope that already reports the scan
// completed, never in one reporting it still scanning: it is too short to fall between two polls.
// Giving it a segment of its own left the last third of the bar unreachable, so the bar stopped at
// two thirds and jumped to done.
//
// What this reports is which pass is running, not how much work is left. The latter cannot be
// known: each pass's size is only discovered by running the one before it, and the passes work on
// shrinking subsets of the same files, so there is no total to count towards. A pass beyond the
// second shares the last segment, and completion is what fills the bar.
const scanPasses = 2

// scanTracker turns the server's per-pass counters into one that only grows.
//
// It is written by the goroutine polling the scan and read nowhere else, so it needs no lock of
// its own.
type scanTracker struct {
	pass string // name of the pass currently being reported
	seen int    // distinct passes seen so far
	pct  int    // last percentage emitted; never decreases
}

// progress maps one scan status poll onto the layer's 0..100 range.
//
// Polling samples the scan rather than streaming it, so a pass shorter than the poll interval is
// never reported at all, and the last pass is routinely still mid-segment when the scan completes.
// That is why completion comes from the status and fills the range: the counters, having missed
// what they missed, would never reach it on their own.
func (t *scanTracker) progress(e *scanossapi.ScanEnvelope) Progress {
	switch string(e.Status) {
	case "queued":
		return Progress{Layer: LayerScan, Status: StatusPending, Total: 100}

	case "completed":
		t.pct = 100
		return Progress{Layer: LayerScan, Status: StatusCompleted, Done: 100, Total: 100}

	case "failed", "expired":
		return Progress{Layer: LayerScan, Status: StatusFailed, Done: t.pct, Total: 100}
	}

	// Uploading or scanning: position the bar inside the current pass's segment.
	if t.seen == 0 || e.Phase != t.pass {
		t.pass, t.seen = e.Phase, t.seen+1
	}
	segment := min(t.seen, scanPasses)

	var within float64 // fraction of the current pass completed
	if e.PhaseTotal > 0 {
		within = math.Min(float64(e.PhaseDone)/float64(e.PhaseTotal), 1)
	}
	pct := int((float64(segment-1) + within) / scanPasses * 100)

	// A pass beyond the second shares the last segment and would otherwise restart inside it; a
	// server reporting no pass name at all keeps every poll in the first. Neither may drag the
	// layer backwards, which is the whole point of normalising here.
	t.pct = max(t.pct, pct)
	return Progress{Layer: LayerScan, Status: StatusRunning, Done: t.pct, Total: 100}
}

// Reporter turns the SDK's stages into this package's layer updates. Run wires one up itself; it
// is exported for the callers that drive the SDK directly — `results` resumes a scan and enriches
// it, collecting and fingerprinting nothing — so that every entry point reports layers the same
// way and the translation exists in one place.
//
// Hand it to a call with WithScanReporter and WithDecorationReporter — the reporter belongs to the
// operation, not to the client, so the same client can serve several with different listeners.
type Reporter struct {
	scan scanTracker // folds the server's restarting per-pass counters into one that grows
	on   func(Progress)
}

// NewReporter returns a Reporter delivering to on. A nil on makes every update a no-op.
func NewReporter(on func(Progress)) *Reporter { return &Reporter{on: on} }

var (
	_ scanoss.ScanReporter       = (*Reporter)(nil)
	_ scanoss.DecorationReporter = (*Reporter)(nil)
)

func (r *Reporter) Fingerprinting(done, total int) {
	r.emit(Progress{Layer: LayerFingerprint, Status: StatusRunning, Done: done, Total: total})
}

func (r *Reporter) Uploading(done, total int) {
	r.emit(Progress{Layer: LayerUpload, Status: StatusRunning, Done: done, Total: total})
}

// Scanning normalises the poll: the server restarts its counter on every pass, so each pass owns a
// share of the layer's range and the result only ever grows.
func (r *Reporter) Scanning(e scanossapi.ScanEnvelope) { r.emit(r.scan.progress(&e)) }

// Decorating names the layer after the service that reported it, which is what a consumer sees.
func (r *Reporter) Decorating(service string, done, total int) {
	r.emit(Progress{Layer: service, Status: StatusRunning, Done: done, Total: total})
}

// emit hands one update on, if anyone asked for them.
func (r *Reporter) emit(u Progress) {
	if r != nil && r.on != nil {
		r.on(u)
	}
}
