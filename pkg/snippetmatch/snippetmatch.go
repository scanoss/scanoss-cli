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

// Package snippetmatch annotates a scan inventory's snippet matches with the local
// snippet-classifier's verdict on whether each match is a false positive — a match whose
// reported OSS line range does not correspond to its reported local range.
//
// The classifier itself (github.com/scanoss/snippets-classifier) is offline and needs no
// state, but scoring a match needs three inputs: the scanned (local) file, the matched OSS
// file, and the paired line ranges. The inventory carries the ranges and the OSS file's hash;
// this package reads the local file from disk and fetches the OSS file's content by hash. The
// fetch is the only network cost, so unique OSS hashes are downloaded once and reused across
// every match that shares them.
//
// Annotation only proposes: it sets FileEvidence.SnippetClassification and removes nothing.
package snippetmatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	snippetclassifier "github.com/scanoss/snippets-classifier"

	"github.com/scanoss/scanoss.go/internal/logging"
	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// DefaultThreshold is the P(false positive) at or above which a match is proposed as a false
// positive. It is the classifier's own default (0.7), tuned to propose for human confirmation.
const DefaultThreshold = snippetclassifier.DefaultThreshold

// DefaultWorkers bounds the concurrent OSS content fetches when Options.Workers is unset.
const DefaultWorkers = 8

// Fetcher retrieves the raw content of an OSS file by its MD5. A 1-based inclusive line range
// may be given; 0 for either bound leaves it at the default (line 1 / the last line), so
// (md5, 0, 0) is the whole file. scanoss.ContentsAPI satisfies this interface.
type Fetcher interface {
	File(ctx context.Context, md5 string, start, end int) ([]byte, error)
}

// Options configures an Annotator.
type Options struct {
	// Fetcher supplies OSS file content by hash. Required.
	Fetcher Fetcher
	// ScanRoot is the directory the inventory's file paths are relative to. Required for a
	// directory scan; a match whose local file cannot be read is skipped, not failed.
	ScanRoot string
	// Threshold overrides the classifier's decision threshold. 0 uses DefaultThreshold.
	Threshold float64
	// Model, when non-empty, replaces the embedded model (a per-organisation model in the same
	// JSON shape). Empty uses the embedded default.
	Model []byte
	// Workers bounds concurrent OSS content fetches. <1 uses DefaultWorkers.
	Workers int
	// OnProgress, when set, is called as OSS files are fetched (done out of total unique
	// hashes). It must be safe for concurrent use.
	OnProgress func(done, total int)
}

// Annotator scores an inventory's snippet matches. Build one with New and reuse it.
type Annotator struct {
	fetcher    Fetcher
	scanRoot   string
	workers    int
	inner      *snippetclassifier.Classifier
	onProgress func(done, total int)
}

// New builds an Annotator from opts. It errors when no Fetcher is given or the model cannot be
// loaded.
func New(opts Options) (*Annotator, error) {
	if opts.Fetcher == nil {
		return nil, errors.New("snippetmatch: a Fetcher is required")
	}
	var copts []snippetclassifier.Option
	if opts.Threshold != 0 {
		copts = append(copts, snippetclassifier.WithThreshold(opts.Threshold))
	}
	if len(opts.Model) > 0 {
		copts = append(copts, snippetclassifier.WithModel(opts.Model))
	}
	inner, err := snippetclassifier.New(copts...)
	if err != nil {
		return nil, fmt.Errorf("snippetmatch: %w", err)
	}
	workers := opts.Workers
	if workers < 1 {
		workers = DefaultWorkers
	}
	return &Annotator{
		fetcher:    opts.Fetcher,
		scanRoot:   opts.ScanRoot,
		workers:    workers,
		inner:      inner,
		onProgress: opts.OnProgress,
	}, nil
}

// ModelVersion identifies the model the Annotator scores with.
func (a *Annotator) ModelVersion() string { return a.inner.ModelVersion() }

// job is one snippet match to score: where its result goes and what it needs.
type job struct {
	ev    *sbom.FileEvidence
	path  string // local file path, relative to scanRoot
	hash  string // OSS file MD5
	spans []snippetclassifier.Span
}

// Annotate scores every snippet match in inv in place, setting FileEvidence.SnippetClassification
// on each match it could score. It is non-fatal: a match whose local file is unreadable or whose
// OSS content cannot be fetched is left unannotated and logged. The returned error names how many
// matches could not be scored, for the caller to surface; it does not mean the inventory is
// unusable.
//
// The inventory is scored, not filtered: no match is removed, whatever its verdict.
func (a *Annotator) Annotate(ctx context.Context, inv *sbom.Inventory) error {
	jobs := collectJobs(inv)
	if len(jobs) == 0 {
		return nil
	}

	// Fetch each distinct OSS file once. Several matches often point at the same OSS file
	// (different local files matching the same upstream source), and the download is the only
	// network cost, so it is shared.
	oss := a.fetchOSS(ctx, uniqueHashes(jobs))

	// Local files are read from disk once per distinct path. Cheap next to the network, so this
	// stays sequential.
	local := a.readLocal(uniquePaths(jobs))

	// Score. Each job reads only from the read-only caches, and the classifier is safe for
	// concurrent use, so the CPU-bound scoring fans out too. A worst-case OSS file takes ~1s.
	var skipped int
	var mu sync.Mutex
	a.forEach(jobs, func(j job) {
		lb, ok := local[j.path]
		if !ok {
			mu.Lock()
			skipped++
			mu.Unlock()
			return
		}
		ob, ok := oss[j.hash]
		if !ok {
			mu.Lock()
			skipped++
			mu.Unlock()
			return
		}
		res, err := a.inner.Classify(snippetclassifier.Match{Local: lb, OSS: ob, Spans: j.spans})
		if err != nil {
			logging.Warn("snippet classification failed", "path", j.path, "err", err)
			mu.Lock()
			skipped++
			mu.Unlock()
			return
		}
		j.ev.SnippetClassification = &sbom.SnippetClassification{
			Verdict:      string(res.Verdict),
			Probability:  res.Probability,
			ModelVersion: res.ModelVersion,
		}
	})

	if skipped > 0 {
		return fmt.Errorf("snippetmatch: %d of %d snippet matches could not be classified", skipped, len(jobs))
	}
	return nil
}

// collectJobs gathers every snippet match that can be scored: one with an OSS file hash and at
// least one paired local/OSS line range. The evidence pointer is kept so the verdict lands back
// on the inventory.
func collectJobs(inv *sbom.Inventory) []job {
	var jobs []job
	for ci := range inv.Components {
		evs := inv.Components[ci].Evidence
		for ei := range evs {
			ev := &evs[ei]
			if ev.MatchType != "snippet" || ev.FileHash == "" {
				continue
			}
			spans := spansOf(ev.InputLineRanges, ev.OssLineRanges)
			if len(spans) == 0 {
				continue
			}
			jobs = append(jobs, job{ev: ev, path: ev.Path, hash: ev.FileHash, spans: spans})
		}
	}
	return jobs
}

// spansOf pairs the local and OSS line ranges index by index, as the scanner reports them in
// parallel. A range present on only one side has no counterpart and is dropped.
func spansOf(local, oss []sbom.LineRange) []snippetclassifier.Span {
	n := min(len(local), len(oss))
	if n == 0 {
		return nil
	}
	spans := make([]snippetclassifier.Span, 0, n)
	for i := 0; i < n; i++ {
		spans = append(spans, snippetclassifier.Span{
			LocalStart: local[i].StartLine, LocalEnd: local[i].EndLine,
			OSSStart: oss[i].StartLine, OSSEnd: oss[i].EndLine,
		})
	}
	return spans
}

// fetchOSS downloads the whole content of each hash, concurrently and bounded by a.workers.
// The classifier's global features (matched_inf_ratio, log_longest_run) read the entire OSS
// file, so the whole file is fetched — not just the matched window. A fetch that fails leaves
// its hash out of the map and is logged.
func (a *Annotator) fetchOSS(ctx context.Context, hashes []string) map[string][]byte {
	out := make(map[string][]byte, len(hashes))
	var mu sync.Mutex
	var done int
	total := len(hashes)

	sem := make(chan struct{}, a.workers)
	var wg sync.WaitGroup
	for _, h := range hashes {
		wg.Add(1)
		sem <- struct{}{}
		go func(hash string) {
			defer wg.Done()
			defer func() { <-sem }()
			content, err := a.fetcher.File(ctx, hash, 0, 0)
			mu.Lock()
			if err != nil {
				logging.Warn("fetching OSS file content failed", "hash", hash, "err", err)
			} else {
				out[hash] = content
			}
			done++
			d := done
			mu.Unlock()
			if a.onProgress != nil {
				a.onProgress(d, total)
			}
		}(h)
	}
	wg.Wait()
	return out
}

// readLocal reads each distinct local file once, resolving it against the scan root. An
// unreadable file is left out of the map and logged.
func (a *Annotator) readLocal(paths []string) map[string][]byte {
	out := make(map[string][]byte, len(paths))
	for _, p := range paths {
		full := p
		if a.scanRoot != "" && !filepath.IsAbs(p) {
			full = filepath.Join(a.scanRoot, p)
		}
		content, err := os.ReadFile(full)
		if err != nil {
			logging.Warn("reading local file for snippet classification failed", "path", p, "err", err)
			continue
		}
		out[p] = content
	}
	return out
}

// forEach runs fn over every job, bounded by a.workers. Jobs only read the shared caches and
// write to their own evidence pointer, so no locking is needed inside fn beyond what fn does.
func (a *Annotator) forEach(jobs []job, fn func(job)) {
	sem := make(chan struct{}, a.workers)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(j)
		}(j)
	}
	wg.Wait()
}

func uniqueHashes(jobs []job) []string {
	seen := make(map[string]struct{}, len(jobs))
	var out []string
	for _, j := range jobs {
		if _, ok := seen[j.hash]; ok {
			continue
		}
		seen[j.hash] = struct{}{}
		out = append(out, j.hash)
	}
	return out
}

func uniquePaths(jobs []job) []string {
	seen := make(map[string]struct{}, len(jobs))
	var out []string
	for _, j := range jobs {
		if _, ok := seen[j.path]; ok {
			continue
		}
		seen[j.path] = struct{}{}
		out = append(out, j.path)
	}
	return out
}
