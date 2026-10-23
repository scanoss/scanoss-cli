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

package scanoss

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	scanossapi "github.com/scanoss/scanoss.api-sdk"

	"github.com/scanoss/scanoss.go/internal/logging"
	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/postprocess"
	"github.com/scanoss/scanoss.go/pkg/settings"
	"github.com/scanoss/scanoss.go/pkg/wfp"
)

// ScanAPI is the batch scan service surface. Folder, Files, WFP and WFPReader each
// run the full flow — upload (parallel byte-range chunks) + poll to completion — and
// return the envelope with its Result populated. They differ only in the input: a
// directory tree, an explicit file list, or an already-assembled WFP (in memory, or
// read from a file). The caller never manages the scan id; stages are reported via
// WithScanReporter and the client-generated id is surfaced via WithScanIDNotify for
// optional recovery.
type ScanAPI interface {
	// Folder collects, fingerprints and scans a directory tree (or single file).
	Folder(ctx context.Context, path string, opts ...ScanOption) (scanossapi.ScanEnvelope, error)

	// Files fingerprints and scans an explicit list of files.
	Files(ctx context.Context, files []string, opts ...ScanOption) (scanossapi.ScanEnvelope, error)

	// WFP scans an already-assembled WFP byte stream.
	WFP(ctx context.Context, wfp []byte, opts ...ScanOption) (scanossapi.ScanEnvelope, error)

	// WFPReader scans an already-assembled WFP read from r — WFP without the
	// in-memory requirement, for a caller whose WFP lives in a file.
	WFPReader(ctx context.Context, r io.ReaderAt, size int64, opts ...ScanOption) (scanossapi.ScanEnvelope, error)

	// Status performs a single status poll for a known scan id.
	Status(ctx context.Context, scanID string) (scanossapi.ScanEnvelope, error)

	// Wait resumes polling a known scan id until a terminal state. Used to recover
	// an interrupted scan (e.g. `scanoss-cli results <id>`). The poll cadence can be
	// tuned with WithPollInterval.
	Wait(ctx context.Context, scanID string, opts ...ScanOption) (scanossapi.ScanEnvelope, error)
}

// serviceScan is the v3 batch scan endpoint. WFP fingerprints are uploaded as
// octet-stream byte ranges (Content-Range); the server assigns a scan id and
// queues the scan once all bytes are received.
var serviceScan = Service{Name: "scan", endpoint: "/v3/wfp/scan"}

// Scan defaults applied when the corresponding option is not given.
// DefaultScanChunkBytes is the WFP upload block size (1 MiB).
const DefaultScanChunkBytes = 1 << 20

// ScanOption configures a single scan (Folder / Files / WFP).
type ScanOption func(*scanOptions)

type scanOptions struct {
	chunkBytes int64          // WFP upload block size
	filters    filter.Options // file collection filters (Folder only)

	// root is what WFP paths are labelled relative to. No option sets it today, so Files
	// labels each file by its full path; Folder does not read it at all, resolving the
	// scanned folder as its own root.
	root string

	bom           *settings.BOM            // when set, BOM rules are applied to the result (post-scan)
	onBOMReport   func(postprocess.Report) // receives what the BOM selection rules concluded (WithBOMReport)
	wfpOptions    []wfp.Option             // per-file fingerprinting tuning (WithFingerprintOptions)
	rankThreshold int                      // drop matches ranked worse than this (WithRankingThreshold)
	maxComponents ComponentLimit           // components the server reports, sent with every block (WithMaxComponents)
	pollInterval  time.Duration            // scan status poll cadence (WithPollInterval)
	reporter      ScanReporter             // receives this scan's stages (WithScanReporter)
	onScanID      func(string)             // receives this scan's id once it is resumable (WithScanIDNotify)
}

func resolveScanOptions(opts []ScanOption) scanOptions {
	o := scanOptions{
		chunkBytes: DefaultScanChunkBytes,
		// The profile, not a hand-built equivalent: the two agree today only because the default
		// size bounds happen to be an int's zero value, so a change to either would silently leave
		// a scan filtering differently from everything else that uses the scanning profile.
		filters:      filter.Scanning(nil),
		pollInterval: DefaultScanPollInterval,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithScanIDNotify registers a callback invoked once with this scan's id, after the full
// WFP is uploaded and before polling begins — the point from which Scan.Wait can resume
// it. Optional; a normal scan needs no recovery.
func WithScanIDNotify(fn func(scanID string)) ScanOption {
	return func(o *scanOptions) { o.onScanID = fn }
}

// WithChunkBytes sets the WFP upload block size in bytes (default
// DefaultScanChunkBytes). Values <= 0 are ignored.
func WithChunkBytes(n int) ScanOption {
	return func(o *scanOptions) {
		if n > 0 {
			o.chunkBytes = int64(n)
		}
	}
}

// WithFilters sets the file-collection filters used by Folder: default skip lists,
// .gitignore and size bounds. The default is filter.Scanning(nil), which leaves
// Settings nil — pass scanoss.json rules here to have them applied.
func WithFilters(f filter.Options) ScanOption {
	return func(o *scanOptions) { o.filters = f }
}

// WithBOM applies the scan's bill-of-materials rules to the result, post-scan and in order:
// bom.remove (with bom.include as precedence) neutralizes matching file matches, then
// bom.replace re-points the survivors it covers at their replace_with component;
// unreferenced components are pruned. The whole BOM is passed so the rules still to come
// (pre-scan include/identify context, ignore) extend this same option. A nil BOM is a no-op.
func WithBOM(bom *settings.BOM) ScanOption {
	return func(o *scanOptions) { o.bom = bom }
}

// WithBOMReport registers a callback invoked once with what the BOM selection rules concluded —
// today, which components a bom.identify rule claimed. It fires after the rules are applied and
// only when there was a result to apply them to.
//
// It is a callback rather than a field on the returned envelope because the envelope is an API
// SDK type: it carries what the server said, and has nowhere to put a verdict the client reached
// on its own. Optional; a caller that only needs the rewritten result can ignore it.
func WithBOMReport(fn func(postprocess.Report)) ScanOption {
	return func(o *scanOptions) { o.onBOMReport = fn }
}

// WithRankingThreshold drops matches whose component ranks worse than threshold, post-scan.
// Rank is the scanner's own ordering of how well a component explains a match, lowest is
// strongest; ranks seen in practice run 1..9. A threshold at or below 0 disables the filter.
//
// It applies client-side, over the candidate matches the batch scanner reports with their ranks —
// nothing is asked of the server. Matches a bom.identify rule claims are never dropped by it.
func WithRankingThreshold(threshold int) ScanOption {
	return func(o *scanOptions) { o.rankThreshold = threshold }
}

// WithMaxComponents asks the server to report up to l components, or all of them. For a
// full-file match that is the best N components of the project ranking plus up to three context
// picks (folder, file alone, origin), each labelled in the match's context; a snippet block gets
// up to N candidates, and the allowed set widens to at least N. It is sent with every WFP block
// of the scan, because the server refuses a session whose blocks disagree. An unset limit sends
// nothing and leaves the server's defaults in force.
//
// The server must support the max_components parameter. Unlike WithRankingThreshold this is not
// applied client-side.
func WithMaxComponents(l ComponentLimit) ScanOption {
	return func(o *scanOptions) { o.maxComponents = l }
}

// WithFingerprintOptions tunes how each file is fingerprinted by Folder and Files — today,
// whether the leading licence header, comments and imports are dropped. They are dropped by
// default; wfp.WithoutSkipHeaders fingerprints files whole, and wfp.WithSkipHeaders caps how many
// lines go. It has no effect on WFP or WFPReader, which are handed a stream that is already
// assembled.
func WithFingerprintOptions(opts ...wfp.Option) ScanOption {
	return func(o *scanOptions) { o.wfpOptions = opts }
}

// WithPollInterval sets how often the scan status endpoint is polled while waiting
// for a scan to finish (default DefaultScanPollInterval). Values <= 0 are ignored.
// Very small intervals increase load on the server. Applies to the full scan flow
// (Folder/Files/WFP) and to Wait when resuming a known scan id.
func WithPollInterval(d time.Duration) ScanOption {
	return func(o *scanOptions) {
		if d > 0 {
			o.pollInterval = d
		}
	}
}

type scanService struct{ c *Client }

var _ ScanAPI = scanService{}

// Folder collects files under path (applying the filter options), fingerprints them
// straight to a temporary spill file, then scans it. The whole WFP never sits in memory.
func (s scanService) Folder(ctx context.Context, path string, opts ...ScanOption) (scanossapi.ScanEnvelope, error) {
	o := resolveScanOptions(opts)
	return s.scanStreamed(ctx, o, func(w io.Writer) ([]error, error) {
		return wfp.StreamFolder(path, &o.filters, s.c.workers, w, s.onFingerprint(o), o.wfpOptions...)
	})
}

// Files fingerprints an explicit list of files straight to a temporary spill file,
// then scans it. The whole WFP never sits in memory.
func (s scanService) Files(ctx context.Context, files []string, opts ...ScanOption) (scanossapi.ScanEnvelope, error) {
	o := resolveScanOptions(opts)
	if len(files) == 0 {
		return scanossapi.ScanEnvelope{}, fmt.Errorf("no files to scan")
	}
	return s.scanStreamed(ctx, o, func(w io.Writer) ([]error, error) {
		return wfp.Stream(files, s.c.workers, o.root, w, s.onFingerprint(o), o.wfpOptions...)
	})
}

// onFingerprint adapts the caller's reporter to the fingerprinting callback.
func (s scanService) onFingerprint(o scanOptions) func(done, total int) {
	return func(done, total int) {
		if o.reporter != nil {
			o.reporter.Fingerprinting(done, total)
		}
	}
}

// scanStreamed spills the WFP produced by fingerprint into a temporary file and uploads
// from it, so the stream never sits in memory whole. The file is removed whatever the
// outcome: a resumable scan is recovered by its id (Wait), never by re-reading the spill.
//
// Fingerprinting is best-effort, so a skipped file does not fail the scan — but it is
// reported. A successfully fingerprinted file always writes bytes, so an empty spill
// separates the two failures worth telling apart: input that could not be used (some
// files failed) and no input at all (the filters or the caller supplied nothing).
func (s scanService) scanStreamed(ctx context.Context, o scanOptions, fingerprint func(io.Writer) ([]error, error)) (scanossapi.ScanEnvelope, error) {
	spill, err := os.CreateTemp("", "scanoss-wfp-*")
	if err != nil {
		return scanossapi.ScanEnvelope{}, fmt.Errorf("creating the WFP spill file: %w", err)
	}
	defer func() {
		_ = spill.Close()
		_ = os.Remove(spill.Name())
	}()

	// Buffered so each ~2 KB fingerprint block does not become its own syscall. The
	// flush must land before Stat sizes the file.
	buffered := bufio.NewWriterSize(spill, 64<<10)
	fileErrs, err := fingerprint(buffered)
	if err != nil {
		return scanossapi.ScanEnvelope{}, err
	}
	if err := buffered.Flush(); err != nil {
		return scanossapi.ScanEnvelope{}, fmt.Errorf("writing the WFP spill file: %w", err)
	}
	for _, fpErr := range fileErrs {
		logging.Warn("skipped a file that could not be fingerprinted", "err", fpErr)
	}

	info, err := spill.Stat()
	if err != nil {
		return scanossapi.ScanEnvelope{}, fmt.Errorf("sizing the WFP spill file: %w", err)
	}
	if info.Size() == 0 {
		if len(fileErrs) > 0 {
			return scanossapi.ScanEnvelope{}, fmt.Errorf("no fingerprints generated")
		}
		return scanossapi.ScanEnvelope{}, fmt.Errorf("no files to scan")
	}
	return s.scan(ctx, spill, info.Size(), o)
}

// WFP scans an already-assembled WFP byte stream.
func (s scanService) WFP(ctx context.Context, wfp []byte, opts ...ScanOption) (scanossapi.ScanEnvelope, error) {
	return s.scan(ctx, bytes.NewReader(wfp), int64(len(wfp)), resolveScanOptions(opts))
}

// WFPReader scans an already-assembled WFP read from r (see ScanAPI.WFPReader).
func (s scanService) WFPReader(ctx context.Context, r io.ReaderAt, size int64, opts ...ScanOption) (scanossapi.ScanEnvelope, error) {
	return s.scan(ctx, r, size, resolveScanOptions(opts))
}

// scan uploads a ready WFP (parallel chunks) and waits for completion. The three entry
// points (Folder/Files/WFP) each produce the WFP, then funnel through here.
func (s scanService) scan(ctx context.Context, r io.ReaderAt, size int64, o scanOptions) (scanossapi.ScanEnvelope, error) {
	logging.Debug("scan: uploading WFP", "bytes", size, "chunkBytes", o.chunkBytes)
	scanID, err := s.upload(ctx, r, size, o)
	if err != nil {
		return scanossapi.ScanEnvelope{}, err
	}
	logging.Debug("scan uploaded", "scanID", scanID)

	env, err := s.wait(ctx, scanID, o.pollInterval, o.reporter)
	if err != nil {
		return scanossapi.ScanEnvelope{}, err
	}
	s.applyBOM(env, o)
	logging.Debug("scan complete", "scanID", scanID)
	return env, nil
}

// upload generates the scan id (UUIDv7) client-side, uploads every WFP chunk
// concurrently (each carrying the id, bounded by the client's worker limit), then
// fires the notify hook. The hook fires only after the full WFP is on the server,
// so the surfaced id is always resumable. It returns the scan id.
func (s scanService) upload(ctx context.Context, r io.ReaderAt, size int64, o scanOptions) (string, error) {
	if size == 0 {
		return "", fmt.Errorf("no fingerprints to scan")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("error generating scan id: %w", err)
	}
	scanID := id.String()

	ranges := chunkRanges(size, o.chunkBytes)
	logging.Debug("uploading WFP chunks", "scanID", scanID, "chunks", len(ranges))
	prog := &chunkProgress{r: o.reporter, total: len(ranges)}
	if err := s.uploadChunks(ctx, scanID, r, size, ranges, o.uploadQuery(), prog); err != nil {
		return "", err
	}

	// The full WFP is now on the server: the id is resumable. Surface it before
	// polling so an interrupted scan can be recovered with `results <id>`.
	if o.onScanID != nil {
		o.onScanID(scanID)
	}
	return scanID, nil
}

// uploadQuery is the query string every block of the upload carries. It is empty unless the
// caller set something that has to reach the server.
func (o scanOptions) uploadQuery() url.Values {
	if !o.maxComponents.IsSet() {
		return nil
	}
	return url.Values{maxComponentsParam: {o.maxComponents.String()}}
}

// uploadChunks uploads all chunks concurrently, bounded by the client's worker
// limit, aborting all on the first error.
func (s scanService) uploadChunks(ctx context.Context, scanID string, r io.ReaderAt, size int64, ranges [][2]int64, query url.Values, prog *chunkProgress) error {
	if len(ranges) == 0 {
		return nil
	}

	workers := s.c.workers
	if len(ranges) < workers {
		workers = len(ranges)
	}
	if workers < 1 {
		workers = 1
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan [2]int64)
	errCh := make(chan error, len(ranges))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rng := range jobs {
				select {
				case <-ctx.Done():
					errCh <- ctx.Err()
					continue
				default:
				}
				if err := s.c.uploadChunk(ctx, scanID, r, rng[0], rng[1], size, query); err != nil {
					errCh <- err
					cancel()
					continue
				}
				prog.inc()
			}
		}()
	}
	for _, rng := range ranges {
		jobs <- rng
	}
	close(jobs)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// chunkRanges splits a payload of total bytes into [off,end] (inclusive) blocks
// of at most size bytes; the final block is short. size <= 0 yields a single
// block; total <= 0 yields none.
func chunkRanges(total int64, size int64) [][2]int64 {
	if total <= 0 {
		return nil
	}
	if size <= 0 {
		return [][2]int64{{0, total - 1}}
	}
	ranges := make([][2]int64, 0, (total+size-1)/size)
	for off := int64(0); off < total; off += size {
		end := off + size - 1
		if end > total-1 {
			end = total - 1
		}
		ranges = append(ranges, [2]int64{off, end})
	}
	return ranges
}

// uploadChunk POSTs one WFP byte range to the scan endpoint, reading the block from src.
// The client-generated scanID is sent on every chunk via the X-Scan-Id request header.
//
// A 409 counts as success: it is what the server answers when it already holds the range,
// which is the normal outcome of a retry whose predecessor landed and whose response was
// lost to a timeout. The ranges this client sends are deterministic and never overlap, so
// a conflict cannot mean anything else. Treating it as a failure would report a scan as
// broken when its upload in fact completed — and the session it names is still resumable.
func (c *Client) uploadChunk(ctx context.Context, scanID string, src io.ReaderAt, off, end, total int64, query url.Values) error {
	block := func() *io.SectionReader { return io.NewSectionReader(src, off, end-off+1) }
	req, err := c.newRequest(http.MethodPost, serviceScan.endpoint, block())
	if err != nil {
		return err
	}
	if len(query) > 0 {
		req.URL.RawQuery = query.Encode()
	}
	// http.NewRequest wires ContentLength and body replay (GetBody) only for bytes and
	// strings readers. A SectionReader gets neither: without these, the send falls back
	// to chunked transfer-encoding and a retried chunk has no body to resend.
	req.ContentLength = end - off + 1
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(block()), nil }
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, end, total))
	req.Header.Set("X-Scan-Id", scanID)

	if _, err := c.do(ctx, req); err != nil {
		var statusErr *StatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusConflict {
			logging.Debug("chunk already accepted by the server",
				"scanID", scanID, "range", fmt.Sprintf("%d-%d/%d", off, end, total),
				"body", statusErr.Body)
			return nil
		}
		return fmt.Errorf("chunk %d-%d/%d: %w", off, end, total, err)
	}
	return nil
}

// chunkProgress reports upload progress in chunks.
//
// inc is safe for concurrent use, and deliberately does more than keep the counter
// intact: the increment and the report happen under one lock, so the reporter sees
// 1..total once each and in order, however the upload workers interleave. Counting
// atomically but reporting outside the lock would keep the counter correct and still
// deliver the values out of order — the report is what the caller sees.
type chunkProgress struct {
	mu    sync.Mutex
	r     ScanReporter
	done  int
	total int
}

func (p *chunkProgress) inc() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	if p.r != nil {
		p.r.Uploading(p.done, p.total)
	}
}

// Status performs a single status poll.
func (s scanService) Status(ctx context.Context, scanID string) (scanossapi.ScanEnvelope, error) {
	if scanID == "" {
		return scanossapi.ScanEnvelope{}, fmt.Errorf("no scan id")
	}
	body, err := s.c.get(ctx, serviceScan.endpoint+"/"+scanID, nil)
	if err != nil {
		return scanossapi.ScanEnvelope{}, err
	}
	return parseScanEnvelope(body)
}

// Wait polls scanID until it reaches a terminal state, then returns the envelope
// (with its Result populated). It honors ctx cancellation without cancelling the
// server-side scan. The poll cadence defaults to DefaultScanPollInterval and can
// be overridden with WithPollInterval.
//
// WithBOM applies here as it does to a full scan: resuming a scan by its id has to reach the
// same result the scan itself would have, or the settings a project keeps would depend on
// whether the run was interrupted.
func (s scanService) Wait(ctx context.Context, scanID string, opts ...ScanOption) (scanossapi.ScanEnvelope, error) {
	o := resolveScanOptions(opts)
	env, err := s.wait(ctx, scanID, o.pollInterval, o.reporter)
	if err != nil {
		return scanossapi.ScanEnvelope{}, err
	}
	s.applyBOM(env, o)
	return env, nil
}

// applyBOM runs the BOM rules over a finished envelope and hands the selection verdict to the
// caller's hook. Shared by the full scan flow and Wait, which is what keeps a resumed scan and a
// direct one producing the same result.
func (s scanService) applyBOM(env scanossapi.ScanEnvelope, o scanOptions) {
	// The ranking threshold is checked alongside the BOM: it is not a statement about any
	// component, so it applies with no settings file in sight.
	if env.Result == nil || (o.bom == nil && o.rankThreshold <= 0) {
		return
	}
	logging.Debug("post-processing scan result", "rankingThreshold", o.rankThreshold)
	report := postprocess.Apply(env.Result, o.bom, postprocess.WithRankingThreshold(o.rankThreshold))
	if o.onBOMReport != nil {
		o.onBOMReport(report)
	}
}

// DefaultScanPollInterval is the cadence for polling the scan status endpoint
// when the caller does not override it with WithPollInterval.
//
// The server reports progress per pass, and polling samples it rather than streaming it: at a
// slower cadence a whole pass can come and go between two polls, leaving a progress display
// frozen for stretches that look like a hang.
const DefaultScanPollInterval = 2 * time.Second

// scanPollInitial is the delay before the first status poll. It is clamped to the
// poll interval when a smaller interval is set (see scanService.wait).
const scanPollInitial = 1 * time.Second

// wait is the polling loop shared by the full scan flow and the public Wait. The
// first poll fires after scanPollInitial, clamped to interval so a sub-second
// cadence stays responsive.
func (s scanService) wait(ctx context.Context, scanID string, interval time.Duration, r ScanReporter) (scanossapi.ScanEnvelope, error) {
	if scanID == "" {
		return scanossapi.ScanEnvelope{}, fmt.Errorf("no scan id")
	}

	initial := scanPollInitial
	if interval < initial {
		initial = interval
	}
	select {
	case <-time.After(initial):
	case <-ctx.Done():
		return scanossapi.ScanEnvelope{}, ctx.Err()
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		e, err := s.Status(ctx, scanID)
		if err != nil {
			return scanossapi.ScanEnvelope{}, err
		}
		if r != nil {
			r.Scanning(e)
		}

		switch e.Status {
		case scanStateCompleted:
			return e, nil
		case scanStateFailed:
			return scanossapi.ScanEnvelope{}, fmt.Errorf("scan %s failed (phase %q)", e.ScanId, e.Phase)
		case scanStateExpired:
			// Terminal, and unlike failed the id cannot be retried: the session is gone. Without
			// this case an expired session falls through to the poll below and is polled until the
			// caller's context is cancelled — which for the CLI means hanging until Ctrl-C.
			return scanossapi.ScanEnvelope{}, fmt.Errorf("scan %s expired before it completed", e.ScanId)
		case scanStateQueued, scanStateUploading, scanStateScanning:
			// Still moving; wait for the next poll.
		default:
			// A state this client predates. Wait too rather than error: the alternative breaks
			// every existing client the moment the server names a new state.
			logging.Debug("scan reported an unrecognised state", "scanID", e.ScanId, "status", e.Status)
		}

		select {
		case <-ctx.Done():
			return scanossapi.ScanEnvelope{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
