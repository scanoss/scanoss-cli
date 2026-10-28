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

package snippetmatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// realCode is a block whose lines correspond to themselves: local == OSS over the same range is
// the clearest "real" match.
const realCode = `func Sum(xs []int) int {
	total := 0
	for _, x := range xs {
		total += x
	}
	if total < 0 {
		panic("negative total")
	}
	return total
}
`

// unrelatedLocal / unrelatedOSS share no informative line: a wrong candidate assignment.
const unrelatedLocal = `func handler(w http.ResponseWriter, r *http.Request) {
	user := loadUser(r)
	if user == nil {
		http.Error(w, "forbidden", 403)
		return
	}
	render(w, user.Profile)
}
`

const unrelatedOSS = `def parse_config(path):
    with open(path) as fh:
        data = yaml.safe_load(fh)
    validate(data)
    return Config(**data)
`

// fakeFetcher serves OSS content from a map and counts calls per hash.
type fakeFetcher struct {
	mu      sync.Mutex
	content map[string][]byte
	calls   map[string]int
	err     error // when set, every File call fails
}

func (f *fakeFetcher) File(_ context.Context, hash string, _, _ int) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[hash]++
	if f.err != nil {
		return nil, f.err
	}
	c, ok := f.content[hash]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}

func (f *fakeFetcher) callCount(hash string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[hash]
}

// writeLocal writes name under root with the given content and returns name (relative), as it
// would appear in a scan result.
func writeLocal(t *testing.T, root, name, content string) string {
	t.Helper()
	full := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// snippetEvidence builds one snippet FileEvidence covering the whole [1,lines] range on both sides.
func snippetEvidence(path, hash string, lines int) sbom.FileEvidence {
	return sbom.FileEvidence{
		Path:            path,
		FileHash:        hash,
		MatchType:       "snippet",
		InputLineRanges: []sbom.LineRange{{StartLine: 1, EndLine: lines}},
		OssLineRanges:   []sbom.LineRange{{StartLine: 1, EndLine: lines}},
	}
}

func invWith(evs ...sbom.FileEvidence) *sbom.Inventory {
	return &sbom.Inventory{Components: []sbom.Component{{Purl: "pkg:x/y", Evidence: evs}}}
}

func TestAnnotateIdenticalIsReal(t *testing.T) {
	root := t.TempDir()
	path := writeLocal(t, root, "sum.go", realCode)
	f := &fakeFetcher{content: map[string][]byte{"h1": []byte(realCode)}}
	inv := invWith(snippetEvidence(path, "h1", 10))

	a, err := New(Options{Fetcher: f, ScanRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Annotate(context.Background(), inv); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	got := inv.Components[0].Evidence[0].SnippetClassification
	if got == nil {
		t.Fatal("no classification set")
	}
	if got.Verdict != "real" {
		t.Fatalf("verdict = %q (p=%.3f), want real", got.Verdict, got.Probability)
	}
	if got.ModelVersion == "" {
		t.Error("model version not recorded")
	}
}

func TestAnnotateUnrelatedIsFalsePositive(t *testing.T) {
	root := t.TempDir()
	path := writeLocal(t, root, "handler.go", unrelatedLocal)
	f := &fakeFetcher{content: map[string][]byte{"h1": []byte(unrelatedOSS)}}
	inv := invWith(snippetEvidence(path, "h1", 8))

	a, _ := New(Options{Fetcher: f, ScanRoot: root})
	if _, err := a.Annotate(context.Background(), inv); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	got := inv.Components[0].Evidence[0].SnippetClassification
	if got == nil || got.Verdict != "false_positive" {
		t.Fatalf("classification = %+v, want false_positive", got)
	}
}

func TestOSSFetchIsDedupedByHash(t *testing.T) {
	root := t.TempDir()
	p1 := writeLocal(t, root, "a.go", realCode)
	p2 := writeLocal(t, root, "b.go", realCode)
	f := &fakeFetcher{content: map[string][]byte{"shared": []byte(realCode)}}
	// Two matches in two files against the same OSS file hash.
	inv := invWith(snippetEvidence(p1, "shared", 10), snippetEvidence(p2, "shared", 10))

	a, _ := New(Options{Fetcher: f, ScanRoot: root})
	if _, err := a.Annotate(context.Background(), inv); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if n := f.callCount("shared"); n != 1 {
		t.Fatalf("OSS hash fetched %d times, want 1 (cache by hash)", n)
	}
	for i, ev := range inv.Components[0].Evidence {
		if ev.SnippetClassification == nil {
			t.Errorf("evidence %d not classified", i)
		}
	}
}

func TestMissingLocalFileIsSkipped(t *testing.T) {
	root := t.TempDir()
	f := &fakeFetcher{content: map[string][]byte{"h1": []byte(realCode)}}
	// No file written for "ghost.go".
	inv := invWith(snippetEvidence("ghost.go", "h1", 10))

	a, _ := New(Options{Fetcher: f, ScanRoot: root})
	_, err := a.Annotate(context.Background(), inv)
	if err == nil {
		t.Fatal("want an error naming the skipped match")
	}
	if inv.Components[0].Evidence[0].SnippetClassification != nil {
		t.Fatal("unreadable local file must not be annotated")
	}
}

func TestFetchErrorIsNonFatalAndSkips(t *testing.T) {
	root := t.TempDir()
	path := writeLocal(t, root, "sum.go", realCode)
	f := &fakeFetcher{err: errors.New("boom")}
	inv := invWith(snippetEvidence(path, "h1", 10))

	a, _ := New(Options{Fetcher: f, ScanRoot: root})
	if _, err := a.Annotate(context.Background(), inv); err == nil {
		t.Fatal("want an error when OSS content cannot be fetched")
	}
	if inv.Components[0].Evidence[0].SnippetClassification != nil {
		t.Fatal("a match with no OSS content must not be annotated")
	}
}

func TestNonSnippetEvidenceIsIgnored(t *testing.T) {
	root := t.TempDir()
	var fetched atomic.Int32
	f := &countingFetcher{onCall: func() { fetched.Add(1) }}
	inv := invWith(
		sbom.FileEvidence{Path: "whole.go", FileHash: "h1", MatchType: "file"},
		sbom.FileEvidence{Path: "pkg.json", MatchType: "declared"},
	)

	a, _ := New(Options{Fetcher: f, ScanRoot: root})
	if _, err := a.Annotate(context.Background(), inv); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if n := fetched.Load(); n != 0 {
		t.Fatalf("fetched %d OSS files for non-snippet evidence, want 0", n)
	}
	for _, ev := range inv.Components[0].Evidence {
		if ev.SnippetClassification != nil {
			t.Error("non-snippet evidence must not be classified")
		}
	}
}

func TestNoSnippetsMakesNoFetch(t *testing.T) {
	var fetched atomic.Int32
	f := &countingFetcher{onCall: func() { fetched.Add(1) }}
	inv := invWith() // no evidence at all
	a, _ := New(Options{Fetcher: f, ScanRoot: t.TempDir()})
	if _, err := a.Annotate(context.Background(), inv); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if fetched.Load() != 0 {
		t.Fatal("empty inventory must trigger no fetch")
	}
}

// The summary counts every snippet match in the inventory, scorable or not, so a match that
// was never attempted still shows up as unscored.
func TestAnnotateSummaryCounts(t *testing.T) {
	root := t.TempDir()
	realPath := writeLocal(t, root, "sum.go", realCode)
	fpPath := writeLocal(t, root, "handler.go", unrelatedLocal)
	f := &fakeFetcher{content: map[string][]byte{"real": []byte(realCode), "fp": []byte(unrelatedOSS)}}
	noHash := snippetEvidence(realPath, "", 10)
	inv := invWith(
		snippetEvidence(realPath, "real", 10),
		snippetEvidence(fpPath, "fp", 8),
		snippetEvidence("ghost.go", "real", 10), // local file missing
		noHash,                                  // nothing to fetch
		sbom.FileEvidence{Path: "whole.go", FileHash: "real", MatchType: "file"},
	)

	a, _ := New(Options{Fetcher: f, ScanRoot: root, Threshold: 0.6})
	sum, err := a.Annotate(context.Background(), inv)
	if err == nil {
		t.Error("want an error naming the unscored matches")
	}
	want := Summary{ModelVersion: a.ModelVersion(), Threshold: 0.6, Matches: 4, Scored: 2, FalsePositives: 1}
	if sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
}

func TestNewRequiresFetcher(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New must reject a nil Fetcher")
	}
}

type countingFetcher struct{ onCall func() }

func (c *countingFetcher) File(_ context.Context, _ string, _, _ int) ([]byte, error) {
	c.onCall()
	return []byte("x"), nil
}
