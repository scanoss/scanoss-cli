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

package aiusage

import (
	"testing"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// A finding is reachable from a framework route or from top-level code, and unreachable in a
// function nothing calls.
func TestScanReachability(t *testing.T) {
	report, err := Scan("testdata/webapp", Options{RulesDir: "testdata/rules", Reachability: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Reachability != "enabled" {
		t.Fatalf("reachability = %q, want enabled", report.Reachability)
	}
	want := map[int]struct {
		status string
		entry  *sbom.AIEntryPoint
	}{
		8:  {sbom.AIReachable, &sbom.AIEntryPoint{File: "app.py", Line: 12, Kind: "framework_entry"}},
		17: {sbom.AIUnreachable, nil},
		20: {sbom.AIReachable, &sbom.AIEntryPoint{File: "app.py", Line: 1, Kind: "module"}},
	}
	if len(report.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(report.Findings), len(want), report.Findings)
	}
	for _, f := range report.Findings {
		w, ok := want[f.Line]
		if !ok {
			t.Fatalf("unexpected finding at line %d", f.Line)
		}
		if f.Reachability != w.status || (w.entry == nil) != (f.EntryPoint == nil) || (w.entry != nil && *w.entry != *f.EntryPoint) {
			t.Errorf("line %d: %s %+v, want %s %+v", f.Line, f.Reachability, f.EntryPoint, w.status, w.entry)
		}
	}
}

// Without reachability every finding is unknown.
func TestScanWithoutReachability(t *testing.T) {
	report, err := Scan("testdata/webapp", Options{RulesDir: "testdata/rules"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.Reachability != sbom.AIUnknown || f.EntryPoint != nil {
			t.Fatalf("line %d: %s %+v, want unknown", f.Line, f.Reachability, f.EntryPoint)
		}
	}
}
