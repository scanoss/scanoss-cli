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
	"reflect"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// A rule reports the call it matches, with its typed metadata, and not the call its card excludes.
func TestScanReportsTypedFindings(t *testing.T) {
	report, err := Scan("testdata/project", Options{RulesDir: "testdata/rules"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Format != sbom.AIUsageFormat || report.Reachability != "disabled" {
		t.Fatalf("report header = %q, %q", report.Format, report.Reachability)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(report.Findings), report.Findings)
	}
	f := report.Findings[0]
	if f.RuleID != "ai.test.acme-load-unsafe" || f.File != "app.py" || f.Line != 5 || f.Category != "model_load" || f.Tier != "open" {
		t.Fatalf("finding = %+v", f)
	}
	meta, _ := f.Metadata[MetadataKey].(map[string]any)
	if !reflect.DeepEqual(meta["cwe"], []any{"CWE-502"}) || meta["pinned"] != false || meta["risk"] != "high" {
		t.Fatalf("metadata = %#v, want typed cwe list and boolean", meta)
	}
	want := sbom.AIUsageSummary{Findings: 1, ByCategory: map[string]int{"model_load": 1}, ByRisk: map[string]int{"high": 1}}
	if !reflect.DeepEqual(report.Summary, want) {
		t.Fatalf("summary = %+v, want %+v", report.Summary, want)
	}
}

func TestScanRejectsUnknownLanguage(t *testing.T) {
	if _, err := Scan("testdata/project", Options{RulesDir: "testdata/rules", Languages: []string{"cobol"}}); err == nil {
		t.Fatal("want an error for an unsupported language")
	}
}

// A language without cards scans nothing rather than failing.
func TestScanSkipsLanguagesWithoutCards(t *testing.T) {
	report, err := Scan("testdata/project", Options{RulesDir: "testdata/rules", Languages: []string{"typescript"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("got %d findings, want none", len(report.Findings))
	}
}
