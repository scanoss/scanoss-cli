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

package sbom

import (
	"reflect"
	"strings"
	"testing"
)

// TestRawDocument_LineRangesRoundTrip pins the wire shape of matched line ranges: objects
// carrying start_line/end_line, never "start-end" text, and unchanged by a marshal/parse cycle.
func TestRawDocument_LineRangesRoundTrip(t *testing.T) {
	input := []LineRange{{StartLine: 82, EndLine: 209}, {StartLine: 303, EndLine: 775}}
	oss := []LineRange{{StartLine: 77, EndLine: 204}, {StartLine: 298, EndLine: 770}}
	inv := Inventory{Components: []Component{{
		Purl:    "pkg:github/scanoss/engine",
		Version: "5.4.1",
		URLHash: "abc123",
		Evidence: []FileEvidence{{
			Path:            "deflate_modified.c",
			MatchType:       "snippet",
			InputLineRanges: input,
			OssLineRanges:   oss,
		}},
	}}}

	out, err := NewRawDocument(inv, RawMetadata{Tool: "scanoss"}).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(out, `"start_line": 82`) || !strings.Contains(out, `"end_line": 209`) {
		t.Errorf("raw document should carry structured ranges, got:\n%s", out)
	}
	if strings.Contains(out, `"82-209"`) {
		t.Errorf("raw document should not encode ranges as text, got:\n%s", out)
	}
	if !strings.Contains(out, `"schema_version": "`+RawSchemaVersion+`"`) {
		t.Errorf("raw document should be stamped %s, got:\n%s", RawSchemaVersion, out)
	}

	got, err := ParseRaw([]byte(out))
	if err != nil {
		t.Fatalf("ParseRaw: %v", err)
	}
	if len(got.Components) != 1 || len(got.Components[0].Evidence) != 1 {
		t.Fatalf("want 1 component with 1 evidence, got %+v", got.Components)
	}
	ev := got.Components[0].Evidence[0]
	if !reflect.DeepEqual(ev.InputLineRanges, input) {
		t.Errorf("input ranges = %+v, want %+v", ev.InputLineRanges, input)
	}
	if !reflect.DeepEqual(ev.OssLineRanges, oss) {
		t.Errorf("oss ranges = %+v, want %+v", ev.OssLineRanges, oss)
	}
}

// TestRawDocument_Server pins the server block's wire shape and placement, and that it is omitted
// when absent — the guarantee that a report without a `server` block leaves the output unchanged.
func TestRawDocument_Server(t *testing.T) {
	inv := Inventory{Components: []Component{{Purl: "pkg:github/scanoss/engine", Version: "5.4.1"}}}

	doc := NewRawDocument(inv, RawMetadata{Tool: "scanoss"})
	doc.Server = &RawServer{
		EngineVersion:       "6.0.1-crc64",
		KnowledgeBase:       &RawKnowledgeBase{MonthlyVersion: "26.04", DailyVersion: "25.03.19"},
		KnowledgeBaseLatest: &RawKnowledgeBase{MonthlyVersion: "26.05"},
	}
	out, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{
		`"engine_version": "6.0.1-crc64"`,
		`"knowledge_base": {`,
		`"monthly_version": "26.04"`,
		`"daily_version": "25.03.19"`,
		`"knowledge_base_latest": {`,
		`"monthly_version": "26.05"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("server output should carry %s, got:\n%s", want, out)
		}
	}
	// server sits between metadata and the promoted components, mirroring the batch report.
	if mi, si, ci := strings.Index(out, `"metadata"`), strings.Index(out, `"server"`), strings.Index(out, `"components"`); !(mi < si && si < ci) {
		t.Errorf("server should sit between metadata and components (metadata=%d server=%d components=%d):\n%s", mi, si, ci, out)
	}

	// Absent server → the key is omitted entirely.
	bare, err := NewRawDocument(inv, RawMetadata{Tool: "scanoss"}).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(bare, `"server"`) {
		t.Errorf("a document with no server must omit the key, got:\n%s", bare)
	}
}

// A scan that matched nothing emits an empty list, not null. A nil slice
// marshals to null, which forces every consumer to special-case the field
// before ranging over it — and strict JSON-schema validators reject it.
func TestRawDocumentEmptyComponentsIsList(t *testing.T) {
	out, err := NewRawDocument(Inventory{}, RawMetadata{Tool: "t", ToolVersion: "1"}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"components": null`) {
		t.Errorf("components must be [] when there are none, got:\n%s", out)
	}
	if !strings.Contains(out, `"components": []`) {
		t.Errorf("expected an empty list, got:\n%s", out)
	}

	// And it round-trips: parsing it back yields an inventory with no components
	// rather than an error.
	inv, err := ParseRaw([]byte(out))
	if err != nil {
		t.Fatalf("ParseRaw on an empty document: %v", err)
	}
	if len(inv.Components) != 0 {
		t.Errorf("expected no components, got %d", len(inv.Components))
	}
}
