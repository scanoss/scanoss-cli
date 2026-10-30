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
	"slices"
	"strings"
	"testing"
)

func scored(verdict string, p float64) *SnippetClassification {
	return &SnippetClassification{Verdict: verdict, Probability: p, ModelVersion: "lr-test"}
}

func snippetAt(path string, c *SnippetClassification) FileEvidence {
	return FileEvidence{
		Path: path, MatchType: "snippet", SnippetClassification: c,
		InputLineRanges: []LineRange{{StartLine: 1, EndLine: 9}}, OssLineRanges: []LineRange{{StartLine: 1, EndLine: 9}},
	}
}

// filterInventory has one component of each kind the filter must tell apart.
func filterInventory() Inventory {
	return Inventory{
		Components: []Component{
			// Only false-positive snippets: removed whole.
			{Purl: "pkg:github/acme/gone", Version: "1.0.0", Evidence: []FileEvidence{
				snippetAt("src/a.c", scored(VerdictFalsePositive, 0.91)),
				snippetAt("src/b.c", scored(VerdictFalsePositive, 0.80)),
			}},
			// A file match, a real snippet, an unscored snippet and a false positive: only the last goes.
			{Purl: "pkg:github/acme/mixed", Version: "2.0.0", Evidence: []FileEvidence{
				{Path: "src/whole.c", MatchType: "file"},
				snippetAt("src/real.c", scored("real", 0.10)),
				snippetAt("src/unscored.c", nil),
				snippetAt("src/fp.c", scored(VerdictFalsePositive, 0.95)),
			}},
			// A false positive a bom.identify rule claimed: a person confirmed it, so it stays.
			{Purl: "pkg:github/acme/identified", Identified: true, Evidence: []FileEvidence{
				func() FileEvidence {
					e := snippetAt("src/claimed.c", scored(VerdictFalsePositive, 0.99))
					e.Identified = true
					return e
				}(),
			}},
			// Declared in a manifest and also matched by a false-positive snippet: the graph names
			// it, and its declared evidence keeps it.
			{Purl: "pkg:npm/left-pad", Version: "1.3.0", Evidence: []FileEvidence{
				{Path: "package.json", MatchType: "declared"},
				snippetAt("vendor/left-pad.js", scored(VerdictFalsePositive, 0.90)),
			}},
		},
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-GONE", Purls: []string{"pkg:github/acme/gone@1.0.0"}},
			{ID: "CVE-GONE-BARE", Purls: []string{"pkg:github/acme/gone"}},
			{ID: "CVE-BOTH", Purls: []string{"pkg:github/acme/gone", "pkg:github/acme/mixed"}},
			{ID: "CVE-LEFTPAD", Purls: []string{"pkg:npm/left-pad"}},
			{ID: "CVE-ELSEWHERE", Purls: []string{"pkg:npm/not-in-inventory"}},
		},
		Dependencies: []DependencyRoot{{
			Manifest: "package.json", Lockfile: "package-lock.json", Ecosystem: "npm", Status: GraphComplete,
			Direct: []string{"pkg:npm/left-pad@1.3.0"},
		}},
	}
}

func pathsOf(c *Component) []string {
	var out []string
	for _, e := range c.Evidence {
		out = append(out, e.Path)
	}
	return out
}

func findByPurl(inv Inventory, purl string) *Component {
	for i := range inv.Components {
		if inv.Components[i].Purl == purl {
			return &inv.Components[i]
		}
	}
	return nil
}

func TestRemoveFalsePositiveSnippets(t *testing.T) {
	inv := filterInventory()
	if got := inv.RemoveFalsePositiveSnippets(); got != 4 {
		t.Errorf("removed = %d, want 4 (gone x2, mixed x1, left-pad x1)", got)
	}

	if findByPurl(inv, "pkg:github/acme/gone") != nil {
		t.Error("a component left with no evidence must be removed")
	}
	mixed := findByPurl(inv, "pkg:github/acme/mixed")
	if mixed == nil {
		t.Fatal("mixed was removed; it still has evidence")
	}
	if got, want := pathsOf(mixed), []string{"src/whole.c", "src/real.c", "src/unscored.c"}; !slices.Equal(got, want) {
		t.Errorf("mixed evidence = %v, want %v: file matches, real and unscored snippets stay", got, want)
	}
	if c := findByPurl(inv, "pkg:github/acme/identified"); c == nil || len(c.Evidence) != 1 {
		t.Errorf("identified = %+v, want its claimed snippet kept", c)
	}
	leftPad := findByPurl(inv, "pkg:npm/left-pad")
	if leftPad == nil {
		t.Fatal("left-pad was removed; its declared evidence stays")
	}
	if got := pathsOf(leftPad); !slices.Equal(got, []string{"package.json"}) {
		t.Errorf("left-pad evidence = %v, want only the manifest", got)
	}
	if got := inv.DirectMembers(inv.Dependencies[0]); !slices.Equal(got, []string{"pkg:npm/left-pad@1.3.0"}) {
		t.Errorf("graph direct members = %v, want left-pad still resolved", got)
	}

	var ids []string
	for _, v := range inv.Vulnerabilities {
		ids = append(ids, v.ID)
		if v.ID == "CVE-BOTH" && !slices.Equal(v.Purls, []string{"pkg:github/acme/mixed"}) {
			t.Errorf("CVE-BOTH purls = %v, want only the surviving component", v.Purls)
		}
	}
	if want := []string{"CVE-BOTH", "CVE-LEFTPAD", "CVE-ELSEWHERE"}; !slices.Equal(ids, want) {
		t.Errorf("vulnerabilities = %v, want %v: an advisory naming only removed components goes, others stay", ids, want)
	}
}

// A removed component must leave no trace in any rendered format: no component, no advisory
// pointing at it, no dependency edge.
func TestRemoveFalsePositiveSnippetsLeavesNoDanglingReference(t *testing.T) {
	inv := filterInventory()
	inv.RemoveFalsePositiveSnippets()

	raw, err := NewRawDocument(inv, RawMetadata{}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cyclonedx, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	spdx, err := Generate(inv, FormatSPDX)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"raw": raw, "cyclonedx": cyclonedx, "spdx": spdx} {
		if strings.Contains(out, "acme/gone") {
			t.Errorf("%s output still names the removed component", name)
		}
		if !strings.Contains(out, "acme/mixed") {
			t.Errorf("%s output lost a component that kept evidence", name)
		}
	}

	bom := decodeBOM(t, cyclonedx)
	for _, v := range *bom.Vulnerabilities {
		if v.ID == "CVE-ELSEWHERE" {
			continue // never resolved to a component; not the filter's to judge
		}
		if v.Affects == nil || len(*v.Affects) == 0 {
			t.Errorf("CycloneDX vulnerability %s affects nothing", v.ID)
		}
	}
}

func TestRemoveFalsePositiveSnippetsWithNothingToRemove(t *testing.T) {
	inv := Inventory{Components: []Component{
		{Purl: "pkg:x/a", Evidence: []FileEvidence{snippetAt("a.c", scored("real", 0.2)), snippetAt("b.c", nil)}},
		{Purl: "pkg:x/no-evidence"},
	}}
	if got := inv.RemoveFalsePositiveSnippets(); got != 0 {
		t.Errorf("removed = %d, want 0", got)
	}
	if len(inv.Components) != 2 || len(inv.Components[0].Evidence) != 2 {
		t.Errorf("inventory changed: %+v", inv.Components)
	}
}

// CycloneDX occurrences have no properties, so a scored snippet carries its verdict in
// additionalContext, after the ranges.
func TestCycloneDXOccurrenceCarriesClassification(t *testing.T) {
	ev := snippetAt("src/b.c", &SnippetClassification{Verdict: VerdictFalsePositive, Probability: 0.9132, ModelVersion: "lr-d51f2e100211"})
	ev.InputLineRanges = []LineRange{{StartLine: 12, EndLine: 48}}
	ev.OssLineRanges = []LineRange{{StartLine: 100, EndLine: 136}}
	unscored := snippetAt("src/c.c", nil)
	inv := Inventory{Components: []Component{{Purl: "pkg:x/y", Version: "1", Evidence: []FileEvidence{ev, unscored}}}}

	out, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	occ := *(*decodeBOM(t, out).Components)[0].Evidence.Occurrences
	if got, want := occ[0].AdditionalContext, "input lines 12-48; oss lines 100-136; classifier false_positive p=0.91 model=lr-d51f2e100211"; got != want {
		t.Errorf("scored additionalContext = %q, want %q", got, want)
	}
	if got, want := occ[1].AdditionalContext, "input lines 1-9; oss lines 1-9"; got != want {
		t.Errorf("unscored additionalContext = %q, want %q", got, want)
	}
}
