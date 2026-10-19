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
	"fmt"
	"slices"
	"testing"
)

// The SBOM name field must hold a package name, not a PURL. Detected components
// carry one from the scan result; declared ones (sourced from a manifest) carry
// only a PURL, so the last segment stands in — otherwise every declared package
// in an SBOM would be named "pkg:golang/github.com/spf13/cobra".
func TestComponentDisplayName(t *testing.T) {
	for _, tc := range []struct {
		name string
		comp Component
		want string
	}{
		{"detected keeps its name", Component{Purl: "pkg:github/madler/zlib", Name: "zlib"}, "zlib"},
		{"declared falls back to the purl tail", Component{Purl: "pkg:golang/github.com/spf13/cobra"}, "cobra"},
		{"short purl", Component{Purl: "pkg:npm/lodash"}, "lodash"},
		{"maven namespace", Component{Purl: "pkg:maven/org.apache.commons/commons-lang3"}, "commons-lang3"},
		{"no slash at all", Component{Purl: "weird"}, "weird"},
		{"trailing slash falls back to the whole purl", Component{Purl: "pkg:npm/"}, "pkg:npm/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.comp.DisplayName(); got != tc.want {
				t.Errorf("DisplayName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Add collapses duplicate identities (PURL+version) into one — so SBOM ids stay unique — while
// keeping distinct versions of the same PURL, and a detected/declared overlap merges into a
// single detected component that combines the file-match and manifest evidence.
func TestInventoryAdd(t *testing.T) {
	var inv Inventory
	inv.Add(
		Component{Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: ScopeDetected, Evidence: []FileEvidence{{Path: "a.js", MatchType: "file"}}},
		Component{Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: ScopeDeclared, Evidence: []FileEvidence{{Path: "package.json", MatchType: "declared"}}}, // dup of the above
		Component{Purl: "pkg:npm/abort-controller", Version: "3.0.0", Scope: ScopeDeclared, Evidence: []FileEvidence{{Path: "package.json", MatchType: "declared"}}},
		Component{Purl: "pkg:npm/abort-controller", Version: "3.0.0", Scope: ScopeDeclared, Evidence: []FileEvidence{{Path: "package-lock.json", MatchType: "declared"}}}, // exact dup — evidence merged
		Component{Purl: "pkg:npm/tar", Version: "6.2.0", Scope: ScopeDeclared},
		Component{Purl: "pkg:npm/tar", Version: "7.5.7", Scope: ScopeDeclared}, // same purl, different version — kept
	)

	if len(inv.Components) != 4 {
		t.Fatalf("got %d components, want 4: %+v", len(inv.Components), inv.Components)
	}

	// lodash: detected wins, and the file-match + manifest evidence are combined.
	lodash := inv.Components[0]
	if lodash.Scope != ScopeDetected || len(lodash.Evidence) != 2 {
		t.Errorf("lodash merge wrong (want detected with 2 evidences): %+v", lodash)
	}

	// tar keeps both versions.
	var tarVersions []string
	for _, c := range inv.Components {
		if c.Purl == "pkg:npm/tar" {
			tarVersions = append(tarVersions, c.Version)
		}
	}
	if len(tarVersions) != 2 {
		t.Errorf("tar should keep both versions, got %v", tarVersions)
	}

	// every (purl,version) is unique.
	seen := map[string]bool{}
	for _, c := range inv.Components {
		k := c.Purl + "@" + c.Version
		if seen[k] {
			t.Errorf("duplicate identity survived: %s", k)
		}
		seen[k] = true
	}
}

// The zero Scope means detected, as the field documents, so it must win over declared on a merge
// too. An inventory parsed from an external SBOM carries no scope, and merging declared
// dependencies into it used to leave the result labelled declared.
func TestInventoryAddTreatsEmptyScopeAsDetected(t *testing.T) {
	for name, tc := range map[string]struct{ first, second ComponentScope }{
		"empty then declared": {"", ScopeDeclared},
		"declared then empty": {ScopeDeclared, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var inv Inventory
			inv.Add(Component{Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: tc.first})
			inv.Add(Component{Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: tc.second})

			if len(inv.Components) != 1 {
				t.Fatalf("got %d components, want 1", len(inv.Components))
			}
			if inv.Components[0].IsDeclared() {
				t.Errorf("scope = %q, want detected to win", inv.Components[0].Scope)
			}
		})
	}
}

// Detected wins over declared as a whole: when a detected component folds into a declared
// entry, its metadata comes along — a component labelled detected must not carry the declared
// entry's empty name/vendor/url/licenses. The CLI pipeline always adds detected first, so this
// protects external Add callers building in the other order.
func TestInventoryAddDeclaredThenDetectedKeepsDetectedMetadata(t *testing.T) {
	detected := Component{
		Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: ScopeDetected,
		Name: "lodash", Vendor: "lodash", URL: "https://github.com/lodash/lodash",
		Rank: 1, Licenses: []License{{ID: "MIT"}},
		Evidence: []FileEvidence{{Path: "src/clone.js", MatchType: "snippet"}},
	}
	declared := Component{
		Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: ScopeDeclared,
		Evidence: []FileEvidence{{Path: "package.json", MatchType: "declared"}},
	}

	for name, order := range map[string][]Component{
		"declared first": {declared, detected},
		"detected first": {detected, declared},
	} {
		t.Run(name, func(t *testing.T) {
			var inv Inventory
			inv.Add(order[0])
			inv.Add(order[1])

			if len(inv.Components) != 1 {
				t.Fatalf("got %d components, want 1", len(inv.Components))
			}
			c := inv.Components[0]
			if c.Scope != ScopeDetected {
				t.Errorf("scope = %q, want detected", c.Scope)
			}
			if c.Name != "lodash" || c.Vendor != "lodash" || c.URL != detected.URL || c.Rank != 1 {
				t.Errorf("detected metadata lost on merge: %+v", c)
			}
			if len(c.Licenses) != 1 || c.Licenses[0].ID != "MIT" {
				t.Errorf("licenses lost on merge: %+v", c.Licenses)
			}
			if len(c.Evidence) != 2 {
				t.Errorf("evidence from both origins must survive, got %+v", c.Evidence)
			}
		})
	}
}

// BenchmarkInventoryAdd measures the merge path: half the components are declared
// entries whose identity is then re-added as a detected component with metadata and
// evidence, so every declared entry goes through the declared→detected fold.
func BenchmarkInventoryAdd(b *testing.B) {
	const n = 1000
	declared := make([]Component, n)
	detected := make([]Component, n)
	for i := range n {
		purl := fmt.Sprintf("pkg:npm/component-%d", i)
		declared[i] = Component{
			Purl: purl, Version: "1.0.0", Scope: ScopeDeclared,
			Evidence: []FileEvidence{{Path: "package.json", MatchType: "declared"}},
		}
		detected[i] = Component{
			Purl: purl, Version: "1.0.0", Scope: ScopeDetected,
			Name: fmt.Sprintf("component-%d", i), Vendor: "vendor", Rank: 1,
			URL: "https://example.com", Licenses: []License{{ID: "MIT"}},
			Evidence: []FileEvidence{{Path: fmt.Sprintf("src/file-%d.js", i), MatchType: "file"}},
		}
	}

	b.ReportAllocs()
	for b.Loop() {
		var inv Inventory
		inv.Add(declared...)
		inv.Add(detected...)
		if len(inv.Components) != n {
			b.Fatalf("got %d components, want %d", len(inv.Components), n)
		}
	}
}

// Appending to Components directly still works: Add is how the inventory keeps one entry per
// component, not a gate on building one.
func TestInventoryAddAfterDirectAppend(t *testing.T) {
	inv := Inventory{Components: []Component{{Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: ScopeDeclared}}}
	inv.Add(Component{Purl: "pkg:npm/lodash", Version: "4.17.21", Scope: ScopeDetected})

	if len(inv.Components) != 1 {
		t.Fatalf("got %d components, want the appended one folded in: %+v", len(inv.Components), inv.Components)
	}
	if inv.Components[0].Scope != ScopeDetected {
		t.Errorf("scope = %q, want detected", inv.Components[0].Scope)
	}
}

// Add must not keep the caller's evidence array. A Component's Evidence is a slice, so storing
// it as given leaves the inventory and the caller sharing memory: appending to it later writes
// into the caller's array, and two inventories seeded from one Component value overwrite each
// other's occurrences.
func TestInventoryAddDoesNotAliasCallerEvidence(t *testing.T) {
	t.Run("two inventories from one component", func(t *testing.T) {
		// Spare capacity is what makes append reuse the array rather than allocate.
		shared := make([]FileEvidence, 1, 8)
		shared[0] = FileEvidence{Path: "shared.c", MatchType: "file"}
		base := Component{Purl: "pkg:x/y", Version: "1", Evidence: shared}

		var invA, invB Inventory
		invA.Add(base)
		invB.Add(base)
		invA.Add(Component{Purl: "pkg:x/y", Version: "1", Evidence: []FileEvidence{{Path: "only-in-A", MatchType: "file"}}})
		invB.Add(Component{Purl: "pkg:x/y", Version: "1", Evidence: []FileEvidence{{Path: "only-in-B", MatchType: "file"}}})

		if got := evidencePaths(invA); !slices.Equal(got, []string{"shared.c", "only-in-A"}) {
			t.Errorf("inventory A = %v, want its own occurrence", got)
		}
		if got := evidencePaths(invB); !slices.Equal(got, []string{"shared.c", "only-in-B"}) {
			t.Errorf("inventory B = %v, want its own occurrence", got)
		}
		if shared[0].Path != "shared.c" || len(shared) != 1 {
			t.Errorf("the caller's slice was written through: %+v", shared)
		}
	})

	t.Run("caller mutates its slice afterwards", func(t *testing.T) {
		ev := []FileEvidence{{Path: "original.c", MatchType: "file"}}
		var inv Inventory
		inv.Add(Component{Purl: "pkg:x/y", Version: "1", Evidence: ev})

		ev[0].Path = "changed by the caller"

		if got := inv.Components[0].Evidence[0].Path; got != "original.c" {
			t.Errorf("evidence path = %q, want the inventory to hold its own copy", got)
		}
	})
}

// evidencePaths lists the occurrence paths of an inventory's first component.
func evidencePaths(inv Inventory) []string {
	out := make([]string, 0, len(inv.Components[0].Evidence))
	for _, e := range inv.Components[0].Evidence {
		out = append(out, e.Path)
	}
	return out
}

// Identified is a statement about the component, not about one origin's view of it: whichever
// side of a merge carries it, the folded component keeps it.
func TestAddPreservesIdentifiedAcrossMerge(t *testing.T) {
	cases := []struct {
		name  string
		first Component
		next  Component
	}{
		{
			"detected identified, then declared",
			Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDetected, Identified: true},
			Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDeclared},
		},
		{
			// The declared-then-detected path replaces the component wholesale; the flag must
			// survive that too.
			"declared identified, then detected",
			Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDeclared, Identified: true},
			Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDetected},
		},
		{
			"declared, then detected identified",
			Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDeclared},
			Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDetected, Identified: true},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var inv Inventory
			inv.Add(tt.first)
			inv.Add(tt.next)

			if len(inv.Components) != 1 {
				t.Fatalf("got %d components, want them folded into 1", len(inv.Components))
			}
			if !inv.Components[0].Identified {
				t.Error("the folded component lost its identified flag")
			}
		})
	}
}

// Nothing invents the flag: two unidentified components fold into an unidentified one.
func TestAddDoesNotInventIdentified(t *testing.T) {
	var inv Inventory
	inv.Add(Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDeclared})
	inv.Add(Component{Purl: "pkg:npm/vue", Version: "2.6.14", Scope: ScopeDetected})

	if inv.Components[0].Identified {
		t.Error("component marked identified when neither side was")
	}
}

// Merging two entries for one path drops the duplicate but must not drop its claim: the file was
// either declared present or it was not, whichever origin said so.
func TestAddEvidencePreservesIdentifiedOnDuplicates(t *testing.T) {
	cases := []struct{ first, second bool }{{true, false}, {false, true}, {true, true}}
	for _, tt := range cases {
		var inv Inventory
		inv.Add(Component{Purl: "pkg:npm/vue", Version: "1.0.0", Evidence: []FileEvidence{
			{Path: "src/a.js", MatchType: "file", Identified: tt.first},
		}})
		inv.Add(Component{Purl: "pkg:npm/vue", Version: "1.0.0", Evidence: []FileEvidence{
			{Path: "src/a.js", MatchType: "file", Identified: tt.second},
		}})

		if n := len(inv.Components[0].Evidence); n != 1 {
			t.Fatalf("got %d evidence entries, want them folded into 1", n)
		}
		if !inv.Components[0].Evidence[0].Identified {
			t.Errorf("(%v, %v): the folded evidence lost its identified flag", tt.first, tt.second)
		}
	}

	// And nothing is invented when neither side claimed it.
	var inv Inventory
	for i := 0; i < 2; i++ {
		inv.Add(Component{Purl: "pkg:npm/x", Version: "1.0.0", Evidence: []FileEvidence{
			{Path: "src/a.js", MatchType: "file"},
		}})
	}
	if inv.Components[0].Evidence[0].Identified {
		t.Error("evidence marked identified when neither side was")
	}
}

// Two releases of one component that matched the same file fold into one evidence. The one that
// stood first in the file's candidate list is kept — its position and its match details — however
// the two arrive, and a position is never traded for the absence of one.
func TestInventoryAddKeepsTheBetterMatchIndex(t *testing.T) {
	at := func(i int) *int { return &i }
	first := FileEvidence{Path: "x.c", MatchType: "file", MatchIndex: at(1), OssFilePath: "first"}
	second := FileEvidence{Path: "x.c", MatchType: "file", MatchIndex: at(3), OssFilePath: "second", Identified: true}
	unknown := FileEvidence{Path: "x.c", MatchType: "file", OssFilePath: "unknown"}

	for _, order := range [][]FileEvidence{{first, second}, {second, first}, {first, unknown}, {unknown, first}} {
		var inv Inventory
		for _, e := range order {
			inv.Add(Component{Purl: "pkg:github/a/b", Version: "1", Evidence: []FileEvidence{e}})
		}
		got := inv.Components[0].Evidence
		if len(got) != 1 {
			t.Fatalf("want one evidence for one file, got %+v", got)
		}
		if got[0].MatchIndex == nil || *got[0].MatchIndex != 1 || got[0].OssFilePath != "first" {
			t.Errorf("adding %s then %s: kept %+v, want the index-1 match",
				order[0].OssFilePath, order[1].OssFilePath, got[0])
		}
		identified := order[0].Identified || order[1].Identified
		if got[0].Identified != identified {
			t.Errorf("adding %s then %s: Identified = %v, want %v",
				order[0].OssFilePath, order[1].OssFilePath, got[0].Identified, identified)
		}
	}
}

// Local is a statement about the component, not about the origin that reported it: a workspace
// package the scan also matched is still the project's own. It survives the merge in either
// order, including the declared-to-detected replacement.
func TestInventoryAddKeepsLocal(t *testing.T) {
	local := Component{Purl: "pkg:npm/tool", Version: "1.0.0", Scope: ScopeDeclared, Local: true}
	detected := Component{Purl: "pkg:npm/tool", Version: "1.0.0", Scope: ScopeDetected, Name: "tool"}
	for name, order := range map[string][]Component{
		"local first":    {local, detected},
		"detected first": {detected, local},
	} {
		t.Run(name, func(t *testing.T) {
			var inv Inventory
			inv.Add(order...)
			if len(inv.Components) != 1 || !inv.Components[0].Local {
				t.Errorf("merged component = %+v, want one local component", inv.Components)
			}
		})
	}
}
