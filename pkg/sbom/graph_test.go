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
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/spdxlib"
)

// graphInventory is an inventory with a resolved graph: a detected match the graph does not
// reach, a complete root whose manifest declares a and the local tool, edges a -> b, a -> c,
// b -> c and tool -> child, a partial root with one unattributed member, an unknown root, and
// one edge into a ref no component has.
func graphInventory() Inventory {
	declared := func(manifest, matchType string) []FileEvidence {
		return []FileEvidence{{Path: manifest, MatchType: matchType}}
	}
	return Inventory{
		Components: []Component{
			{Purl: "pkg:npm/lodash", Name: "lodash", Version: "4.17.21", Evidence: []FileEvidence{{Path: "src/a.js", MatchType: "file"}}},
			{Purl: "pkg:npm/a", Version: "1.0.0", Scope: ScopeDeclared, Evidence: declared("package.json", "declared")},
			{Purl: "pkg:npm/b", Version: "1.0.0", Scope: ScopeDeclared, Evidence: declared("package.json", "transitive")},
			{Purl: "pkg:npm/c", Version: "1.0.0", Scope: ScopeDeclared, Evidence: declared("package.json", "transitive")},
			{Purl: "pkg:npm/tool", Scope: ScopeDeclared, Local: true, Evidence: declared("package.json", "declared")},
			{Purl: "pkg:npm/child", Version: "2.0.0", Scope: ScopeDeclared, Evidence: declared("package.json", "transitive")},
			{Purl: "pkg:npm/p1", Version: "1.0.0", Scope: ScopeDeclared, Evidence: declared("web/package.json", "transitive")},
		},
		Dependencies: []DependencyRoot{
			{Manifest: "broken/package.json", Lockfile: "broken/package-lock.json", Ecosystem: "npm", Status: GraphUnknown, Reason: "malformed", Edges: []DependencyEdge{}},
			{Manifest: "package.json", Lockfile: "package-lock.json", Ecosystem: "npm", Status: GraphComplete, DevKnown: true, Direct: []string{"pkg:npm/a@1.0.0", "pkg:npm/tool"}, Edges: []DependencyEdge{
				{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"},
				{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"},
				{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"},
				{From: "pkg:npm/tool", To: "pkg:npm/child@2.0.0"},
				{From: "pkg:npm/c@1.0.0", To: "pkg:npm/ghost@1.0.0"},
			}},
			{Manifest: "web/package.json", Lockfile: "web/yarn.lock", Ecosystem: "npm", Status: GraphPartial, Reason: "manifest_missing", Edges: []DependencyEdge{}},
		},
	}
}

// cdxDependsOn flattens the dependencies section into ref -> dependsOn, with the key present
// even when the list is empty, so a test can tell "no dependencies" from "no entry".
func cdxDependsOn(bom cdx.BOM) map[string][]string {
	out := map[string][]string{}
	if bom.Dependencies == nil {
		return out
	}
	for _, d := range *bom.Dependencies {
		targets := []string{}
		if d.Dependencies != nil {
			targets = append(targets, *d.Dependencies...)
		}
		out[d.Ref] = targets
	}
	return out
}

// checkCycloneDXReferences fails when a ref in dependencies or compositions names nothing in
// the document: not a component, not the metadata component.
func checkCycloneDXReferences(t *testing.T, bom cdx.BOM) {
	t.Helper()
	known := map[string]bool{}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		known[bom.Metadata.Component.BOMRef] = true
	}
	if bom.Components != nil {
		for _, c := range *bom.Components {
			known[c.BOMRef] = true
		}
	}
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if !known[d.Ref] {
				t.Errorf("dependencies entry %q names no component", d.Ref)
			}
			if d.Dependencies != nil {
				for _, to := range *d.Dependencies {
					if !known[to] {
						t.Errorf("%q dependsOn %q, which is not in the document", d.Ref, to)
					}
				}
			}
		}
	}
	if bom.Compositions != nil {
		for _, c := range *bom.Compositions {
			if c.Dependencies != nil {
				for _, ref := range *c.Dependencies {
					if !known[string(ref)] {
						t.Errorf("composition names %q, which is not in the document", ref)
					}
				}
			}
		}
	}
}

func TestCycloneDXDependencyGraph(t *testing.T) {
	out, err := Generate(graphInventory(), FormatCycloneDX, WithProjectName("proj"))
	if err != nil {
		t.Fatal(err)
	}
	bom := decodeBOM(t, out)
	checkCycloneDXReferences(t, bom)

	if bom.Metadata.Component.BOMRef != "proj" {
		t.Errorf("metadata component bom-ref = %q, want the project name", bom.Metadata.Component.BOMRef)
	}

	roots := map[string]cdx.Component{}
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeApplication {
			roots[c.BOMRef] = c
		}
	}
	main, ok := roots["package.json@package-lock.json"]
	if !ok || main.Name != "package.json" || main.PackageURL != "" {
		t.Fatalf("root component = %+v, want an application named by its manifest", main)
	}
	if props := propertyMap(main); props[scanossLockfileProp] != "package-lock.json" || props[scanossReasonProp] != "" {
		t.Errorf("complete root properties = %v", props)
	}
	if props := propertyMap(roots["web/package.json@web/yarn.lock"]); props[scanossReasonProp] != "manifest_missing" {
		t.Errorf("partial root properties = %v, want the reason", props)
	}

	want := map[string][]string{
		"proj": {"broken/package.json@broken/package-lock.json", "package.json@package-lock.json", "web/package.json@web/yarn.lock"},
		"broken/package.json@broken/package-lock.json": {},
		"package.json@package-lock.json":               {"pkg:npm/a@1.0.0", "pkg:npm/tool"},
		"web/package.json@web/yarn.lock":               {},
		"pkg:npm/lodash@4.17.21":                       {},
		"pkg:npm/a@1.0.0":                              {"pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"},
		"pkg:npm/b@1.0.0":                              {"pkg:npm/c@1.0.0"},
		"pkg:npm/c@1.0.0":                              {}, // the edge to ghost is dropped
		"pkg:npm/tool":                                 {"pkg:npm/child@2.0.0"},
		"pkg:npm/child@2.0.0":                          {},
		"pkg:npm/p1@1.0.0":                             {},
	}
	if got := cdxDependsOn(bom); !reflect.DeepEqual(got, want) {
		t.Errorf("dependencies:\n got %v\nwant %v", got, want)
	}

	if bom.Compositions == nil {
		t.Fatal("want one composition per root")
	}
	var compositions []string
	for _, c := range *bom.Compositions {
		compositions = append(compositions, string(c.Aggregate)+" "+string((*c.Dependencies)[0]))
	}
	wantCompositions := []string{
		"unknown broken/package.json@broken/package-lock.json",
		"complete package.json@package-lock.json",
		"incomplete web/package.json@web/yarn.lock",
	}
	if !slices.Equal(compositions, wantCompositions) {
		t.Errorf("compositions = %q, want %q", compositions, wantCompositions)
	}

	for _, c := range *bom.Components {
		local := propertyMap(c)[scanossLocalProp] == "true"
		if local != (c.BOMRef == "pkg:npm/tool") {
			t.Errorf("%s local property = %v", c.BOMRef, local)
		}
		// Transitive evidence is not an occurrence: b is not in package.json.
		if c.BOMRef == "pkg:npm/b@1.0.0" && c.Evidence != nil {
			t.Errorf("transitive member must carry no occurrence, got %+v", c.Evidence)
		}
	}
}

func propertyMap(c cdx.Component) map[string]string {
	props := map[string]string{}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			props[p.Name] = p.Value
		}
	}
	return props
}

// Without a resolved graph the document carries no dependencies section at all: an empty entry
// would claim the scan matches have no dependencies, which it does not know. The metadata
// component keeps its bom-ref either way.
func TestCycloneDXNoGraphWithoutRoots(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX, WithProjectName("proj"))
	if err != nil {
		t.Fatal(err)
	}
	bom := decodeBOM(t, out)
	if bom.Dependencies != nil || bom.Compositions != nil {
		t.Errorf("dependencies = %v, compositions = %v, want neither", bom.Dependencies, bom.Compositions)
	}
	if bom.Metadata.Component.BOMRef != "proj" {
		t.Errorf("metadata component bom-ref = %q", bom.Metadata.Component.BOMRef)
	}
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeLibrary {
			t.Errorf("%s has type %q; no root component without a graph", c.BOMRef, c.Type)
		}
	}
}

// spdxRelationships renders relationships as "A KIND B" with package names, so an expectation
// reads without md5 identifiers.
func spdxRelationships(doc *v2_3.Document) []string {
	names := map[string]string{"DOCUMENT": "DOCUMENT"}
	for _, p := range doc.Packages {
		names[string(p.PackageSPDXIdentifier)] = p.PackageName
	}
	var out []string
	for _, r := range doc.Relationships {
		out = append(out, names[string(r.RefA.ElementRefID)]+" "+r.Relationship+" "+names[string(r.RefB.ElementRefID)])
	}
	return out
}

func TestSPDXLiteDependencyGraph(t *testing.T) {
	out, err := Generate(graphInventory(), FormatSPDX, WithProjectName("proj"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := spdxjson.Read(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if err := spdxlib.ValidateDocument(doc); err != nil {
		t.Errorf("spdxlib.ValidateDocument: %v", err)
	}

	want := []string{
		"DOCUMENT DESCRIBES lodash",
		"DOCUMENT DESCRIBES a",
		"DOCUMENT DESCRIBES b",
		"DOCUMENT DESCRIBES c",
		"DOCUMENT DESCRIBES tool",
		"DOCUMENT DESCRIBES child",
		"DOCUMENT DESCRIBES p1",
		"DOCUMENT DESCRIBES proj",
		"proj DEPENDS_ON broken/package.json",
		"proj DEPENDS_ON package.json",
		"package.json DEPENDS_ON a",
		"package.json DEPENDS_ON tool",
		"proj DEPENDS_ON web/package.json",
		"a DEPENDS_ON b",
		"a DEPENDS_ON c",
		"b DEPENDS_ON c",
		"tool DEPENDS_ON child",
	}
	if got := spdxRelationships(doc); !slices.Equal(got, want) {
		t.Errorf("relationships:\n got %q\nwant %q", got, want)
	}

	comments := map[string]string{}
	for _, p := range doc.Packages {
		comments[p.PackageName] = p.PackageComment
	}
	if comments["proj"] != scanossProjectComment {
		t.Errorf("project comment = %q", comments["proj"])
	}
	if comments["web/package.json"] != "scanoss:root lockfile=web/yarn.lock status=partial reason=manifest_missing" {
		t.Errorf("root comment = %q", comments["web/package.json"])
	}
	if comments["tool"] != scanossLocalComment || comments["a"] != "" {
		t.Errorf("local comments: tool=%q a=%q", comments["tool"], comments["a"])
	}
}

// Reading a graph-bearing document back yields the packages, never the project or root
// placeholders as components, and keeps the local mark. The graph itself is raw-only.
func TestParseGraphDocumentsKeepPackagesOnly(t *testing.T) {
	inv := graphInventory()
	wantRefs := []string{"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0", "pkg:npm/child@2.0.0", "pkg:npm/lodash@4.17.21", "pkg:npm/p1@1.0.0", "pkg:npm/tool"}

	for name, tc := range map[string]struct {
		format Format
		parse  func([]byte) (Inventory, error)
	}{
		"cyclonedx": {FormatCycloneDX, ParseCycloneDX},
		"spdx":      {FormatSPDX, ParseSPDX},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := Generate(inv, tc.format, WithProjectName("proj"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := tc.parse([]byte(out))
			if err != nil {
				t.Fatal(err)
			}
			var refs []string
			local := map[string]bool{}
			for _, c := range got.Components {
				refs = append(refs, c.Ref())
				local[c.Ref()] = c.Local
			}
			slices.Sort(refs)
			if !slices.Equal(refs, wantRefs) {
				t.Errorf("components = %q, want %q", refs, wantRefs)
			}
			if !local["pkg:npm/tool"] || local["pkg:npm/a@1.0.0"] {
				t.Errorf("local marks = %v", local)
			}
		})
	}
}
