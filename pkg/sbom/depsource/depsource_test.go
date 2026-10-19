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

package depsource

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/sbom"
)

func npm(name string) resolve.Node {
	return resolve.Node{ID: resolve.NodeID("pkg:npm/" + name + "@1.0.0"), PURL: "pkg:npm/" + name, Version: "1.0.0"}
}

func id(name string) resolve.NodeID { return npm(name).ID }

func edge(from, to string) resolve.Edge { return resolve.Edge{From: id(from), To: id(to)} }

// sampleGraph covers every shape the projection has to get right: a diamond (a -> b, a -> c,
// b -> d, c -> d), a cycle (cyc1 <-> cyc2), a dev-only subtree (jest -> jest-core), a package
// both dev- and runtime-reachable (shared, through jest and through left), a local node with a
// child (tool -> toolchild), a partial root and an unknown root.
func sampleGraph() resolve.Graph {
	tool := resolve.Node{ID: "pkg:npm/tool", PURL: "pkg:npm/tool", Local: true}
	nodes := []resolve.Node{npm("a"), npm("b"), npm("c"), npm("cyc1"), npm("cyc2"), npm("d"),
		npm("jest"), npm("jest-core"), npm("left"), npm("p1"), npm("p2"), npm("shared"), tool, npm("toolchild")}
	main := resolve.Root{
		Manifest: "package.json", Lockfile: "package-lock.json", Ecosystem: resolve.EcosystemNPM,
		Status: resolve.StatusComplete, DevKnown: true,
		Members: []resolve.Member{
			{ID: id("a"), Direct: true}, {ID: id("b")}, {ID: id("c")},
			{ID: id("cyc1"), Direct: true}, {ID: id("cyc2")}, {ID: id("d")},
			{ID: id("jest"), Direct: true, Dev: true}, {ID: id("jest-core"), Dev: true},
			{ID: id("left"), Direct: true}, {ID: id("shared")},
			{ID: tool.ID, Direct: true}, {ID: id("toolchild")},
		},
		Edges: []resolve.Edge{
			edge("a", "b"), edge("a", "c"), edge("b", "d"), edge("c", "d"),
			edge("cyc1", "cyc2"), edge("cyc2", "cyc1"),
			edge("jest", "jest-core"), edge("jest", "shared"), edge("left", "shared"),
			{From: tool.ID, To: id("toolchild")},
		},
	}
	partial := resolve.Root{
		Manifest: "web/package.json", Lockfile: "web/yarn.lock", Ecosystem: resolve.EcosystemNPM,
		Status: resolve.StatusPartial, Reason: resolve.ReasonManifestMissing, Detail: "no package.json",
		Members: []resolve.Member{{ID: id("p1")}, {ID: id("p2")}},
		Edges:   []resolve.Edge{edge("p1", "p2")},
	}
	unknown := resolve.Root{
		Manifest: "broken/package.json", Lockfile: "broken/package-lock.json", Ecosystem: resolve.EcosystemNPM,
		Status: resolve.StatusUnknown, Reason: resolve.ReasonMalformed, Detail: "unexpected end of JSON input",
	}
	return resolve.Graph{Nodes: nodes, Roots: []resolve.Root{unknown, main, partial}}
}

func refs(comps []sbom.Component) []string {
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		out = append(out, c.Ref())
	}
	slices.Sort(out)
	return out
}

func find(t *testing.T, inv sbom.Inventory, ref string) sbom.Component {
	t.Helper()
	for _, c := range inv.Components {
		if c.Ref() == ref {
			return c
		}
	}
	t.Fatalf("component %s missing from %v", ref, refs(inv.Components))
	return sbom.Component{}
}

func TestGraphKeepsRuntimeMembersAndDropsDev(t *testing.T) {
	inv := Graph(sampleGraph())

	want := []string{
		"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0", "pkg:npm/cyc1@1.0.0", "pkg:npm/cyc2@1.0.0",
		"pkg:npm/d@1.0.0", "pkg:npm/left@1.0.0", "pkg:npm/p1@1.0.0", "pkg:npm/p2@1.0.0", "pkg:npm/shared@1.0.0",
		"pkg:npm/tool", "pkg:npm/toolchild@1.0.0",
	}
	if got := refs(inv.Components); !slices.Equal(got, want) {
		t.Errorf("components:\n got %q\nwant %q", got, want)
	}
	for _, c := range inv.Components {
		if !c.IsDeclared() {
			t.Errorf("%s should be declared, got %q", c.Ref(), c.Scope)
		}
	}

	a := find(t, inv, "pkg:npm/a@1.0.0")
	if want := []sbom.FileEvidence{{Path: "package.json", MatchType: "declared"}}; !reflect.DeepEqual(a.Evidence, want) {
		t.Errorf("direct member evidence = %+v", a.Evidence)
	}
	d := find(t, inv, "pkg:npm/d@1.0.0")
	if want := []sbom.FileEvidence{{Path: "package.json", MatchType: "transitive"}}; !reflect.DeepEqual(d.Evidence, want) {
		t.Errorf("transitive member evidence = %+v", d.Evidence)
	}
	if tool := find(t, inv, "pkg:npm/tool"); !tool.Local {
		t.Error("the workspace package must be marked local")
	}
	if left := find(t, inv, "pkg:npm/left@1.0.0"); left.Local {
		t.Error("a registry package must not be marked local")
	}
}

func TestGraphRootsAndEdges(t *testing.T) {
	inv := Graph(sampleGraph())

	if len(inv.Dependencies) != 3 {
		t.Fatalf("want 3 roots, got %+v", inv.Dependencies)
	}
	unknown, main, partial := inv.Dependencies[0], inv.Dependencies[1], inv.Dependencies[2]

	if unknown.Status != sbom.GraphUnknown || unknown.Reason != "malformed" || unknown.Detail == "" || len(unknown.Edges) != 0 {
		t.Errorf("unknown root = %+v", unknown)
	}
	if partial.Status != sbom.GraphPartial || partial.Reason != "manifest_missing" || partial.Lockfile != "web/yarn.lock" {
		t.Errorf("partial root = %+v", partial)
	}
	if !slices.Equal(partial.Edges, []sbom.DependencyEdge{{From: "pkg:npm/p1@1.0.0", To: "pkg:npm/p2@1.0.0"}}) {
		t.Errorf("partial edges = %+v", partial.Edges)
	}
	if main.Status != sbom.GraphComplete || main.Ecosystem != "npm" || !main.DevKnown || main.Reason != "" {
		t.Errorf("complete root = %+v", main)
	}
	wantEdges := []sbom.DependencyEdge{
		{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"},
		{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"},
		{From: "pkg:npm/b@1.0.0", To: "pkg:npm/d@1.0.0"},
		{From: "pkg:npm/c@1.0.0", To: "pkg:npm/d@1.0.0"},
		{From: "pkg:npm/cyc1@1.0.0", To: "pkg:npm/cyc2@1.0.0"},
		{From: "pkg:npm/cyc2@1.0.0", To: "pkg:npm/cyc1@1.0.0"},
		{From: "pkg:npm/left@1.0.0", To: "pkg:npm/shared@1.0.0"},
		{From: "pkg:npm/tool", To: "pkg:npm/toolchild@1.0.0"},
	}
	if !slices.Equal(main.Edges, wantEdges) {
		t.Errorf("complete root edges:\n got %+v\nwant %+v", main.Edges, wantEdges)
	}
}

// A node that two roots reach is one component with one evidence per root, so a root's
// membership is still readable after the merge.
func TestGraphMergesSharedNodes(t *testing.T) {
	g := resolve.Graph{
		Nodes: []resolve.Node{npm("x")},
		Roots: []resolve.Root{
			{Manifest: "a/package.json", Lockfile: "package-lock.json", Status: resolve.StatusComplete, Members: []resolve.Member{{ID: id("x"), Direct: true}}},
			{Manifest: "b/package.json", Lockfile: "package-lock.json", Status: resolve.StatusComplete, Members: []resolve.Member{{ID: id("x")}}},
		},
	}
	inv := Graph(g)
	if len(inv.Components) != 1 {
		t.Fatalf("want 1 component, got %+v", inv.Components)
	}
	want := []sbom.FileEvidence{{Path: "a/package.json", MatchType: "declared"}, {Path: "b/package.json", MatchType: "transitive"}}
	if got := inv.Components[0].Evidence; !reflect.DeepEqual(got, want) {
		t.Errorf("evidence = %+v, want %+v", got, want)
	}
}

func copyFixture(t *testing.T, dst, fixture string) {
	t.Helper()
	src := filepath.Join("..", "..", "dependencies", "resolve", "lockfile", "testdata", fixture)
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const pomXML = `<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency></dependencies></project>`

// TestInventory reads a tree where a lockfile covers its manifest (no flat range entry for it),
// a Cargo workspace yields one root per member, a pom.xml has no lockfile (flat), and a malformed
// lockfile leaves its package.json to the flat parser.
func TestInventory(t *testing.T) {
	root := t.TempDir()
	copyFixture(t, root, "package-lock/dev-scope")
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"left":"^1.0.0"},"devDependencies":{"jest":"^29.0.0"}}`)
	copyFixture(t, filepath.Join(root, "rust"), "cargo/workspace")
	writeFile(t, filepath.Join(root, "java", "pom.xml"), pomXML)
	copyFixture(t, filepath.Join(root, "broken"), "package-lock/malformed")
	writeFile(t, filepath.Join(root, "broken", "package.json"), `{"dependencies":{"express":"^4.0.0"}}`)

	var files []string
	if err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	selected := Select(files)
	wantSelected := []string{"broken/package-lock.json", "broken/package.json", "java/pom.xml", "package-lock.json", "package.json", "rust/Cargo.lock"}
	var gotSelected []string
	for _, f := range selected {
		gotSelected = append(gotSelected, relSlash(root, f))
	}
	slices.Sort(gotSelected)
	if !slices.Equal(gotSelected, wantSelected) {
		t.Errorf("Select = %q, want %q", gotSelected, wantSelected)
	}

	inv, failed := Inventory(root, selected)
	// The malformed lockfile is reported on its root, not as a failure; the flat parser then
	// reads it and fails on the same content.
	if len(failed) != 1 || failed[filepath.Join(root, "broken", "package-lock.json")] == nil {
		t.Errorf("failed = %v, want only the malformed lockfile's flat parse", failed)
	}

	var roots []string
	for _, r := range inv.Dependencies {
		roots = append(roots, fmt.Sprintf("%s %s", r.Manifest, r.Status))
	}
	wantRoots := []string{
		"broken/package.json unknown",
		"package.json complete",
		"packages/tool/package.json complete",
		"rust/Cargo.toml complete",
		"rust/crates/app/Cargo.toml complete",
		"rust/crates/lib/Cargo.toml complete",
	}
	if !slices.Equal(roots, wantRoots) {
		t.Errorf("roots:\n got %q\nwant %q", roots, wantRoots)
	}

	got := refs(inv.Components)
	for _, absent := range []string{"pkg:npm/left@^1.0.0", "pkg:npm/jest@^29.0.0"} {
		if slices.Contains(got, absent) {
			t.Errorf("%s must not appear: a manifest its lockfile covers is not parsed flat (got %q)", absent, got)
		}
	}
	for _, present := range []string{
		"pkg:npm/left@1.0.0", "pkg:npm/shared@1.0.0", // runtime, from the graph
		"pkg:npm/jest@29.0.0",                            // dev in the main root, runtime in the workspace member
		"pkg:cargo/serde@1.0.200", "pkg:cargo/lib@0.1.0", // Cargo, including the local crate
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0", // flat fallback, no lockfile
		"pkg:npm/express@^4.0.0",                            // flat fallback, lockfile unreadable
	} {
		if !slices.Contains(got, present) {
			t.Errorf("%s missing from %q", present, got)
		}
	}
	// jest is dev for the main root and runtime for the workspace member, so it is kept with
	// the member's evidence only; the same goes for what it pulls in.
	jest := find(t, inv, "pkg:npm/jest@29.0.0")
	if want := []sbom.FileEvidence{{Path: "packages/tool/package.json", MatchType: "declared"}}; !reflect.DeepEqual(jest.Evidence, want) {
		t.Errorf("jest evidence = %+v, want only the workspace member that needs it at runtime", jest.Evidence)
	}
	core := find(t, inv, "pkg:npm/jest-core@29.0.0")
	if want := []sbom.FileEvidence{{Path: "packages/tool/package.json", MatchType: "transitive"}}; !reflect.DeepEqual(core.Evidence, want) {
		t.Errorf("jest-core evidence = %+v", core.Evidence)
	}
	if express := find(t, inv, "pkg:npm/express@^4.0.0"); express.Evidence[0].Path != "broken/package.json" {
		t.Errorf("flat fallback evidence = %+v", express.Evidence)
	}
}

// Declared components come from the parsed manifests without a service call: each PURL is split
// into base + version, scoped npm PURLs split correctly, and only exact duplicates (same PURL +
// version) are collapsed. A declared range (package.json "^1.3.0") is kept alongside its
// resolved pin (package-lock.json "1.3.0"): those are not duplicates.
func TestManifests(t *testing.T) {
	declared := &parsers.LocalDependencies{
		Files: []parsers.LocalDependency{
			{File: "package.json", Purls: []parsers.LocalPurl{
				{Purl: "pkg:npm/left-pad", Requirement: "^1.3.0"},
				{Purl: "pkg:npm/dup@1.0.0", Requirement: "1.0.0"},
			}},
			{File: "package-lock.json", Purls: []parsers.LocalPurl{
				{Purl: "pkg:npm/left-pad@1.3.0", Requirement: "1.3.0"},
				{Purl: "pkg:npm/@scope/pkg@2.1.0", Requirement: "2.1.0"},
				{Purl: "pkg:npm/dup@1.0.0", Requirement: "1.0.0"},
				{Purl: "pkg:npm/multi@1.0.0", Requirement: "1.0.0"},
				{Purl: "pkg:npm/multi@2.0.0", Requirement: "2.0.0"},
			}},
		},
	}

	got := Manifests(declared, "")
	byKey := make(map[string]sbom.Component, len(got.Components))
	for _, c := range got.Components {
		if _, dup := byKey[c.Ref()]; dup {
			t.Errorf("duplicate entry for %s", c.Ref())
		}
		byKey[c.Ref()] = c
		if !c.IsDeclared() {
			t.Errorf("%s should have declared scope", c.Purl)
		}
	}
	for _, w := range []string{
		"pkg:npm/left-pad@^1.3.0",
		"pkg:npm/left-pad@1.3.0",
		"pkg:npm/@scope/pkg@2.1.0",
		"pkg:npm/multi@1.0.0",
		"pkg:npm/multi@2.0.0",
		"pkg:npm/dup@1.0.0",
	} {
		c, ok := byKey[w]
		if !ok {
			t.Errorf("missing %q in %v", w, byKey)
			continue
		}
		if len(c.Evidence) == 0 || c.Evidence[0].MatchType != "declared" {
			t.Errorf("%s should carry declared evidence, got %+v", w, c.Evidence)
		}
	}
	if dup := byKey["pkg:npm/dup@1.0.0"]; len(dup.Evidence) != 2 {
		t.Errorf("dup@1.0.0 should keep both manifest occurrences, got %+v", dup.Evidence)
	}
}

func TestMerge(t *testing.T) {
	shared := resolve.Node{ID: "pkg:npm/a@1.0.0", PURL: "pkg:npm/a", Version: "1.0.0"}
	only := resolve.Node{ID: "pkg:npm/b@1.0.0", PURL: "pkg:npm/b", Version: "1.0.0"}
	g := merge([]resolve.Graph{
		{Nodes: []resolve.Node{shared, only}, Roots: []resolve.Root{{Manifest: "z/package.json", Lockfile: "z/package-lock.json"}}},
		{Nodes: []resolve.Node{shared}, Roots: []resolve.Root{{Manifest: "a/package.json", Lockfile: "a/yarn.lock"}}},
	})

	if !slices.Equal(g.Nodes, []resolve.Node{shared, only}) {
		t.Errorf("nodes: %v", g.Nodes)
	}
	var manifests []string
	for _, r := range g.Roots {
		manifests = append(manifests, r.Manifest)
	}
	if !slices.Equal(manifests, []string{"a/package.json", "z/package.json"}) {
		t.Errorf("roots: %v", manifests)
	}
}
