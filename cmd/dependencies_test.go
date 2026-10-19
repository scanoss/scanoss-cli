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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdxlib"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/sbom"
)

func copyFixture(t *testing.T, dst, fixture string) {
	t.Helper()
	src := filepath.Join("..", "pkg", "dependencies", "resolve", "lockfile", "testdata", fixture)
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
}

// dependencyTree mixes a package-lock.json whose main root has a dev dependency, a Cargo
// workspace, and a pom.xml that no lockfile covers.
func dependencyTree(t *testing.T) string {
	t.Helper()
	tree := t.TempDir()
	copyFixture(t, tree, "package-lock/dev-scope")
	copyFixture(t, filepath.Join(tree, "rust"), "cargo/workspace")
	pom := `<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency></dependencies></project>`
	if err := os.WriteFile(filepath.Join(tree, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	return tree
}

func runDependenciesFormat(t *testing.T, tree, format string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.json")
	if _, _, err := runBare(t, "dependencies", tree, "--extract-local", "--format", format, "--output", out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDependenciesFormatRaw(t *testing.T) {
	out := runDependenciesFormat(t, dependencyTree(t), "raw")

	inv, err := sbom.ParseRaw([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	var roots []string
	for _, r := range inv.Dependencies {
		roots = append(roots, fmt.Sprintf("%s %s devKnown=%v", r.Manifest, r.Status, r.DevKnown))
	}
	want := []string{
		"package.json complete devKnown=true",
		"packages/tool/package.json complete devKnown=true",
		"rust/Cargo.toml complete devKnown=false",
		"rust/crates/app/Cargo.toml complete devKnown=true",
		"rust/crates/lib/Cargo.toml complete devKnown=true",
	}
	if !slices.Equal(roots, want) {
		t.Errorf("roots:\n got %q\nwant %q", roots, want)
	}

	var refs []string
	for _, c := range inv.Components {
		refs = append(refs, c.Ref())
	}
	for _, present := range []string{"pkg:npm/left@1.0.0", "pkg:cargo/serde@1.0.200", "pkg:maven/org.apache.commons/commons-lang3@3.12.0"} {
		if !slices.Contains(refs, present) {
			t.Errorf("%s missing from %q", present, refs)
		}
	}
	// jest is a dev dependency of the main root and a runtime one of the workspace member, so
	// it is in the document with the member's evidence only.
	for _, c := range inv.Components {
		if c.Purl != "pkg:npm/jest" {
			continue
		}
		if len(c.Evidence) != 1 || c.Evidence[0].Path != "packages/tool/package.json" {
			t.Errorf("jest evidence = %+v, want only the workspace member", c.Evidence)
		}
	}
	if !strings.Contains(out, `"schema_version": "`+sbom.RawSchemaVersion+`"`) {
		t.Error("raw output must be the versioned envelope")
	}
}

func TestDependenciesFormatCycloneDX(t *testing.T) {
	out := runDependenciesFormat(t, dependencyTree(t), "cyclonedx")

	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(strings.NewReader(out), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatal(err)
	}
	refs := map[string]bool{bom.Metadata.Component.BOMRef: true}
	for _, c := range *bom.Components {
		refs[c.BOMRef] = true
	}
	for _, d := range *bom.Dependencies {
		if !refs[d.Ref] {
			t.Errorf("dependencies entry %q names no component", d.Ref)
		}
		if d.Dependencies != nil {
			for _, to := range *d.Dependencies {
				if !refs[to] {
					t.Errorf("%q dependsOn %q, which is not in the document", d.Ref, to)
				}
			}
		}
	}
	if !refs["package.json@package-lock.json"] || !refs["rust/crates/app/Cargo.toml@rust/Cargo.lock"] {
		t.Errorf("root components missing from %v", refs)
	}
	if !refs["pkg:maven/org.apache.commons/commons-lang3@3.12.0"] {
		t.Error("the flat-parsed pom.xml dependency must still be a component")
	}
	if len(*bom.Compositions) != 5 {
		t.Errorf("want one composition per root, got %d", len(*bom.Compositions))
	}
}

func TestDependenciesFormatSPDX(t *testing.T) {
	out := runDependenciesFormat(t, dependencyTree(t), "spdx")

	doc, err := spdxjson.Read(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if err := spdxlib.ValidateDocument(doc); err != nil {
		t.Errorf("spdxlib.ValidateDocument: %v", err)
	}
	var names []string
	depends := 0
	for _, p := range doc.Packages {
		names = append(names, p.PackageName)
	}
	for _, r := range doc.Relationships {
		if r.Relationship == "DEPENDS_ON" {
			depends++
		}
	}
	for _, want := range []string{"package.json", "rust/crates/app/Cargo.toml", "commons-lang3", "left", "serde"} {
		if !slices.Contains(names, want) {
			t.Errorf("package %q missing from %q", want, names)
		}
	}
	if depends == 0 {
		t.Error("want DEPENDS_ON relationships from the lockfile graph")
	}
}

// Without --format the command prints what it always printed: the flat per-file list.
func TestDependenciesExtractLocalWithoutFormatIsFlat(t *testing.T) {
	out := filepath.Join(t.TempDir(), "deps.json")
	if _, _, err := runBare(t, "dependencies", dependencyTree(t), "--extract-local", "--output", out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var flat struct {
		Files []struct {
			File  string `json:"file"`
			Purls []struct {
				Purl string `json:"purl"`
			} `json:"purls"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &flat); err != nil {
		t.Fatalf("flat output should be the per-file list, got %v:\n%s", err, data)
	}
	if len(flat.Files) == 0 || strings.Contains(string(data), "schema_version") {
		t.Errorf("flat output changed shape:\n%s", data)
	}
}

func TestDependenciesFormatFlagRules(t *testing.T) {
	if _, _, err := runBare(t, "dependencies", t.TempDir(), "--format", "raw"); err == nil || err.Error() != "--format requires --extract-local" {
		t.Errorf("--format without --extract-local: got %v", err)
	}
	if _, _, err := runBare(t, "dependencies", t.TempDir(), "--extract-local", "--format", "xml"); err == nil || !strings.Contains(err.Error(), "invalid output format") {
		t.Errorf("--format xml: got %v", err)
	}
}

func TestDependenciesGraphFindsEveryLockfile(t *testing.T) {
	tree := t.TempDir()
	copyFixture(t, tree, "package-lock/diamond")
	copyFixture(t, filepath.Join(tree, "web"), "yarn/diamond")
	copyFixture(t, filepath.Join(tree, "app"), "pnpm/v9-diamond")
	copyFixture(t, filepath.Join(tree, "rust"), "cargo/workspace")
	copyFixture(t, filepath.Join(tree, "ruby"), "gemfile/diamond")
	copyFixture(t, filepath.Join(tree, "py"), "poetry/diamond")
	copyFixture(t, filepath.Join(tree, "php"), "composer/diamond")
	copyFixture(t, filepath.Join(tree, "node_modules", "dep"), "package-lock/diamond")
	unreadable := filepath.Join(tree, "broken", "Gemfile.lock")
	if err := os.MkdirAll(filepath.Dir(unreadable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unreadable, []byte("GEM\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	out := filepath.Join(t.TempDir(), "graph.json")

	_, _, err := runBare(t, "dependencies", tree, "--extract-local", "--graph", "--output", out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var g resolve.Graph
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, r := range g.Roots {
		got = append(got, r.Manifest+" "+string(r.Status))
	}
	want := []string{
		"app/package.json complete",
		"package.json complete",
		"php/composer.json complete",
		"py/pyproject.toml complete",
		"ruby/Gemfile complete",
		"rust/Cargo.toml complete",
		"rust/crates/app/Cargo.toml complete",
		"rust/crates/lib/Cargo.toml complete",
		"web/package.json complete",
	}
	if !slices.Equal(got, want) {
		t.Errorf("roots:\n got %q\nwant %q", got, want)
	}
	if len(g.Nodes) == 0 {
		t.Error("no nodes")
	}
}

func TestDependenciesGraphRequiresExtractLocal(t *testing.T) {
	_, _, err := runBare(t, "dependencies", t.TempDir(), "--graph")
	if err == nil || err.Error() != "--graph requires --extract-local" {
		t.Fatalf("got %v", err)
	}
}

func TestMergeGraphs(t *testing.T) {
	shared := resolve.Node{ID: "pkg:npm/a@1.0.0", PURL: "pkg:npm/a", Version: "1.0.0"}
	only := resolve.Node{ID: "pkg:npm/b@1.0.0", PURL: "pkg:npm/b", Version: "1.0.0"}
	g := mergeGraphs([]resolve.Graph{
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
