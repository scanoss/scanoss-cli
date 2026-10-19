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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

func copyFixture(t *testing.T, dst, fixture string) {
	t.Helper()
	src := filepath.Join("..", "pkg", "dependencies", "resolve", "lockfile", "testdata", fixture)
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
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
	copyFixture(t, filepath.Join(tree, "shrink"), "npm-shrinkwrap/dev-scope")
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
		"shrink/package.json complete",
		"shrink/packages/tool/package.json complete",
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
