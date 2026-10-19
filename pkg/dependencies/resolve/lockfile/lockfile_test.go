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

package lockfile

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

func ids(nodes []resolve.Node) []resolve.NodeID {
	out := make([]resolve.NodeID, len(nodes))
	for i, n := range nodes {
		out[i] = n.ID
	}
	return out
}

func TestLimits(t *testing.T) {
	diamond := loadCase(t, "testdata/package-lock/diamond")
	tests := []struct {
		name   string
		in     Input
		lim    Limits
		status resolve.Status
		reason resolve.Reason
		nodes  []resolve.NodeID
		edges  []resolve.Edge
	}{
		{
			name:   "lockfile too large",
			in:     diamond,
			lim:    Limits{MaxBytes: 10, MaxNodes: 10, MaxEdges: 10},
			status: resolve.StatusUnknown,
			reason: resolve.ReasonTooLarge,
			nodes:  []resolve.NodeID{},
			edges:  []resolve.Edge{},
		},
		{
			name:   "node limit keeps the first nodes in lockfile order",
			in:     diamond,
			lim:    Limits{MaxBytes: 1 << 20, MaxNodes: 2, MaxEdges: 10},
			status: resolve.StatusPartial,
			reason: resolve.ReasonNodeLimit,
			nodes:  []resolve.NodeID{"pkg:npm/@test/runner@3.1.0", "pkg:npm/bottom@1.2.3"},
			edges:  []resolve.Edge{},
		},
		{
			name:   "edge limit keeps the first edges in lockfile order",
			in:     diamond,
			lim:    Limits{MaxBytes: 1 << 20, MaxNodes: 10, MaxEdges: 1},
			status: resolve.StatusPartial,
			reason: resolve.ReasonEdgeLimit,
			nodes: []resolve.NodeID{
				"pkg:npm/@test/runner@3.1.0", "pkg:npm/bottom@1.2.3", "pkg:npm/left@1.0.0", "pkg:npm/right@2.0.0",
			},
			edges: []resolve.Edge{{From: "pkg:npm/left@1.0.0", To: "pkg:npm/bottom@1.2.3"}},
		},
		{
			name:   "node limit wins over invalid entry",
			in:     loadCase(t, "testdata/package-lock/invalid-entry"),
			lim:    Limits{MaxBytes: 1 << 20, MaxNodes: 0, MaxEdges: 10},
			status: resolve.StatusPartial,
			reason: resolve.ReasonNodeLimit,
			nodes:  []resolve.NodeID{},
			edges:  []resolve.Edge{},
		},
		{
			name: "manifests too large together",
			in: Input{
				Path:     "Cargo.lock",
				Lockfile: []byte("version = 4"),
				Manifest: []byte("[workspace]\nmembers = [\"a\", \"b\"]\n"),
				Members: map[string][]byte{
					"a/Cargo.toml": []byte("[package]\nname = \"a\"\n# padding padding padding\n"),
					"b/Cargo.toml": []byte("[package]\nname = \"b\"\n# padding padding padding\n"),
				},
			},
			lim:    Limits{MaxBytes: 100, MaxNodes: 10, MaxEdges: 10},
			status: resolve.StatusUnknown,
			reason: resolve.ReasonTooLarge,
			nodes:  []resolve.NodeID{},
			edges:  []resolve.Edge{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := parseChecked(t, tt.in, tt.lim)
			if len(g.Roots) != 1 {
				t.Fatalf("got %d roots, want 1", len(g.Roots))
			}
			r := g.Roots[0]
			if r.Status != tt.status || r.Reason != tt.reason {
				t.Errorf("got %s/%s, want %s/%s", r.Status, r.Reason, tt.status, tt.reason)
			}
			if got := ids(g.Nodes); !reflect.DeepEqual(got, tt.nodes) {
				t.Errorf("nodes = %v, want %v", got, tt.nodes)
			}
			if !reflect.DeepEqual(r.Edges, tt.edges) {
				t.Errorf("edges = %v, want %v", r.Edges, tt.edges)
			}
		})
	}
}

func TestDetailIsBounded(t *testing.T) {
	name := strings.Repeat("x", 1<<20)
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/` + name + `":{}}}`
	g := parseChecked(t, Input{Path: "package-lock.json", Lockfile: []byte(lock)}, DefaultLimits())
	r := g.Roots[0]
	if r.Reason != resolve.ReasonInvalidEntry {
		t.Fatalf("reason = %q, want %q", r.Reason, resolve.ReasonInvalidEntry)
	}
	if len(r.Detail) > maxDetail+len("...") {
		t.Errorf("detail is %d bytes, want at most %d", len(r.Detail), maxDetail+len("..."))
	}
}

func TestParseUnsupported(t *testing.T) {
	if _, err := Parse(Input{Path: "go.sum"}, DefaultLimits()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Parse(go.sum) error = %v, want ErrUnsupported", err)
	}
	if Supported("sub/go.sum") || !Supported("sub/package-lock.json") {
		t.Error("Supported does not match on the base name")
	}
	if m, ok := ManifestFor("package-lock.json"); ok {
		t.Errorf("ManifestFor(package-lock.json) = %q, want none: the lockfile records its own roots", m)
	}
	if m, ok := ManifestFor("sub/yarn.lock"); !ok || m != "package.json" {
		t.Errorf("ManifestFor(sub/yarn.lock) = %q, %v; want package.json", m, ok)
	}
	if m, ok := ManifestFor("Gemfile.lock"); !ok || m != "Gemfile" {
		t.Errorf("ManifestFor(Gemfile.lock) = %q, %v; want Gemfile: it says which gems are dev", m, ok)
	}
	if m, ok := ManifestFor("Cargo.lock"); !ok || m != "Cargo.toml" {
		t.Errorf("ManifestFor(Cargo.lock) = %q, %v; want Cargo.toml: it names the workspace members", m, ok)
	}
}

func TestParseFS(t *testing.T) {
	fsys := os.DirFS("testdata/fs")
	tests := []struct {
		path     string
		lim      Limits
		manifest string
		status   resolve.Status
		reason   resolve.Reason
		members  int
		direct   int
	}{
		{"web/package-lock.json", DefaultLimits(), "web/package.json", resolve.StatusComplete, "", 4, 3},
		{"web/package-lock.json", Limits{MaxBytes: 64, MaxNodes: 10, MaxEdges: 10}, "web/package.json", resolve.StatusUnknown, resolve.ReasonTooLarge, 0, 0},
		{"app/yarn.lock", DefaultLimits(), "app/package.json", resolve.StatusComplete, "", 4, 3},
		{"app/yarn.lock", Limits{MaxBytes: 300, MaxNodes: 10, MaxEdges: 10}, "app/package.json", resolve.StatusUnknown, resolve.ReasonTooLarge, 0, 0},
		{"nomanifest/yarn.lock", DefaultLimits(), "nomanifest/package.json", resolve.StatusPartial, resolve.ReasonManifestMissing, 4, 0},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			g, err := ParseFS(fsys, tt.path, tt.lim)
			if err != nil {
				t.Fatal(err)
			}
			if len(g.Roots) != 1 {
				t.Fatalf("got %d roots, want 1", len(g.Roots))
			}
			r := g.Roots[0]
			if r.Manifest != tt.manifest || r.Lockfile != tt.path {
				t.Errorf("root names %q from %q, want %q from %q", r.Manifest, r.Lockfile, tt.manifest, tt.path)
			}
			direct := 0
			for _, m := range r.Members {
				if m.Direct {
					direct++
				}
			}
			if r.Status != tt.status || r.Reason != tt.reason || len(r.Members) != tt.members || direct != tt.direct {
				t.Errorf("got %s/%s with %d members, %d direct; want %s/%s with %d, %d direct",
					r.Status, r.Reason, len(r.Members), direct, tt.status, tt.reason, tt.members, tt.direct)
			}
		})
	}

	if _, err := ParseFS(fsys, "absent/package-lock.json", DefaultLimits()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing lockfile: error = %v, want fs.ErrNotExist", err)
	}
	if _, err := ParseFS(fsys, "web/go.sum", DefaultLimits()); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported lockfile: error = %v, want ErrUnsupported", err)
	}
}
