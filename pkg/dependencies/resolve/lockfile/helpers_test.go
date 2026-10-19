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
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

var update = flag.Bool("update", false, "rewrite the graph.golden.json files")

// fuzzLimits are small so that fuzzing reaches the node and edge caps.
var fuzzLimits = Limits{MaxBytes: 1 << 20, MaxNodes: 6, MaxEdges: 8}

// parseChecked parses in, checks every graph invariant, and checks that a
// second parse gives the same graph.
func parseChecked(t testing.TB, in Input, lim Limits) resolve.Graph {
	t.Helper()
	g, err := Parse(in, lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	checkGraph(t, in, lim, g)
	again, _ := Parse(in, lim)
	if !reflect.DeepEqual(g, again) {
		t.Fatalf("Parse is not deterministic:\n%+v\n%+v", g, again)
	}
	return g
}

func checkGraph(t testing.TB, in Input, lim Limits, g resolve.Graph) {
	t.Helper()
	if g.Nodes == nil || g.Roots == nil {
		t.Fatalf("nil slices in %+v", g)
	}
	if len(g.Nodes) > lim.MaxNodes {
		t.Errorf("%d nodes, limit %d", len(g.Nodes), lim.MaxNodes)
	}
	nodes := map[resolve.NodeID]bool{}
	for i, n := range g.Nodes {
		if i > 0 && g.Nodes[i-1].ID >= n.ID {
			t.Errorf("nodes not sorted and unique at %q", n.ID)
		}
		if n.Version == "" || string(n.ID) != n.PURL+"@"+n.Version {
			t.Errorf("node %+v: ID is not PURL@Version", n)
		}
		nodes[n.ID] = true
	}
	if len(g.Roots) == 0 {
		t.Fatalf("no roots")
	}
	inSomeRoot := map[resolve.NodeID]bool{}
	for i, r := range g.Roots {
		if i > 0 {
			p := g.Roots[i-1]
			if p.Manifest > r.Manifest || (p.Manifest == r.Manifest && p.Lockfile >= r.Lockfile) {
				t.Errorf("roots not sorted and unique at %q", r.Manifest)
			}
		}
		if r.Lockfile != in.Path {
			t.Errorf("root %q: lockfile %q, want %q", r.Manifest, r.Lockfile, in.Path)
		}
		checkStatus(t, r)
		if len(r.Detail) > maxDetail+len("...") {
			t.Errorf("root %q: detail of %d bytes, limit %d", r.Manifest, len(r.Detail), maxDetail)
		}
		if r.Members == nil || r.Edges == nil {
			t.Errorf("root %q: nil members or edges", r.Manifest)
		}
		if r.Status == resolve.StatusUnknown && (len(r.Members) > 0 || len(r.Edges) > 0) {
			t.Errorf("unknown root %q has members or edges", r.Manifest)
		}
		if len(r.Edges) > lim.MaxEdges {
			t.Errorf("root %q: %d edges, limit %d", r.Manifest, len(r.Edges), lim.MaxEdges)
		}
		members := map[resolve.NodeID]bool{}
		for j, m := range r.Members {
			if j > 0 && r.Members[j-1].ID >= m.ID {
				t.Errorf("root %q: members not sorted and unique at %q", r.Manifest, m.ID)
			}
			if !nodes[m.ID] {
				t.Errorf("root %q: member %q is not a node", r.Manifest, m.ID)
			}
			members[m.ID] = true
			inSomeRoot[m.ID] = true
		}
		for j, e := range r.Edges {
			if j > 0 {
				p := r.Edges[j-1]
				if p.From > e.From || (p.From == e.From && p.To >= e.To) {
					t.Errorf("root %q: edges not sorted and unique at %+v", r.Manifest, e)
				}
			}
			if !members[e.From] || !members[e.To] {
				t.Errorf("root %q: edge %+v has an end that is not a member", r.Manifest, e)
			}
		}
	}
	for id := range nodes {
		if !inSomeRoot[id] {
			t.Errorf("node %q is in no root", id)
		}
	}
}

func checkStatus(t testing.TB, r resolve.Root) {
	t.Helper()
	unknown := []resolve.Reason{resolve.ReasonMalformed, resolve.ReasonUnsupportedVersion, resolve.ReasonTooLarge}
	partial := []resolve.Reason{
		resolve.ReasonNodeLimit, resolve.ReasonEdgeLimit, resolve.ReasonManifestMissing,
		resolve.ReasonManifestMalformed, resolve.ReasonUnsupportedWorkspaces,
		resolve.ReasonUnresolvedDependency, resolve.ReasonInvalidEntry,
	}
	ok := false
	switch r.Status {
	case resolve.StatusComplete:
		ok = r.Reason == "" && r.Detail == ""
	case resolve.StatusUnknown:
		ok = slices.Contains(unknown, r.Reason)
	case resolve.StatusPartial:
		ok = slices.Contains(partial, r.Reason)
	}
	if !ok {
		t.Errorf("root %q: status %q with reason %q", r.Manifest, r.Status, r.Reason)
	}
}

// loadCase reads the lockfile in dir, its sibling manifest when the format
// reads one and the case has it, and the member manifests the format collects.
func loadCase(t testing.TB, dir string) Input {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !Supported(e.Name()) {
			continue
		}
		in := Input{Path: e.Name()}
		if in.Lockfile, err = os.ReadFile(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
		if m, ok := ManifestFor(e.Name()); ok {
			in.Manifest, err = os.ReadFile(filepath.Join(dir, m))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		if f, _ := lookup(e.Name()); f.members != nil && in.Manifest != nil {
			lim := DefaultLimits()
			in.Members = f.members(os.DirFS(dir), ".", in.Manifest, lim.MaxBytes, lim.MaxNodes)
		}
		return in
	}
	t.Fatalf("no lockfile in %s", dir)
	return Input{}
}

func caseDirs(t testing.TB, format string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join("testdata", format, "*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no cases for %s: %v", format, err)
	}
	return dirs
}

// runGolden parses every case under testdata/<format> and compares the graph
// with the case's graph.golden.json.
func runGolden(t *testing.T, format string) {
	for _, dir := range caseDirs(t, format) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			g := parseChecked(t, loadCase(t, dir), DefaultLimits())
			got, err := json.MarshalIndent(g, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join(dir, "graph.golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("graph differs from %s (rerun with -update to accept):\n%s", golden, got)
			}
		})
	}
}

// fuzzFormat seeds f with every case of format and checks the invariants of
// whatever Parse makes of the mutated input.
func fuzzFormat(f *testing.F, format string) {
	var lockfile string
	for _, dir := range caseDirs(f, format) {
		in := loadCase(f, dir)
		lockfile = in.Path
		f.Add(in.Lockfile, in.Manifest, in.Manifest != nil)
	}
	f.Fuzz(func(t *testing.T, data, manifest []byte, hasManifest bool) {
		in := Input{Path: lockfile, Lockfile: data}
		if hasManifest {
			in.Manifest = manifest
		}
		parseChecked(t, in, fuzzLimits)
	})
}
