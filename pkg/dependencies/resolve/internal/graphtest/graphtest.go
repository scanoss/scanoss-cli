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

// Package graphtest checks the invariants every resolve.Graph keeps, for the
// tests of the resolvers under resolve.
package graphtest

import (
	"slices"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// Check checks every invariant of g, the graph resolved from lockfile within
// lim.
func Check(t testing.TB, g resolve.Graph, lockfile string, lim build.Limits) {
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
		versioned := n.Version != "" && string(n.ID) == n.PURL+"@"+n.Version
		versionless := n.Local && n.Version == "" && string(n.ID) == n.PURL
		if !versioned && !versionless {
			t.Errorf("node %+v: ID is not PURL@Version, nor the PURL of a local node without a version", n)
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
		if r.Lockfile != lockfile {
			t.Errorf("root %q: lockfile %q, want %q", r.Manifest, r.Lockfile, lockfile)
		}
		checkStatus(t, r)
		if len(r.Detail) > build.MaxDetail+len("...") {
			t.Errorf("root %q: detail of %d bytes, limit %d", r.Manifest, len(r.Detail), build.MaxDetail)
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
		checkDev(t, r)
	}
	for id := range nodes {
		if !inSomeRoot[id] {
			t.Errorf("node %q is in no root", id)
		}
	}
}

func checkDev(t testing.TB, r resolve.Root) {
	t.Helper()
	dev := map[resolve.NodeID]bool{}
	var queue []resolve.NodeID
	for _, m := range r.Members {
		if m.Dev {
			dev[m.ID] = true
			if m.Direct {
				queue = append(queue, m.ID)
			}
		}
	}
	if len(dev) > 0 && !r.DevKnown {
		t.Errorf("root %q: dev members although DevKnown is false", r.Manifest)
	}
	out := map[resolve.NodeID][]resolve.NodeID{}
	for _, e := range r.Edges {
		if !dev[e.From] && dev[e.To] {
			t.Errorf("root %q: runtime %q depends on dev %q", r.Manifest, e.From, e.To)
		}
		out[e.From] = append(out[e.From], e.To)
	}
	reached := map[resolve.NodeID]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if reached[id] {
			continue
		}
		reached[id] = true
		queue = append(queue, out[id]...)
	}
	for id := range dev {
		if !reached[id] {
			t.Errorf("root %q: dev %q is not reached from a dev direct dependency", r.Manifest, id)
		}
	}
}

func checkStatus(t testing.TB, r resolve.Root) {
	t.Helper()
	unknown := []resolve.Reason{
		resolve.ReasonMalformed, resolve.ReasonUnsupportedVersion, resolve.ReasonTooLarge,
		resolve.ReasonToolMissing, resolve.ReasonToolFailed, resolve.ReasonTimeout,
	}
	partial := []resolve.Reason{
		resolve.ReasonNodeLimit, resolve.ReasonEdgeLimit, resolve.ReasonRegistryUnreachable, resolve.ReasonManifestMissing,
		resolve.ReasonManifestMalformed, resolve.ReasonUnsupportedWorkspaces,
		resolve.ReasonEdgesUnknown, resolve.ReasonUnresolvedDependency, resolve.ReasonInvalidEntry,
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
