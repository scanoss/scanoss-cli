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

package build_test

import (
	"reflect"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/graphtest"
)

func TestUnknownRootHasNoMembers(t *testing.T) {
	lim := build.Limits{MaxNodes: 10, MaxEdges: 10}
	b := build.New("Cargo.lock", resolve.EcosystemCargo, "Cargo.toml", lim)
	shared, _ := b.Node("", "shared", "1.0.0")
	only, _ := b.Node("", "only", "1.0.0")
	b.Edge(only, shared)
	b.Root("").Declare(shared, false)
	r := b.Root("crates/app")
	r.DevKnown = true
	r.Declare(only, false)
	r.Flag(resolve.ReasonTooLarge, "too big")

	g := b.Graph()
	graphtest.Check(t, g, "Cargo.lock", lim)
	want := resolve.Graph{
		Nodes: []resolve.Node{{ID: shared, PURL: "pkg:cargo/shared", Version: "1.0.0"}},
		Roots: []resolve.Root{
			{
				Manifest: "Cargo.toml", Lockfile: "Cargo.lock", Ecosystem: resolve.EcosystemCargo,
				Status: resolve.StatusComplete, Members: []resolve.Member{{ID: shared, Direct: true}}, Edges: []resolve.Edge{},
			},
			{
				Manifest: "crates/app/Cargo.toml", Lockfile: "Cargo.lock", Ecosystem: resolve.EcosystemCargo,
				Status: resolve.StatusUnknown, Reason: resolve.ReasonTooLarge, Detail: "too big",
				Members: []resolve.Member{}, Edges: []resolve.Edge{},
			},
		},
	}
	if !reflect.DeepEqual(g, want) {
		t.Errorf("got  %+v\nwant %+v", g, want)
	}
}

func TestMerge(t *testing.T) {
	lim := build.Limits{MaxNodes: 10, MaxEdges: 10}
	module := func(dir string, local bool) resolve.Graph {
		b := build.New(dir+"/pom.xml", resolve.EcosystemMaven, "pom.xml", lim)
		add := b.Node
		if local {
			add = b.Local
		}
		core, _ := add("com.example", "core", "1.0.0")
		own, _ := b.Node("org.example", dir, "1.0")
		b.Root("").Declare(core, false)
		b.Root("").Declare(own, false)
		return b.Graph()
	}
	core := resolve.NodeID("pkg:maven/com.example/core@1.0.0")
	g := build.Merge(module("b", true), module("a", false), module("c", true))

	var ids []resolve.NodeID
	for _, n := range g.Nodes {
		ids = append(ids, n.ID)
		if n.ID == core && n.Local {
			t.Error("core is a registry node in one graph, but the merge made it local")
		}
	}
	wantIDs := []resolve.NodeID{core, "pkg:maven/org.example/a@1.0", "pkg:maven/org.example/b@1.0", "pkg:maven/org.example/c@1.0"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("nodes %v, want %v", ids, wantIDs)
	}
	var manifests []string
	for _, r := range g.Roots {
		manifests = append(manifests, r.Manifest+" "+r.Lockfile)
	}
	if want := []string{"a/pom.xml a/pom.xml", "b/pom.xml b/pom.xml", "c/pom.xml c/pom.xml"}; !reflect.DeepEqual(manifests, want) {
		t.Errorf("roots %v, want %v", manifests, want)
	}

	if both := build.Merge(module("b", true), module("c", true)); both.Nodes[0].ID != core || !both.Nodes[0].Local {
		t.Errorf("core is local in every graph, but the merge has %+v", both.Nodes[0])
	}
	if empty := build.Merge(); empty.Nodes == nil || empty.Roots == nil {
		t.Errorf("Merge() = %+v, want empty slices", empty)
	}
}
