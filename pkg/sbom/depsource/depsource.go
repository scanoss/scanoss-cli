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

// Package depsource builds an sbom.Inventory from a project's dependency files. Lockfiles the
// resolver supports become a dependency graph (pkg/dependencies/resolve/lockfile), with dev
// members left out; manifests no lockfile covers are parsed flat (pkg/dependencies), as a list
// of declared packages with no edges. It is the dependency counterpart of scansource, and the
// only SBOM code that depends on the dependency parsers.
package depsource

import (
	"cmp"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies"
	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/lockfile"
	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// Select keeps the files Inventory reads: the lockfiles the resolver supports and the manifests
// the flat parsers handle. A caller collecting a tree hands it everything and gets back what the
// dependency stage will open, which is also the count worth reporting as that stage's total.
func Select(files []string) []string {
	parser := dependencies.NewDependencyParser()
	var out []string
	for _, f := range files {
		if lockfile.Supported(f) || parser.IsSupportedFile(f) {
			out = append(out, f)
		}
	}
	return out
}

// Inventory reads the dependency files of the project at root. Each supported lockfile is
// resolved into a graph and the graphs are merged; every root covers its manifest and its
// lockfile, so neither is parsed flat again. An unknown root covers them too: it says the
// lockfile was there and could not be read, and a flat parse would bring back the range entries
// and dev dependencies the graph exists to replace. Every other selected manifest is parsed flat.
//
// failed is keyed by path and holds the lockfiles that could not be read and the manifests that
// could not be parsed. It is nil when nothing failed. Unknown roots are not failures: they are
// reported on the root itself.
func Inventory(root string, files []string) (sbom.Inventory, map[string]error) {
	fsys := os.DirFS(root)
	failed := map[string]error{}
	var graphs []resolve.Graph
	for _, f := range files {
		if !lockfile.Supported(f) {
			continue
		}
		g, err := lockfile.ParseFS(fsys, relSlash(root, f), lockfile.DefaultLimits())
		if err != nil {
			failed[f] = err
			continue
		}
		graphs = append(graphs, g)
	}
	graph := merge(graphs)

	covered := map[string]bool{}
	for _, r := range graph.Roots {
		covered[r.Manifest] = true
		covered[r.Lockfile] = true
	}
	parser := dependencies.NewDependencyParser()
	var flat []string
	for _, f := range files {
		if parser.IsSupportedFile(f) && !covered[relSlash(root, f)] {
			flat = append(flat, f)
		}
	}
	parsed, flatFailed := parser.ParseFiles(flat)
	maps.Copy(failed, flatFailed)

	inv := Graph(graph)
	inv.Add(Manifests(parsed, root).Components...)
	if len(failed) == 0 {
		failed = nil
	}
	return inv, failed
}

// Graph projects a resolved graph into an inventory: one declared component per member of each
// root that is not dev, and one DependencyRoot per root. A node shared by several roots is one
// component carrying one evidence per root, "declared" where that root's manifest declares it
// and "transitive" where its lockfile pulls it in. Dev members never appear, and neither does an
// edge that touches one, so a root's edges only ever join components that are in the inventory.
// An unknown root is kept, with no members and no edges, so the output says the lockfile was
// there and could not be read.
func Graph(g resolve.Graph) sbom.Inventory {
	nodes := make(map[resolve.NodeID]resolve.Node, len(g.Nodes))
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}

	var inv sbom.Inventory
	var comps []sbom.Component
	for _, r := range g.Roots {
		dev := map[resolve.NodeID]bool{}
		direct := []string{}
		for _, m := range r.Members {
			if m.Dev {
				dev[m.ID] = true
				continue
			}
			n := nodes[m.ID]
			matchType := "transitive"
			if m.Direct {
				matchType = "declared"
				direct = append(direct, ref(n))
			}
			comps = append(comps, sbom.Component{
				Purl:     n.PURL,
				Version:  n.Version,
				Scope:    sbom.ScopeDeclared,
				Local:    n.Local,
				Evidence: []sbom.FileEvidence{{Path: r.Manifest, MatchType: matchType}},
			})
		}
		edges := make([]sbom.DependencyEdge, 0, len(r.Edges))
		for _, e := range r.Edges {
			if dev[e.From] || dev[e.To] {
				continue
			}
			edges = append(edges, sbom.DependencyEdge{From: ref(nodes[e.From]), To: ref(nodes[e.To])})
		}
		inv.Dependencies = append(inv.Dependencies, sbom.DependencyRoot{
			Manifest:  r.Manifest,
			Lockfile:  r.Lockfile,
			Ecosystem: string(r.Ecosystem),
			Status:    sbom.GraphStatus(r.Status),
			Reason:    string(r.Reason),
			Detail:    r.Detail,
			DevKnown:  r.DevKnown,
			Direct:    direct,
			Edges:     edges,
		})
	}
	inv.Add(comps...)
	return inv
}

// ref is the component ref a node renders as, computed by the inventory's own rule rather than
// copied from the node ID so an edge always names the component it lands on.
func ref(n resolve.Node) string {
	return sbom.Component{Purl: n.PURL, Version: n.Version}.Ref()
}

// Manifests builds declared components from flat-parsed manifests, with no round trip to any
// service: each PURL is split into its base and version (the manifest's requirement when the
// PURL carries none), tagged declared, and given the manifest as evidence, relative to root in
// slash form so it matches a root's manifest path. Exact duplicates fold into one component with
// one evidence per manifest; distinct versions of a package are kept, including a declared range
// (package.json "^1.5.5") alongside its resolved pin (package-lock.json "1.14.3").
func Manifests(parsed *parsers.LocalDependencies, root string) sbom.Inventory {
	var inv sbom.Inventory
	if parsed == nil {
		return inv
	}
	var comps []sbom.Component
	for _, file := range parsed.Files {
		manifest := relSlash(root, file.File)
		for _, p := range file.Purls {
			purl, version := splitPurlVersion(p.Purl)
			if version == "" {
				version = p.Requirement
			}
			if purl == "" {
				continue
			}
			comps = append(comps, sbom.Component{
				Purl:     purl,
				Version:  version,
				Scope:    sbom.ScopeDeclared,
				Evidence: []sbom.FileEvidence{{Path: manifest, MatchType: "declared"}},
			})
		}
	}
	inv.Add(comps...)
	return inv
}

// merge joins graphs into one, keeping each node once and the order resolve.Graph documents.
func merge(graphs []resolve.Graph) resolve.Graph {
	var out resolve.Graph
	seen := map[resolve.NodeID]bool{}
	for _, g := range graphs {
		for _, n := range g.Nodes {
			if !seen[n.ID] {
				seen[n.ID] = true
				out.Nodes = append(out.Nodes, n)
			}
		}
		out.Roots = append(out.Roots, g.Roots...)
	}
	slices.SortFunc(out.Nodes, func(a, b resolve.Node) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Roots, func(a, b resolve.Root) int {
		return cmp.Or(cmp.Compare(a.Manifest, b.Manifest), cmp.Compare(a.Lockfile, b.Lockfile))
	})
	return out
}

// relSlash returns path relative to root in slash form when it is under root, so a manifest's
// evidence matches the path its lockfile root is named by. Falls back to the path unchanged when
// root is empty or the path is outside it.
func relSlash(root, path string) string {
	if root == "" {
		return filepath.ToSlash(path)
	}
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// splitPurlVersion splits a PURL into its base identity and version, e.g.
// "pkg:npm/@scope/name@1.2.3" -> ("pkg:npm/@scope/name", "1.2.3"). The version separator is the
// last "@" after the final "/", so a scoped-npm "@scope" prefix (which has no preceding "/") is
// never mistaken for a version.
func splitPurlVersion(purl string) (base, version string) {
	slash := strings.LastIndex(purl, "/")
	if at := strings.LastIndex(purl, "@"); at > slash {
		return purl[:at], purl[at+1:]
	}
	return purl, ""
}
