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
	"cmp"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// precedence lists every reason, unknown ones first. When several apply to a
// root, the earliest wins.
var precedence = []resolve.Reason{
	resolve.ReasonMalformed,
	resolve.ReasonUnsupportedVersion,
	resolve.ReasonTooLarge,
	resolve.ReasonNodeLimit,
	resolve.ReasonEdgeLimit,
	resolve.ReasonManifestMissing,
	resolve.ReasonManifestMalformed,
	resolve.ReasonUnsupportedWorkspaces,
	resolve.ReasonEdgesUnknown,
	resolve.ReasonUnresolvedDependency,
	resolve.ReasonInvalidEntry,
}

func isUnknown(r resolve.Reason) bool {
	return r == resolve.ReasonMalformed || r == resolve.ReasonUnsupportedVersion || r == resolve.ReasonTooLarge
}

// maxDetail bounds a detail, which quotes names taken from the lockfile, so a
// hostile lockfile cannot make every root carry megabytes of text.
const maxDetail = 256

// issue is the winning reason among those recorded. Ties on the reason keep
// the smallest detail, so the result does not depend on recording order.
type issue struct {
	reason resolve.Reason
	detail string
}

func (i *issue) add(o issue) {
	if o.reason == "" {
		return
	}
	if len(o.detail) > maxDetail {
		o.detail = strings.ToValidUTF8(o.detail[:maxDetail], "") + "..."
	}
	if i.reason == "" {
		*i = o
		return
	}
	a, b := slices.Index(precedence, o.reason), slices.Index(precedence, i.reason)
	if a < b || (a == b && o.detail < i.detail) {
		*i = o
	}
}

// root collects what a format knows about one manifest: the nodes it declares
// and its own problems. Members, edges and dev marks are derived in graph.
type root struct {
	direct  map[resolve.NodeID]bool // declared nodes
	runtime map[resolve.NodeID]bool // declared nodes that are not dev dependencies
	// devKnown is set by a format whose manifests say which declared nodes
	// are dev dependencies.
	devKnown bool
	issue
}

// declare records id as declared by the root's manifest, as a dev dependency
// when dev is set. A node declared both ways is a runtime dependency.
func (r *root) declare(id resolve.NodeID, dev bool) {
	r.direct[id] = true
	if !dev {
		r.runtime[id] = true
	}
}

func (r *root) flag(reason resolve.Reason, detail string) {
	r.add(issue{reason, detail})
}

// builder is the only way a format adds to a graph, so the graph invariants
// (limits, edge ends, reasons, ordering) hold for every format.
type builder struct {
	lim       Limits
	lockfile  string
	ecosystem resolve.Ecosystem
	manifest  string
	nodes     map[resolve.NodeID]resolve.Node
	adj       map[resolve.NodeID]map[resolve.NodeID]bool
	edges     int
	roots     map[string]*root
	problem   issue
	problems  map[resolve.NodeID]issue
}

func newBuilder(lockfile string, f format, lim Limits) *builder {
	return &builder{
		lim:       lim,
		lockfile:  lockfile,
		ecosystem: f.ecosystem,
		manifest:  f.manifest,
		nodes:     map[resolve.NodeID]resolve.Node{},
		adj:       map[resolve.NodeID]map[resolve.NodeID]bool{},
		roots:     map[string]*root{},
		problems:  map[resolve.NodeID]issue{},
	}
}

// node adds the registry package namespace/name at version and returns its
// ID. It returns false when the entry is incomplete or the node limit is
// reached.
func (b *builder) node(namespace, name, version string) (resolve.NodeID, bool) {
	return b.add(namespace, name, version, false)
}

// local adds the project's own package namespace/name, as node does. A local
// package may lack a version; its ID is then its versionless Package URL. A
// local package with the ID of a registry package shares that node, which
// stays a registry node, so a consumer that skips local nodes never drops a
// third-party package.
func (b *builder) local(namespace, name, version string) (resolve.NodeID, bool) {
	return b.add(namespace, name, version, true)
}

func (b *builder) add(namespace, name, version string, local bool) (resolve.NodeID, bool) {
	if name == "" || (version == "" && !local) {
		b.flag(resolve.ReasonInvalidEntry, fmt.Sprintf("entry %q at version %q lacks a name or version", name, version))
		return "", false
	}
	purl := parsers.BuildPURL(string(b.ecosystem), namespace, name, "", nil)
	id := resolve.NodeID(purl)
	if version != "" {
		id = resolve.NodeID(parsers.BuildPURL(string(b.ecosystem), namespace, name, version, nil))
	}
	if n, ok := b.nodes[id]; ok {
		n.Local = n.Local && local
		b.nodes[id] = n
		return id, true
	}
	if len(b.nodes) >= b.lim.MaxNodes {
		b.flag(resolve.ReasonNodeLimit, fmt.Sprintf("more than %d nodes", b.lim.MaxNodes))
		return "", false
	}
	b.nodes[id] = resolve.Node{ID: id, PURL: purl, Version: version, Local: local}
	return id, true
}

// edge records that from depends on to. Both must be nodes already.
func (b *builder) edge(from, to resolve.NodeID) {
	if b.adj[from][to] {
		return
	}
	if _, ok := b.nodes[from]; !ok {
		return
	}
	if _, ok := b.nodes[to]; !ok {
		return
	}
	if b.edges >= b.lim.MaxEdges {
		b.flag(resolve.ReasonEdgeLimit, fmt.Sprintf("more than %d edges", b.lim.MaxEdges))
		return
	}
	if b.adj[from] == nil {
		b.adj[from] = map[resolve.NodeID]bool{}
	}
	b.adj[from][to] = true
	b.edges++
}

// root returns the root for the manifest in dir, a directory relative to the
// lockfile's.
func (b *builder) root(dir string) *root {
	m := path.Join(path.Dir(b.lockfile), dir, b.manifest)
	r, ok := b.roots[m]
	if !ok {
		r = &root{direct: map[resolve.NodeID]bool{}, runtime: map[resolve.NodeID]bool{}}
		b.roots[m] = r
	}
	return r
}

// nameRoot names the roots after the one file in members, for a format whose
// manifest name varies; its members hook is sibling.
func (b *builder) nameRoot(members map[string][]byte) {
	if len(members) == 1 {
		b.manifest = slices.Collect(maps.Keys(members))[0]
	}
}

// flag records a problem that affects every root.
func (b *builder) flag(reason resolve.Reason, detail string) {
	b.problem.add(issue{reason, detail})
}

// flagNode records a problem with node id; it affects every root that reaches
// id.
func (b *builder) flagNode(id resolve.NodeID, reason resolve.Reason, detail string) {
	i := b.problems[id]
	i.add(issue{reason, detail})
	b.problems[id] = i
}

func (b *builder) graph() resolve.Graph {
	b.root("")
	mainName := path.Join(path.Dir(b.lockfile), b.manifest)
	if isUnknown(b.problem.reason) {
		return resolve.Graph{
			Nodes: []resolve.Node{},
			Roots: []resolve.Root{b.emit(mainName, b.problem, map[resolve.NodeID]bool{}, nil)},
		}
	}

	starts := map[string]map[resolve.NodeID]bool{}
	reached := map[resolve.NodeID]bool{}
	for name, r := range b.roots {
		starts[name] = maps.Clone(r.direct)
		for id := range b.reach(r.direct) {
			reached[id] = true
		}
	}
	for id := range b.nodes {
		if !reached[id] {
			starts[mainName][id] = false
		}
	}

	g := resolve.Graph{Nodes: make([]resolve.Node, 0, len(b.nodes)), Roots: make([]resolve.Root, 0, len(b.roots))}
	for _, n := range b.nodes {
		g.Nodes = append(g.Nodes, n)
	}
	slices.SortFunc(g.Nodes, func(x, y resolve.Node) int { return cmp.Compare(x.ID, y.ID) })
	for name, r := range b.roots {
		members := b.reach(starts[name])
		is := r.issue
		is.add(b.problem)
		for id := range members {
			is.add(b.problems[id])
		}
		// Only what dev dependencies alone reach is dev; the rest of starts,
		// unattributed nodes included, counts as runtime.
		var runtime map[resolve.NodeID]bool
		if r.devKnown {
			runtime = map[resolve.NodeID]bool{}
			for id, direct := range starts[name] {
				if !direct || r.runtime[id] {
					runtime[id] = true
				}
			}
			runtime = b.reach(runtime)
		}
		g.Roots = append(g.Roots, b.emit(name, is, members, runtime))
	}
	slices.SortFunc(g.Roots, func(x, y resolve.Root) int {
		return cmp.Or(cmp.Compare(x.Manifest, y.Manifest), cmp.Compare(x.Lockfile, y.Lockfile))
	})
	return g
}

// reach returns start plus every node reachable from it, keeping start's
// direct flags.
func (b *builder) reach(start map[resolve.NodeID]bool) map[resolve.NodeID]bool {
	out := make(map[resolve.NodeID]bool, len(start))
	queue := make([]resolve.NodeID, 0, len(start))
	for id, direct := range start {
		out[id] = direct
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for to := range b.adj[id] {
			if _, ok := out[to]; !ok {
				out[to] = false
				queue = append(queue, to)
			}
		}
	}
	return out
}

// emit builds a root from its members. runtime holds the members that runtime
// dependencies reach; nil means the root does not know its dev dependencies.
func (b *builder) emit(manifest string, is issue, members, runtime map[resolve.NodeID]bool) resolve.Root {
	r := resolve.Root{
		Manifest:  manifest,
		Lockfile:  b.lockfile,
		Ecosystem: b.ecosystem,
		Status:    resolve.StatusComplete,
		Reason:    is.reason,
		Detail:    is.detail,
		DevKnown:  runtime != nil,
		Members:   make([]resolve.Member, 0, len(members)),
		Edges:     []resolve.Edge{},
	}
	switch {
	case isUnknown(is.reason):
		r.Status = resolve.StatusUnknown
	case is.reason != "":
		r.Status = resolve.StatusPartial
	}
	for id, direct := range members {
		_, rt := runtime[id]
		r.Members = append(r.Members, resolve.Member{ID: id, Direct: direct, Dev: runtime != nil && !rt})
		for to := range b.adj[id] {
			r.Edges = append(r.Edges, resolve.Edge{From: id, To: to})
		}
	}
	slices.SortFunc(r.Members, func(x, y resolve.Member) int { return cmp.Compare(x.ID, y.ID) })
	slices.SortFunc(r.Edges, func(x, y resolve.Edge) int {
		return cmp.Or(cmp.Compare(x.From, y.From), cmp.Compare(x.To, y.To))
	})
	return r
}
