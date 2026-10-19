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

// Package build is the only way the resolvers under resolve add to a graph,
// so the graph invariants (limits, edge ends, reasons, ordering) hold for
// every one of them.
package build

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
	resolve.ReasonToolMissing,
	resolve.ReasonToolFailed,
	resolve.ReasonTimeout,
	resolve.ReasonNodeLimit,
	resolve.ReasonEdgeLimit,
	resolve.ReasonRegistryUnreachable,
	resolve.ReasonManifestMissing,
	resolve.ReasonManifestMalformed,
	resolve.ReasonUnsupportedWorkspaces,
	resolve.ReasonUnresolvedDependency,
	resolve.ReasonInvalidEntry,
	resolve.ReasonEdgesUnknown,
}

func isUnknown(r resolve.Reason) bool {
	switch r {
	case resolve.ReasonMalformed, resolve.ReasonUnsupportedVersion, resolve.ReasonTooLarge,
		resolve.ReasonToolMissing, resolve.ReasonToolFailed, resolve.ReasonTimeout:
		return true
	}
	return false
}

// MaxDetail bounds a detail, which quotes names taken from the input, so a
// hostile lockfile cannot make every root carry megabytes of text.
const MaxDetail = 256

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
	if len(o.detail) > MaxDetail {
		o.detail = strings.ToValidUTF8(o.detail[:MaxDetail], "") + "..."
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

// Limits bounds the graph a Builder makes.
type Limits struct {
	MaxNodes int // nodes kept; reaching it makes the roots partial (node_limit)
	MaxEdges int // edges kept; reaching it makes the roots partial (edge_limit)
}

// Root collects what a resolver knows about one manifest: the nodes it
// declares and its own problems. Members, edges and dev marks are derived in
// Graph.
type Root struct {
	direct  map[resolve.NodeID]bool // declared nodes
	runtime map[resolve.NodeID]bool // declared nodes that are not dev dependencies
	// DevKnown is set by a resolver whose manifests say which declared nodes
	// are dev dependencies.
	DevKnown bool
	issue
}

// Declare records id as declared by the root's manifest, as a dev dependency
// when dev is set. A node declared both ways is a runtime dependency.
func (r *Root) Declare(id resolve.NodeID, dev bool) {
	r.direct[id] = true
	if !dev {
		r.runtime[id] = true
	}
}

// Flag records a problem of this root alone.
func (r *Root) Flag(reason resolve.Reason, detail string) {
	r.add(issue{reason, detail})
}

// Builder collects the nodes, edges and roots of one graph.
type Builder struct {
	lim       Limits
	lockfile  string
	ecosystem resolve.Ecosystem
	manifest  string
	nodes     map[resolve.NodeID]resolve.Node
	adj       map[resolve.NodeID]map[resolve.NodeID]bool
	edges     int
	roots     map[string]*Root
	problem   issue
	problems  map[resolve.NodeID]issue
}

// New returns a Builder for the graph that lockfile, a slash path, resolves.
// Its roots stand for files named manifest and carry eco.
func New(lockfile string, eco resolve.Ecosystem, manifest string, lim Limits) *Builder {
	return &Builder{
		lim:       lim,
		lockfile:  lockfile,
		ecosystem: eco,
		manifest:  manifest,
		nodes:     map[resolve.NodeID]resolve.Node{},
		adj:       map[resolve.NodeID]map[resolve.NodeID]bool{},
		roots:     map[string]*Root{},
		problems:  map[resolve.NodeID]issue{},
	}
}

// Lockfile returns the slash path of the lockfile the graph is resolved from.
func (b *Builder) Lockfile() string {
	return b.lockfile
}

// Node adds the registry package namespace/name at version and returns its
// ID. It returns false when the entry is incomplete or the node limit is
// reached.
func (b *Builder) Node(namespace, name, version string) (resolve.NodeID, bool) {
	return b.add(namespace, name, version, false)
}

// Local adds the project's own package namespace/name, as Node does. A local
// package may lack a version; its ID is then its versionless Package URL. A
// local package with the ID of a registry package shares that node, which
// stays a registry node, so a consumer that skips local nodes never drops a
// third-party package.
func (b *Builder) Local(namespace, name, version string) (resolve.NodeID, bool) {
	return b.add(namespace, name, version, true)
}

func (b *Builder) add(namespace, name, version string, local bool) (resolve.NodeID, bool) {
	if name == "" || (version == "" && !local) {
		b.Flag(resolve.ReasonInvalidEntry, fmt.Sprintf("entry %q at version %q lacks a name or version", name, version))
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
		b.Flag(resolve.ReasonNodeLimit, fmt.Sprintf("more than %d nodes", b.lim.MaxNodes))
		return "", false
	}
	b.nodes[id] = resolve.Node{ID: id, PURL: purl, Version: version, Local: local}
	return id, true
}

// Edge records that from depends on to. Both must be nodes already.
func (b *Builder) Edge(from, to resolve.NodeID) {
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
		b.Flag(resolve.ReasonEdgeLimit, fmt.Sprintf("more than %d edges", b.lim.MaxEdges))
		return
	}
	if b.adj[from] == nil {
		b.adj[from] = map[resolve.NodeID]bool{}
	}
	b.adj[from][to] = true
	b.edges++
}

// Root returns the root for the manifest in dir, a directory relative to the
// lockfile's.
func (b *Builder) Root(dir string) *Root {
	m := path.Join(path.Dir(b.lockfile), dir, b.manifest)
	r, ok := b.roots[m]
	if !ok {
		r = &Root{direct: map[resolve.NodeID]bool{}, runtime: map[resolve.NodeID]bool{}}
		b.roots[m] = r
	}
	return r
}

// NameRoot names the roots after the one file in members, for a format whose
// manifest name varies; its members hook is sibling.
func (b *Builder) NameRoot(members map[string][]byte) {
	if len(members) == 1 {
		b.manifest = slices.Collect(maps.Keys(members))[0]
	}
}

// Flag records a problem that affects every root.
func (b *Builder) Flag(reason resolve.Reason, detail string) {
	b.problem.add(issue{reason, detail})
}

// FlagNode records a problem with node id; it affects every root that reaches
// id.
func (b *Builder) FlagNode(id resolve.NodeID, reason resolve.Reason, detail string) {
	i := b.problems[id]
	i.add(issue{reason, detail})
	b.problems[id] = i
}

// Graph returns the graph built so far.
func (b *Builder) Graph() resolve.Graph {
	b.Root("")
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
		if r.DevKnown {
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
	kept := map[resolve.NodeID]bool{}
	for _, r := range g.Roots {
		for _, m := range r.Members {
			kept[m.ID] = true
		}
	}
	for id, n := range b.nodes {
		if kept[id] {
			g.Nodes = append(g.Nodes, n)
		}
	}
	slices.SortFunc(g.Nodes, func(x, y resolve.Node) int { return cmp.Compare(x.ID, y.ID) })
	slices.SortFunc(g.Roots, func(x, y resolve.Root) int {
		return cmp.Or(cmp.Compare(x.Manifest, y.Manifest), cmp.Compare(x.Lockfile, y.Lockfile))
	})
	return g
}

// reach returns start plus every node reachable from it, keeping start's
// direct flags.
func (b *Builder) reach(start map[resolve.NodeID]bool) map[resolve.NodeID]bool {
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
func (b *Builder) emit(manifest string, is issue, members, runtime map[resolve.NodeID]bool) resolve.Root {
	r := resolve.Root{
		Manifest:  manifest,
		Lockfile:  b.lockfile,
		Ecosystem: b.ecosystem,
		Status:    resolve.StatusComplete,
		Reason:    is.reason,
		Detail:    is.detail,
		DevKnown:  runtime != nil,
		Members:   []resolve.Member{},
		Edges:     []resolve.Edge{},
	}
	switch {
	case isUnknown(is.reason):
		r.Status = resolve.StatusUnknown
		r.DevKnown = false
		return r
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
