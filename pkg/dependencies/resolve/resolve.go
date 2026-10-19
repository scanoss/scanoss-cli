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

// Package resolve defines a dependency graph with edges, as resolved from a
// project's lockfiles. The parsers that build it live in sub-packages, such as
// resolve/lockfile.
//
// A node is one package at one version, identified by its versioned Package
// URL ("pkg:npm/express@4.19.2"). Nodes are shared by every root.
//
// A local node is one of the project's own packages, such as a workspace
// member or a path or link dependency, rather than one fetched from a registry
// or git. It appears only when something depends on it, and its edges are its
// own dependencies, so every root that reaches it reaches them too. A local
// package may have no version; its ID is then its versionless Package URL.
// Consumers that want third-party packages skip local nodes.
//
// A root stands for one manifest: package.json, Cargo.toml, a workspace
// member's manifest and so on. A local package that has a manifest is both a
// root, for its own dependencies, and a local node, for the roots that depend
// on it. A root's members are the nodes it reaches, plus the nodes the
// lockfile lists under it that nothing reaches. Its edges run from node to
// node; the manifest itself is never an edge end. Member.Direct is the
// only signal that the manifest declares a package: a member that is not
// direct and has no incoming edge is unattributed.
//
// A dev dependency is one the project needs only to develop it (tests, lint,
// build tooling), which its users never install. Member.Dev marks a member
// the root reaches only through its dev dependencies; a member that any
// runtime dependency reaches is not Dev, so the same node can be Dev in one
// root and not in another. Root.DevKnown says whether the manifests say which
// direct dependencies are dev. When it is false no member is Dev and a
// consumer must treat them all as runtime. An unattributed member is never
// Dev, and a local node's edges never include its own dev dependencies, since
// a dependent never installs them.
//
// The graph describes the lockfile as written, so cycles are kept and callers
// decide what to drop. A root whose Status is not complete carries a Reason;
// an unknown root has no members and no edges. Every slice is sorted, so the
// same lockfile always gives the same graph.
package resolve

// NodeID is a versioned Package URL, such as "pkg:npm/express@4.19.2", or
// the versionless one of a local package that has no version.
type NodeID string

// Ecosystem names the package ecosystem of a root. Its values match the
// Package URL type of the root's nodes.
type Ecosystem string

// Ecosystems.
const (
	EcosystemNPM      Ecosystem = "npm"
	EcosystemCargo    Ecosystem = "cargo"
	EcosystemGem      Ecosystem = "gem"
	EcosystemPyPI     Ecosystem = "pypi"
	EcosystemComposer Ecosystem = "composer"
	EcosystemNuGet    Ecosystem = "nuget"
	EcosystemMaven    Ecosystem = "maven"
	EcosystemGolang   Ecosystem = "golang"
)

// Status says how much of a root's graph is known.
type Status string

// Statuses.
const (
	// StatusComplete means the root's graph is the lockfile's graph.
	StatusComplete Status = "complete"
	// StatusPartial means the root's graph is usable but missing something;
	// Reason says what.
	StatusPartial Status = "partial"
	// StatusUnknown means the lockfile could not be read; the root has no
	// members and no edges.
	StatusUnknown Status = "unknown"
)

// Reason says why a root is not complete. It is empty if and only if the
// Status is complete. When several reasons apply, the one listed first below
// wins.
type Reason string

// Reasons for an unknown root.
const (
	ReasonMalformed          Reason = "malformed"
	ReasonUnsupportedVersion Reason = "unsupported_version"
	ReasonTooLarge           Reason = "too_large"
)

// Reasons for a partial root.
const (
	ReasonNodeLimit             Reason = "node_limit"
	ReasonEdgeLimit             Reason = "edge_limit"
	ReasonManifestMissing       Reason = "manifest_missing"
	ReasonManifestMalformed     Reason = "manifest_malformed"
	ReasonUnsupportedWorkspaces Reason = "unsupported_workspaces"
	ReasonUnresolvedDependency  Reason = "unresolved_dependency"
	ReasonInvalidEntry          Reason = "invalid_entry"
	// ReasonEdgesUnknown means the lockfile pins exact versions but records
	// no edges, such as gradle.lockfile, Pipfile.lock or go.mod: the members
	// are known and the edges are not, so a member that is not direct is
	// unattributed. It holds for every root of those formats, so it ranks
	// last and any other problem shows instead.
	ReasonEdgesUnknown Reason = "edges_unknown"
)

// Graph is the dependency graph of one or more lockfiles.
type Graph struct {
	Nodes []Node `json:"nodes"` // sorted by ID, unique
	Roots []Root `json:"roots"` // sorted by Manifest, then Lockfile
}

// Node is one package at one version.
type Node struct {
	ID      NodeID `json:"id"`
	PURL    string `json:"purl"`    // versionless
	Version string `json:"version"` // empty only for a local package without one
	// Local marks the project's own package (a workspace member, a path or
	// link dependency), not one fetched from a registry or git.
	Local bool `json:"local,omitempty"`
}

// Root is the graph of one manifest, as resolved by one lockfile.
type Root struct {
	Manifest  string    `json:"manifest"` // slash path of the manifest this root stands for
	Lockfile  string    `json:"lockfile"` // slash path of the lockfile it was resolved from
	Ecosystem Ecosystem `json:"ecosystem"`
	Status    Status    `json:"status"`
	Reason    Reason    `json:"reason,omitempty"`
	Detail    string    `json:"detail,omitempty"` // free text that explains Reason
	DevKnown  bool      `json:"devKnown"`         // the manifests say which direct dependencies are dev; false means no member is Dev
	Members   []Member  `json:"members"`          // sorted by ID, unique
	Edges     []Edge    `json:"edges"`            // sorted by From then To, unique, both ends are Members
}

// Member is a node that belongs to a root.
type Member struct {
	ID     NodeID `json:"id"`
	Direct bool   `json:"direct"`        // declared by the manifest; false means only in the lockfile
	Dev    bool   `json:"dev,omitempty"` // the root reaches it only through dev dependencies
}

// Edge says that From depends on To.
type Edge struct {
	From NodeID `json:"from"`
	To   NodeID `json:"to"`
}
