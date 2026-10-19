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
// A root stands for one manifest: package.json, Cargo.toml, a workspace
// member's manifest and so on. Its members are the nodes it reaches, plus the
// nodes the lockfile lists under it that nothing reaches. Its edges run from
// node to node; the manifest itself is never an edge end. Member.Direct is the
// only signal that the manifest declares a package: a member that is not
// direct and has no incoming edge is unattributed.
//
// The graph describes the lockfile as written, so cycles are kept and callers
// decide what to drop. A root whose Status is not complete carries a Reason;
// an unknown root has no members and no edges. Every slice is sorted, so the
// same lockfile always gives the same graph.
package resolve

// NodeID is a versioned Package URL, such as "pkg:npm/express@4.19.2".
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
)

// Graph is the dependency graph of one or more lockfiles.
type Graph struct {
	Nodes []Node `json:"nodes"` // sorted by ID, unique
	Roots []Root `json:"roots"` // sorted by Manifest, then Lockfile
}

// Node is one package at one version.
type Node struct {
	ID      NodeID `json:"id"`
	PURL    string `json:"purl"` // versionless
	Version string `json:"version"`
}

// Root is the graph of one manifest, as resolved by one lockfile.
type Root struct {
	Manifest  string    `json:"manifest"` // slash path of the manifest this root stands for
	Lockfile  string    `json:"lockfile"` // slash path of the lockfile it was resolved from
	Ecosystem Ecosystem `json:"ecosystem"`
	Status    Status    `json:"status"`
	Reason    Reason    `json:"reason,omitempty"`
	Detail    string    `json:"detail,omitempty"` // free text that explains Reason
	Members   []Member  `json:"members"`          // sorted by ID, unique
	Edges     []Edge    `json:"edges"`            // sorted by From then To, unique, both ends are Members
}

// Member is a node that belongs to a root.
type Member struct {
	ID     NodeID `json:"id"`
	Direct bool   `json:"direct"` // declared by the manifest; false means only in the lockfile
}

// Edge says that From depends on To.
type Edge struct {
	From NodeID `json:"from"`
	To   NodeID `json:"to"`
}
