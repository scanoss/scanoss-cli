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

package sbom

import "slices"

// GraphStatus says how much of a root's dependency graph the lockfile gave.
type GraphStatus string

const (
	// GraphComplete means the root's edges are the lockfile's.
	GraphComplete GraphStatus = "complete"
	// GraphPartial means the graph is usable but missing something; Reason says what.
	GraphPartial GraphStatus = "partial"
	// GraphUnknown means the lockfile could not be read; the root has no edges and no members.
	GraphUnknown GraphStatus = "unknown"
)

// DependencyRoot is one manifest whose dependency graph was resolved from a lockfile, with dev
// members already left out. Direct lists the components the manifest declares as this root's
// lockfile resolved them; a manifest resolved by two lockfiles is two roots, each with its own
// versions, which evidence alone cannot tell apart since it names only the manifest. Edges run
// between component refs (see Component.Ref).
type DependencyRoot struct {
	Manifest  string           `json:"manifest"` // slash path of the manifest, relative to the project
	Lockfile  string           `json:"lockfile"` // slash path of the lockfile it was resolved from
	Ecosystem string           `json:"ecosystem"`
	Status    GraphStatus      `json:"status"`
	Reason    string           `json:"reason,omitempty"`
	Detail    string           `json:"detail,omitempty"`
	DevKnown  bool             `json:"dev_known"` // the manifests said which dependencies are dev; false means every member is kept as runtime
	Direct    []string         `json:"direct"`    // refs of the components the manifest declares, sorted
	Edges     []DependencyEdge `json:"edges"`     // From depends on To; both ends are component refs
}

// DependencyEdge says that From depends on To.
type DependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Ref is the component's identifier in a dependency edge and in the SBOM formats (the CycloneDX
// bom-ref): its PURL with the version appended, or the bare PURL when it has none.
func (c Component) Ref() string {
	if c.Version != "" && c.Version != noAssertion {
		return c.Purl + "@" + c.Version
	}
	return c.Purl
}

// Ref identifies the root in the SBOM formats. A manifest can be resolved by more than one
// lockfile (package-lock.json and yarn.lock side by side), so the lockfile is part of it.
func (r DependencyRoot) Ref() string {
	return r.Manifest + "@" + r.Lockfile
}

// DirectMembers returns the refs of the components root declares, in the root's order. A ref
// that is not a component is dropped, as dependsOn drops such an edge end.
func (inv Inventory) DirectMembers(root DependencyRoot) []string {
	present := make(map[string]bool, len(inv.Components))
	for _, c := range inv.Components {
		present[c.Ref()] = true
	}
	refs := []string{}
	for _, ref := range root.Direct {
		if present[ref] {
			refs = append(refs, ref)
		}
	}
	return refs
}

// dependsOn returns, for every component ref, the sorted refs it depends on across every root.
// An edge end that is not a component is dropped: the components are the truth of what the
// document contains, and an edge into something absent (a hand-edited raw document) would make
// the rendered SBOM invalid. Every component gets an entry, empty when nothing is known to
// depend on it, so a writer can say "no dependencies" rather than stay silent.
func (inv Inventory) dependsOn() map[string][]string {
	out := make(map[string][]string, len(inv.Components))
	for _, c := range inv.Components {
		out[c.Ref()] = []string{}
	}
	for _, r := range inv.Dependencies {
		for _, e := range r.Edges {
			targets, ok := out[e.From]
			if _, toOK := out[e.To]; !ok || !toOK || slices.Contains(targets, e.To) {
				continue
			}
			out[e.From] = append(targets, e.To)
		}
	}
	for _, targets := range out {
		slices.Sort(targets)
	}
	return out
}
