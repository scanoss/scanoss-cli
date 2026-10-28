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

// VerdictFalsePositive is the SnippetClassification verdict for a match whose reported ranges do
// not correspond.
const VerdictFalsePositive = "false_positive"

// RemoveFalsePositiveSnippets drops every snippet match the classifier proposed as a false
// positive, and returns how many it dropped. A component left with no evidence goes with them.
//
// Only that evidence is touched: file matches, declared and transitive evidence, snippet matches
// that were not scored or were scored real stay, and so does a match a bom.identify rule claimed,
// since a person already confirmed it. Because declared and transitive evidence always stays, a
// component the dependency graph names keeps an entry, so Dependencies never points at a removed
// component. Vulnerabilities do: an advisory names components by PURL, so a PURL that named only
// removed components is dropped from it, and an advisory left naming nothing is dropped too.
func (inv *Inventory) RemoveFalsePositiveSnippets() int {
	var removed int
	var gone []Component
	kept := inv.Components[:0]
	for _, c := range inv.Components {
		before := len(c.Evidence)
		c.Evidence = slices.DeleteFunc(c.Evidence, isFalsePositiveSnippet)
		removed += before - len(c.Evidence)
		if before > 0 && len(c.Evidence) == 0 {
			gone = append(gone, c)
			continue
		}
		kept = append(kept, c)
	}
	inv.Components = kept
	if len(gone) > 0 {
		inv.Vulnerabilities = pruneVulnerabilities(inv.Vulnerabilities, gone, inv.Components)
	}
	return removed
}

// isFalsePositiveSnippet reports whether e is a snippet match the classifier proposed as a false
// positive and no bom.identify rule claimed.
func isFalsePositiveSnippet(e FileEvidence) bool {
	return e.MatchType == "snippet" && !e.Identified &&
		e.SnippetClassification != nil && e.SnippetClassification.Verdict == VerdictFalsePositive
}

// pruneVulnerabilities removes from each advisory the PURLs that resolved to a removed component
// and to no remaining one, resolving as the SBOM formats do: by versioned ref or bare PURL. An
// advisory whose PURLs all went is dropped. A PURL that resolved to nothing before is left alone:
// it is not this filter's to judge.
func pruneVulnerabilities(vulns []Vulnerability, gone, remaining []Component) []Vulnerability {
	keys := func(comps []Component) map[string]bool {
		m := make(map[string]bool, len(comps)*2)
		for _, c := range comps {
			m[c.Ref()] = true
			m[c.Purl] = true
		}
		return m
	}
	goneKeys, liveKeys := keys(gone), keys(remaining)

	out := vulns[:0]
	for _, v := range vulns {
		had := len(v.Purls)
		v.Purls = slices.DeleteFunc(v.Purls, func(p string) bool { return goneKeys[p] && !liveKeys[p] })
		if had > 0 && len(v.Purls) == 0 {
			continue
		}
		out = append(out, v)
	}
	return out
}
