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

// Package sbom generates SBOM documents (CycloneDX, SPDX Lite) from a neutral
// inventory of components. It depends on the CycloneDX and SPDX libraries — never on
// the scan SDK — so it can be reused by the CLI and by external consumers alike. Adapters
// that build an Inventory from a scan result live in the scansource subpackage.
package sbom

import (
	"slices"
	"strings"
)

// Inventory is the neutral, format-agnostic bill of materials and the core of the CLI's raw
// output. Detected components (scan matches) and declared dependency components live in ONE
// Components list, tagged by Component.Scope, so enrichment decorates the union origin-agnostic.
// Per-component layers (licenses, cryptography, geoprovenance) attach inline on each component;
// vulnerabilities are a flat top-level list joined to components by base PURL. Build it directly,
// or via the scansource and depsource adapters from a scan result or a project's dependency
// files. Add components through Add to keep one entry per component when more than one origin
// reports the same one.
//
// Dependencies is the dependency graph the lockfiles resolved, one root per manifest, with dev
// members already left out. Which components a root reaches, and whether directly, is on the
// components' evidence (see FileEvidence.MatchType); the root carries its edges.
type Inventory struct {
	Components      []Component      `json:"components"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty"`
	Dependencies    []DependencyRoot `json:"dependencies,omitempty"`
}

// Add appends comps, folding any that shares an identity (Purl and Version) with a component
// already present rather than listing it twice: the evidence lists are combined, and a detected
// component wins over a declared one — scope and metadata both. A component both matched by a scan and declared in a manifest is one
// component, detected, carrying its file matches and its manifest occurrence together. An empty
// Scope counts as detected, as the field documents.
//
// The inventory takes its own copy of each component's evidence, so what it holds is not the
// caller's to change afterwards — and two inventories seeded from one Component value cannot
// grow into each other's memory.
//
// It is how the inventory keeps one entry per component. Appending to Components directly still
// works, and leaves the caller to answer what two entries for one component mean.
func (inv *Inventory) Add(comps ...Component) {
	index := make(map[string]int, len(inv.Components)+len(comps))
	for i, existing := range inv.Components {
		index[componentKey(existing)] = i
	}
	for _, c := range comps {
		key := componentKey(c)
		if i, ok := index[key]; ok {
			mergeComponent(&inv.Components[i], c)
			continue
		}
		index[key] = len(inv.Components)
		c.Evidence = slices.Clone(c.Evidence)
		inv.Components = append(inv.Components, c)
	}
}

// componentKey is a component's identity: the same PURL at the same version is the same
// component, whichever origin reported it.
func componentKey(c Component) string { return c.Purl + "@" + c.Version }

// mergeComponent folds src into dst, which share an identity. Detected wins over
// declared as a whole, not just the scope tag: a declared entry carries nothing
// but its identity and its manifest occurrence, so when a detected src arrives
// its metadata (name, vendor, url, licenses, …) replaces dst's empty fields.
// Evidence from both origins is kept either way, and so are Identified and Local.
func mergeComponent(dst *Component, src Component) {
	// Identified and Local are statements about the component, not about either origin's view
	// of it: a user who declared it present declared it once, and a project's own package stays
	// its own when the scan also matches it. Both survive whichever way the merge goes,
	// including the wholesale replacement below.
	identified := dst.Identified || src.Identified
	local := dst.Local || src.Local

	if effectiveScope(*dst) == ScopeDeclared && effectiveScope(src) == ScopeDetected {
		src.Evidence = addEvidence(dst.Evidence, src.Evidence...)
		*dst = src
		dst.Scope = ScopeDetected // src's zero scope must not render as ""
	} else {
		dst.Evidence = addEvidence(dst.Evidence, src.Evidence...)
	}
	dst.Identified = identified
	dst.Local = local
}

// effectiveScope resolves the zero value to what the field documents it to mean.
func effectiveScope(c Component) ComponentScope {
	if c.Scope == "" {
		return ScopeDetected
	}
	return c.Scope
}

// addEvidence appends the occurrences not already recorded. Two occurrences are the same when
// they name the same path with the same match type.
//
// A duplicate is dropped rather than appended, but its Identified claim is not: two entries for
// one path can reach here from different origins, and the file was either claimed or it was not.
//
// When both carry a MatchIndex — two url_hashes of one component that matched the same file — the
// one that stood first in the file's candidate list is kept, whole: the merged component stands
// where its best-placed release stood, and the match details kept are that release's. Which of
// them arrived first does not decide it, so neither does the order components are added in.
func addEvidence(dst []FileEvidence, add ...FileEvidence) []FileEvidence {
	for _, e := range add {
		dup := false
		for i, existing := range dst {
			if existing.Path == e.Path && existing.MatchType == e.MatchType {
				identified := existing.Identified || e.Identified
				if lowerMatchIndex(e.MatchIndex, existing.MatchIndex) {
					dst[i] = e
				}
				dst[i].Identified = identified
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, e)
		}
	}
	return dst
}

// Component is one component in the inventory: identity, scope, scan evidence, and the
// per-component enrichment layers attached inline. Vulnerabilities are not stored here — they
// are the Inventory's flat top-level list, joined back by PURL.
type Component struct {
	Purl             string            `json:"purl"`                        // canonical PURL (identity), e.g. "pkg:github/scanoss/engine"
	Scope            ComponentScope    `json:"scope,omitempty"`             // detected (from the scan) | declared (from a manifest); "" == detected
	Identified       bool              `json:"identified,omitempty"`        // a bom.identify rule claimed this component for at least one of its files (see FileEvidence.Identified for which)
	Local            bool              `json:"local,omitempty"`             // the project's own package (a workspace member, a path or link dependency), not a third-party one
	AliasPurls       []string          `json:"alias_purls,omitempty"`       // additional PURLs identifying the same component (beyond Purl)
	Vendor           string            `json:"vendor,omitempty"`            // supplier / namespace
	Name             string            `json:"name,omitempty"`              // component name
	Version          string            `json:"version,omitempty"`           // resolved version; "" renders as "NOASSERTION"
	URL              string            `json:"url,omitempty"`               // homepage / source URL ("" => no externalReference)
	URLHash          string            `json:"url_hash,omitempty"`          // SCANOSS url_hash (SPDX package checksum)
	Rank             int               `json:"rank,omitempty"`              // engine match ordering; lower is a stronger match
	ReleaseDate      string            `json:"release_date,omitempty"`      // release date of Version (YYYY-MM-DD)
	ArtifactName     string            `json:"artifact_name,omitempty"`     // release artifact holding this version, e.g. "v0.38.0.zip"
	Licenses         []License         `json:"licenses,omitempty"`          // declared and/or concluded licenses (licenses layer)
	Cryptography     []CryptoAlgorithm `json:"cryptography,omitempty"`      // cryptographic algorithms detected (crypto layer)
	Geoprovenance    []GeoLocation     `json:"geoprovenance,omitempty"`     // contributor geographic origin (geo layer)
	DownloadLocation string            `json:"download_location,omitempty"` // download location (defaults to URL)
	Evidence         []FileEvidence    `json:"evidence,omitempty"`          // where the component came from: scanned files that matched, or the manifest that declared it
}

// CryptoAlgorithm is a cryptographic algorithm detected in a component (crypto layer).
type CryptoAlgorithm struct {
	Algorithm string `json:"algorithm"`
	Strength  string `json:"strength,omitempty"`
}

// GeoLocation is one geographic origin of a component's contributors (geo layer), with the
// share of contribution when known.
type GeoLocation struct {
	Name       string  `json:"name"`
	Percentage float64 `json:"percentage,omitempty"`
}

// ComponentScope records how a component entered the inventory.
type ComponentScope string

const (
	// ScopeDetected marks a component found by the scan (an OSS match). The zero value is
	// treated as detected.
	ScopeDetected ComponentScope = "detected"
	// ScopeDeclared marks a component declared in a dependency manifest.
	ScopeDeclared ComponentScope = "declared"
)

// DisplayName is the component's name for an SBOM package entry.
//
// Detected components carry Name from the scan result; declared ones (sourced
// from a manifest) carry only a PURL, so the name is taken from its last
// segment — "pkg:golang/github.com/spf13/cobra" yields "cobra". Falling back to
// the whole PURL would put "pkg:golang/github.com/spf13/cobra" in a field that
// consumers render as a package name.
func (c Component) DisplayName() string {
	if c.Name != "" {
		return c.Name
	}
	name := c.Purl
	if i := strings.LastIndex(name, "/"); i >= 0 && i+1 < len(name) {
		name = name[i+1:]
	}
	if name == "" {
		return c.Purl // nothing better to offer
	}
	return name
}

// IsDeclared reports whether the component is a declared dependency rather than a
// scan-detected match. The zero-value scope counts as detected.
func (c Component) IsDeclared() bool {
	return c.Scope == ScopeDeclared
}

// AllPurls returns the canonical Purl followed by any AliasPurls.
func (c Component) AllPurls() []string {
	if c.Purl == "" {
		return nil
	}
	return append([]string{c.Purl}, c.AliasPurls...)
}

// LicenseAcknowledgement is how a license was established for a component.
type LicenseAcknowledgement string

const (
	// AckDeclared marks a license stated by the project (from the decoration service).
	AckDeclared LicenseAcknowledgement = "declared"
	// AckConcluded marks a license determined by review (e.g. from a downstream consumer's identifications).
	AckConcluded LicenseAcknowledgement = "concluded"
)

// resolved settles the zero value: a license with no acknowledgement was stated by the project,
// so it counts as declared. Every writer needs this before it can compare or translate an
// acknowledgement, which is why the rule lives here rather than in each of them.
func (a LicenseAcknowledgement) resolved() LicenseAcknowledgement {
	if a == AckConcluded {
		return AckConcluded
	}
	return AckDeclared
}

// License is a single license on a component, with its acknowledgement. The same id may
// appear more than once (e.g. both declared and concluded).
type License struct {
	ID              string                 `json:"id"`                        // SPDX id or "LicenseRef-*", e.g. "GPL-2.0-only"
	Acknowledgement LicenseAcknowledgement `json:"acknowledgement,omitempty"` // declared (default) | concluded
}

// LineRange is a matched line range (inclusive) within a file. It mirrors the shape the scan
// engine reports, so ranges travel from the scan result to the SBOM writers without being
// encoded to text and parsed back.
type LineRange struct {
	StartLine int `json:"start_line"` // first line of the matched range
	EndLine   int `json:"end_line"`   // last line of the matched range
}

// FileEvidence is one occurrence of a component in the scanned project (a CycloneDX
// evidence.occurrence): a scanned file that matched (match_type "file"/"snippet", with — for
// snippets — where and how strongly it matched inside the OSS component), the manifest that
// declared it (match_type "declared", with only the path set), or the manifest whose lockfile
// pulls it in through another dependency (match_type "transitive", path set the same way).
type FileEvidence struct {
	Path            string      `json:"path"`                        // occurrence location: scanned file path, or the manifest path for a declared or transitive dependency
	SourceHash      string      `json:"source_hash,omitempty"`       // hash of the scanned input file (from the WFP)
	FileHash        string      `json:"file_hash,omitempty"`         // hash of the matched file (== source_hash for a file match; the OSS file's for a snippet)
	MatchType       string      `json:"match_type,omitempty"`        // "file" (whole file) | "snippet" | "declared" (the manifest declares it) | "transitive" (the manifest's lockfile pulls it in)
	Identified      bool        `json:"identified,omitempty"`        // a bom.identify rule claimed this component for this file
	MatchPercentage int         `json:"match_percentage,omitempty"`  // match confidence (snippet only)
	Confidence      string      `json:"confidence,omitempty"`        // attribution reliability grade: LOW, MEDIUM or HIGH
	OssFilePath     string      `json:"oss_file_path,omitempty"`     // matched file path inside the OSS component
	InputLineRanges []LineRange `json:"input_line_ranges,omitempty"` // matched line ranges in the scanned file (snippet only)
	OssLineRanges   []LineRange `json:"oss_line_ranges,omitempty"`   // matched line ranges in the OSS component (snippet only)

	// MatchIndex is where this component stood among the candidates the scan returned for this
	// file, after the BOM rules: 0 is the file's primary match — the component the file
	// originates from — and the ones after it redistribute it (forks, mirrors, packagings,
	// projects that vendor it). Nil when there is no candidate list to stand in: declared
	// evidence, or a document written before the field existed.
	//
	// It is the only place a file's candidate order survives. A component's evidence is sorted
	// by path and the components are not in any file's order, so a consumer rebuilding "the
	// candidates of this file" ranks them by this field, not by where it found them.
	MatchIndex *int `json:"match_index,omitempty"`
}

// IsPrimary reports whether this evidence is its file's primary match (MatchIndex 0).
func (e FileEvidence) IsPrimary() bool {
	return e.MatchIndex != nil && *e.MatchIndex == 0
}

// lowerMatchIndex reports whether a stood ahead of b in their file's candidate list. A known
// position beats an unknown one, so a merge never trades a position for its absence.
func lowerMatchIndex(a, b *int) bool {
	if a == nil {
		return false
	}
	return b == nil || *a < *b
}

// Vulnerability is one known vulnerability affecting one or more components, in a
// format independent of any decoration API wire type.
type Vulnerability struct {
	ID       string   `json:"id"`                 // advisory/CVE id, e.g. "CVE-2021-1234"
	Severity string   `json:"severity,omitempty"` // critical|high|medium|low|none|"" (case-insensitive)
	Source   string   `json:"source,omitempty"`   // advisory source name, e.g. "NVD"
	URL      string   `json:"url,omitempty"`      // advisory URL (optional)
	Summary  string   `json:"summary,omitempty"`  // short description (optional)
	Purls    []string `json:"purls,omitempty"`    // PURLs of the affected components, versioned when the source says which version

	// Optional quantitative scoring. All fields are optional: when unset they are not
	// rendered, and the output is identical to a severity-only vulnerability.
	CVSSScore  *float64 `json:"cvss_score,omitempty"`  // CVSS base score 0.0–10.0
	CVSSVector string   `json:"cvss_vector,omitempty"` // CVSS vector string, e.g. "CVSS:3.1/AV:N/..."
	CVSSMethod string   `json:"cvss_method,omitempty"` // CVSS scoring method, e.g. "CVSSv31"
	CWEs       []int    `json:"cwes,omitempty"`        // CWE ids, e.g. [77]
	EPSSScore  *float64 `json:"epss_score,omitempty"`  // EPSS probability 0.0–1.0 (no native CycloneDX field; emitted as a property)
}

// Format is a supported SBOM output format.
type Format string

const (
	// FormatCycloneDX selects CycloneDX JSON output.
	FormatCycloneDX Format = "cyclonedx"
	// FormatSPDX selects SPDX 2.3 (Lite field subset) JSON output.
	FormatSPDX Format = "spdx"
)

// noAssertion is the SPDX/CycloneDX placeholder for unknown values.
const noAssertion = "NOASSERTION"

// supplier returns the component vendor, or the namespace extracted from the PURL,
// falling back to NOASSERTION.
func supplier(comp Component) string {
	if comp.Vendor != "" {
		return comp.Vendor
	}
	if ns := purlNamespace(comp.Purl); ns != "" {
		return ns
	}
	return noAssertion
}

// purlNamespace extracts the namespace from a PURL string.
// e.g. "pkg:github/scanoss/scanner.c" -> "scanoss".
func purlNamespace(purl string) string {
	idx := strings.Index(purl, "/")
	if idx < 0 {
		return ""
	}
	rest := purl[idx+1:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx < 0 {
		return ""
	}
	return rest[:slashIdx] // scoped npm "@scope" is returned as-is
}
