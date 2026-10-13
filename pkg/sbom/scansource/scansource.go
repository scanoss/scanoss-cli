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

// Package scansource adapts SCANOSS SDK values — a v3 scan result and the licenses,
// vulnerabilities, cryptography and geoprovenance decoration responses — into the
// neutral sbom.Inventory consumed by the sbom package. It is the only SBOM code that
// depends on the scan SDK; the sbom package itself stays SDK-free.
package scansource

import (
	"sort"
	"strings"

	scanossapi "github.com/scanoss/scanoss.api-sdk"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// InventoryOption tunes how a scan result is adapted.
type InventoryOption func(*inventoryOptions)

type inventoryOptions struct {
	identified func(path, urlHash string) bool
}

// WithIdentified supplies the verdict the BOM identify rules reached: given a scanned path and
// the url_hash of a component matched there, whether the user declared that component present.
// postprocess.Report.IsIdentified has exactly this shape.
//
// It is passed in rather than read off the result because the result's types come from the API
// SDK: they carry what the server said, and have nowhere to record a conclusion the client
// reached on its own. A function rather than a map so this package needs no type in common with
// whatever produced the verdict.
func WithIdentified(fn func(path, urlHash string) bool) InventoryOption {
	return func(o *inventoryOptions) { o.identified = fn }
}

// Inventory builds one from a v3 scan result. The deduplicated component catalog becomes the
// components; each component's matched files (joined by url_hash) become its file evidence. The
// version is taken from the component entry. Licenses and vulnerabilities are not populated here
// — they come from the decoration services (see Licenses, Vulnerabilities).
func Inventory(result *scanossapi.ScanResult, opts ...InventoryOption) sbom.Inventory {
	if result == nil {
		return sbom.Inventory{}
	}

	var o inventoryOptions
	for _, opt := range opts {
		opt(&o)
	}
	filesByHash := filesByURLHash(result.Files, o.identified)

	// Added in sorted url_hash order so that, when two catalog entries fold into one component,
	// which one's metadata it keeps does not depend on Go's random map iteration order. It is not
	// the order the components are reported in: see orderComponents.
	hashes := make([]string, 0, len(result.Components))
	for hash := range result.Components {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)

	// Added rather than appended: the catalog is keyed by url_hash, so two entries can carry the
	// same PURL at the same version. Add folds those into one component holding both sets of
	// evidence, which is what a consumer of the returned inventory expects to find.
	// Gathered first and added in one call: Add reindexes what the inventory already holds on
	// every call, so adding one at a time would be quadratic in the number of components.
	components := make([]sbom.Component, 0, len(hashes))
	for _, hash := range hashes {
		comp := result.Components[hash]
		if len(comp.Purls) == 0 || comp.Purls[0] == "" {
			continue
		}
		components = append(components, sbom.Component{
			Purl:         comp.Purls[0],
			Scope:        sbom.ScopeDetected,
			Identified:   anyIdentified(filesByHash[hash]),
			AliasPurls:   comp.Purls[1:],
			Vendor:       comp.Vendor,
			Name:         comp.Component,
			Version:      comp.Version,
			URL:          comp.Url,
			URLHash:      hash,
			Rank:         comp.Rank,
			ReleaseDate:  comp.ReleaseDate,
			ArtifactName: comp.File,
			Evidence:     filesByHash[hash],
		})
	}

	var inv sbom.Inventory
	inv.Add(components...)
	orderComponents(inv.Components)
	return inv
}

// Server maps a scan result's `server` block onto the neutral sbom.RawServer carried by the raw
// document. It returns nil when the report had no such block, so a scan against an API that emits
// none leaves the output unchanged.
//
// engine_version and knowledge_base_latest are not mapped: no released scanoss.api-sdk models them
// yet (its ScanServer carries only knowledge_base, api_version, hostname and elapsed_ms). When the
// SDK gains them, wire them here — sbom.RawServer already has the fields.
func Server(s *scanossapi.ScanServer) *sbom.RawServer {
	if s == nil {
		return nil
	}
	return &sbom.RawServer{
		KnowledgeBase: knowledgeBase(s.KnowledgeBase),
		APIVersion:    s.ApiVersion,
		Hostname:      s.Hostname,
		ElapsedMs:     s.ElapsedMs,
	}
}

// knowledgeBase maps the SDK's KnowledgeBase onto the neutral pair, returning nil when absent so an
// empty object is never emitted.
func knowledgeBase(kb *scanossapi.KnowledgeBase) *sbom.RawKnowledgeBase {
	if kb == nil {
		return nil
	}
	return &sbom.RawKnowledgeBase{
		MonthlyVersion: kb.MonthlyVersion,
		DailyVersion:   kb.DailyVersion,
	}
}

// orderComponents puts the components in the order a reader of the inventory would look for them:
// first the ones the most files originate from, then the ones that match the most files, and
// url_hash only to settle what is still tied.
//
// The count that leads is of primary matches — files where the component is the scanner's first
// candidate — because that is what the scanner says about where a file comes from. In a self-scan
// it puts the project itself first and its vendored dependencies after it, and leaves the forks
// and mirrors that redistribute the same files at the end: they match as many files, and are the
// origin of none. Ordering by url_hash alone, as this did before, placed them by an arbitrary CRC.
//
// Counted after the merge, so a component folded from several catalog entries is placed by all of
// its evidence. The url_hash tie-break is total: no two components share one.
func orderComponents(comps []sbom.Component) {
	type standing struct{ primary, files int }
	by := make(map[string]standing, len(comps))
	for _, c := range comps {
		s := standing{files: len(c.Evidence)}
		for _, e := range c.Evidence {
			if e.IsPrimary() {
				s.primary++
			}
		}
		by[c.URLHash] = s
	}
	sort.SliceStable(comps, func(i, j int) bool {
		a, b := by[comps[i].URLHash], by[comps[j].URLHash]
		if a.primary != b.primary {
			return a.primary > b.primary
		}
		if a.files != b.files {
			return a.files > b.files
		}
		return comps[i].URLHash < comps[j].URLHash
	})
}

// Key is the join key matching a decoration response entry to a component: its PURL plus
// the queried version (the decoration echoes the queried version back as `requirement`).
// It identifies a component at a version, so every per-component layer shares it — licenses
// and cryptography today — which is why it is named after none of them.
func Key(purl, version string) string {
	return purl + "\x00" + version
}

// Licenses maps a licenses decoration response into declared licenses keyed by
// Key(purl, requirement). Duplicate ids per key are dropped. (The decoration service has
// no declared/concluded distinction — its licenses are declared.)
func Licenses(resp *scanossapi.ComponentsLicenseResponse) map[string][]sbom.License {
	if resp == nil || resp.Components == nil {
		return nil
	}

	byKey := make(map[string][]sbom.License)
	seen := make(map[string]map[string]bool)
	for _, ci := range *resp.Components {
		if ci.Purl == nil || ci.Licenses == nil {
			continue
		}
		key := Key(*ci.Purl, strVal(ci.Requirement))
		if seen[key] == nil {
			seen[key] = make(map[string]bool)
		}
		for _, l := range *ci.Licenses {
			id := strVal(l.Id)
			if id == "" || seen[key][id] {
				continue
			}
			seen[key][id] = true
			byKey[key] = append(byKey[key], sbom.License{ID: id, Acknowledgement: sbom.AckDeclared})
		}
	}
	return byKey
}

// Cryptography maps a cryptography-algorithms decoration response into algorithms keyed by
// Key(purl, requirement).
func Cryptography(resp *scanossapi.CryptoAlgorithmsResponse) map[string][]sbom.CryptoAlgorithm {
	if resp == nil {
		return nil
	}
	byKey := make(map[string][]sbom.CryptoAlgorithm)
	for _, ci := range resp.Components {
		if ci.Purl == nil || ci.Algorithms == nil {
			continue
		}
		key := Key(*ci.Purl, strVal(ci.Requirement))
		for _, a := range *ci.Algorithms {
			name := strVal(a.Algorithm)
			if name == "" {
				continue
			}
			byKey[key] = append(byKey[key], sbom.CryptoAlgorithm{Algorithm: name, Strength: strVal(a.Strength)})
		}
	}
	return byKey
}

// Geoprovenance maps a geoprovenance-origin decoration response into contributor locations
// keyed by PURL (the response carries no requirement to join on).
func Geoprovenance(resp *scanossapi.GeoOriginResponse) map[string][]sbom.GeoLocation {
	if resp == nil {
		return nil
	}
	byPurl := make(map[string][]sbom.GeoLocation)
	for _, cl := range resp.ComponentsLocations {
		if cl.Purl == nil || cl.Locations == nil {
			continue
		}
		for _, loc := range *cl.Locations {
			name := strVal(loc.Name)
			if name == "" {
				continue
			}
			g := sbom.GeoLocation{Name: name}
			if loc.Percentage != nil {
				g.Percentage = float64(*loc.Percentage)
			}
			byPurl[*cl.Purl] = append(byPurl[*cl.Purl], g)
		}
	}
	return byPurl
}

// Vulnerabilities maps a vulnerabilities decoration response into neutral
// vulnerabilities, deduplicated by id (falling back to the CVE), accumulating the
// affected component PURLs.
func Vulnerabilities(resp *scanossapi.VulnerabilitiesResponse) []sbom.Vulnerability {
	if resp == nil {
		return nil
	}

	byID := make(map[string]*sbom.Vulnerability)
	var order []string

	for _, ci := range resp.Components {
		if ci.Purl == nil || ci.Vulnerabilities == nil {
			continue
		}
		// The version this entry answers for, not the bare PURL. The service reports per version —
		// asked about two releases of the same component it returned 43 advisories for one and 14
		// for the other — so dropping it and keying on the PURL alone imputes every advisory to
		// every version of that component.
		purl := *ci.Purl
		if version := strVal(ci.Version); version != "" {
			purl += "@" + version
		} else if req := strVal(ci.Requirement); req != "" {
			purl += "@" + req
		}
		for _, v := range *ci.Vulnerabilities {
			id := strVal(v.Id)
			if id == "" {
				id = strVal(v.Cve)
			}
			if id == "" {
				continue
			}

			if existing, ok := byID[id]; ok {
				if !containsString(existing.Purls, purl) {
					existing.Purls = append(existing.Purls, purl)
				}
				continue
			}

			vuln := &sbom.Vulnerability{
				ID:       id,
				Severity: strings.ToLower(strVal(v.Severity)),
				URL:      strVal(v.Url),
				Summary:  strVal(v.Summary),
				Purls:    []string{purl},
			}
			if v.Source != nil {
				vuln.Source = string(*v.Source)
			}
			byID[id] = vuln
			order = append(order, id)
		}
	}

	out := make([]sbom.Vulnerability, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// filesByURLHash groups matched files (file/snippet) by component url_hash, emitting one
// evidence per match, sorted by path for deterministic output.
//
// Grouping by component is what loses each file's candidate order — the scanner lists a file's
// matches origin first, then the components that redistribute it — so every evidence records
// where its match stood in that list (FileEvidence.MatchIndex).
//
// identified, when non-nil, says which of those matches the user declared present. It is asked
// per (path, url_hash) because that is the granularity a path-scoped bom.identify rule works at:
// the same component can be declared in the files under "vendor/" and not in the ones outside.
func filesByURLHash(files []scanossapi.FileResult, identified func(path, urlHash string) bool) map[string][]sbom.FileEvidence {
	byHash := make(map[string][]sbom.FileEvidence)
	for _, f := range files {
		if f.MatchType == "" || f.MatchType == "none" {
			continue
		}
		for i, m := range f.Matches {
			ev := sbom.FileEvidence{
				Path:            f.Path,
				SourceHash:      f.SourceHash,
				FileHash:        f.FileHash,
				MatchType:       string(f.MatchType),
				MatchPercentage: m.MatchPercentage,
				Confidence:      string(m.Confidence),
				OssFilePath:     m.OssFilePath,
				InputLineRanges: lineRanges(m.InputLineRanges),
				OssLineRanges:   lineRanges(m.OssLineRanges),
				MatchIndex:      &i,
			}
			if identified != nil {
				ev.Identified = identified(f.Path, m.UrlHash)
			}
			byHash[m.UrlHash] = append(byHash[m.UrlHash], ev)
		}
	}
	for hash := range byHash {
		evs := byHash[hash]
		// Stable, so a file that lists one component more than once keeps those in its own order.
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Path < evs[j].Path })
	}
	return byHash
}

// anyIdentified reports whether the user declared this component present in any of the files it
// matched. It is how Component.Identified stays a summary of the evidence rather than a second,
// independently-computed answer that could disagree with it.
func anyIdentified(evidence []sbom.FileEvidence) bool {
	for _, e := range evidence {
		if e.Identified {
			return true
		}
	}
	return false
}

// lineRanges maps the scan result's line ranges onto the inventory's own type, or nil when
// there are none.
func lineRanges(ranges []scanossapi.LineRange) []sbom.LineRange {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]sbom.LineRange, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, sbom.LineRange{StartLine: r.StartLine, EndLine: r.EndLine})
	}
	return out
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
