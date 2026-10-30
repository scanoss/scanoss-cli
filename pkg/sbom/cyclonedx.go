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

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// scanossURLHashProp is the CycloneDX component property carrying the scanoss url_hash
// (a CRC64), which has no standard CycloneDX hash algorithm.
const scanossURLHashProp = "scanoss:url_hash"

// scanossIdentifiedProp is the CycloneDX component property marking a component the user's
// settings declared present (bom.identify). CycloneDX has no field for it, and SPDX has nowhere
// to put it at all — the raw output is where it is stated plainly.
const scanossIdentifiedProp = "scanoss:identified"

// scanossLocalProp marks a component that is the project's own package rather than a third-party
// one. CycloneDX has no field for the distinction; a reader skipping it lists third-party packages.
const scanossLocalProp = "scanoss:local"

// scanossLockfileProp names, on a dependency root component, the lockfile its graph came from.
// It is also what tells a root apart from a package when the document is read back.
const scanossLockfileProp = "scanoss:lockfile"

// scanossReasonProp carries why a root's graph is not complete; compositions say that it is not,
// but have no field for the reason.
const scanossReasonProp = "scanoss:reason"

// buildCycloneDX renders the inventory as a CycloneDX 1.7 JSON document using the
// official cyclonedx-go encoder, whose version-aware serialization keeps the output
// schema-valid.
func buildCycloneDX(inv Inventory, o options) (string, error) {
	bom := cdx.NewBOM()
	// Every BOM should carry a serial number: it is what lets consumers tell two
	// documents apart, and tell a re-render of the same scan from a new one.
	bom.SerialNumber = "urn:uuid:" + uuid.NewString()
	bom.Metadata = &cdx.Metadata{
		Timestamp: o.resolvedTimestamp().Format(time.RFC3339),
		Authors:   &[]cdx.OrganizationalContact{{Name: o.author}},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    o.toolName,
				Version: o.toolVersion,
			}},
		},
		Component: &cdx.Component{
			// The bom-ref is what the dependency graph hangs the roots from, and it
			// is always set so a consumer can address the project either way.
			BOMRef:  o.projectName,
			Type:    cdx.ComponentTypeApplication,
			Name:    o.projectName,
			Version: noAssertion,
		},
	}

	comps := make([]cdx.Component, 0, len(inv.Components)+len(inv.Dependencies))
	for _, c := range inv.Components {
		comps = append(comps, cycloneDXComponent(c))
	}
	for _, r := range inv.Dependencies {
		comps = append(comps, cycloneDXRoot(r))
	}
	bom.Components = &comps

	if len(inv.Dependencies) > 0 {
		deps, compositions := cycloneDXGraph(inv, o.projectName)
		bom.Dependencies = &deps
		bom.Compositions = &compositions
	}

	if vulns := cycloneDXVulnerabilities(inv); len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	var buf bytes.Buffer
	enc := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_7); err != nil {
		return "", fmt.Errorf("error serializing CycloneDX document: %w", err)
	}
	return buf.String(), nil
}

func cycloneDXComponent(comp Component) cdx.Component {
	version := comp.Version
	if version == "" {
		version = noAssertion
	}
	purl := comp.Ref()

	c := cdx.Component{
		BOMRef:     purl,
		Type:       cdx.ComponentTypeLibrary,
		Name:       comp.DisplayName(),
		Version:    version,
		Publisher:  supplier(comp),
		PackageURL: purl,
	}

	if len(comp.Licenses) > 0 {
		var licenses cdx.Licenses
		for _, l := range comp.Licenses {
			lic := cycloneDXLicense(l)
			licenses = append(licenses, cdx.LicenseChoice{License: &lic})
		}
		c.Licenses = &licenses
	}

	if comp.URL != "" {
		c.ExternalReferences = &[]cdx.ExternalReference{
			{Type: cdx.ERTypeWebsite, URL: comp.URL},
		}
	}

	// A CycloneDX component carries a single purl. When a component has more than one,
	// record every purl in evidence.identity (the spec's field for identifying a
	// component by multiple identifiers), so the aliases aren't lost.
	occ := cycloneDXOccurrences(comp.Evidence)
	ids := purlIdentities(comp)
	if len(occ) > 0 || len(ids) > 0 {
		ev := &cdx.Evidence{}
		if len(occ) > 0 {
			ev.Occurrences = &occ
		}
		if len(ids) > 0 {
			ev.Identity = &cdx.EvidenceIdentityChoice{Identities: &ids}
		}
		c.Evidence = ev
	}

	// Preserve the scanoss url_hash (a CRC64) as a property — CycloneDX has no hash
	// algorithm for it — and the identify verdict, which it has no field for either.
	var props []cdx.Property
	if comp.URLHash != "" {
		props = append(props, cdx.Property{Name: scanossURLHashProp, Value: comp.URLHash})
	}
	if comp.Identified {
		props = append(props, cdx.Property{Name: scanossIdentifiedProp, Value: "true"})
	}
	if comp.Local {
		props = append(props, cdx.Property{Name: scanossLocalProp, Value: "true"})
	}
	if len(props) > 0 {
		c.Properties = &props
	}

	return c
}

// cycloneDXRoot renders a dependency root as an application component named by its manifest,
// the shape SBOM tools give a lockfile's project so the packages hang off something a reader
// can find. The lockfile and the reason travel as properties: compositions carry the status but
// have nowhere for either.
func cycloneDXRoot(r DependencyRoot) cdx.Component {
	props := []cdx.Property{{Name: scanossLockfileProp, Value: r.Lockfile}}
	if r.Reason != "" {
		props = append(props, cdx.Property{Name: scanossReasonProp, Value: r.Reason})
	}
	return cdx.Component{
		BOMRef:     r.Ref(),
		Type:       cdx.ComponentTypeApplication,
		Name:       r.Manifest,
		Properties: &props,
	}
}

// cycloneDXGraph renders the dependency graph: the project depends on every root, a root on the
// members its manifest declares, and a package on its edges. Every component gets an entry even
// when nothing depends on it, because in CycloneDX a missing entry means "unknown" while an
// entry with only a ref is the spec's empty element for "none". (The encoder writes an empty
// dependsOn in that form: its copy of the BOM goes through gob, which drops empty lists.)
//
// One composition per root states how complete that root's graph is, listing the root under
// compositions.dependencies: the spec's field for "the dependency relationships of these
// elements are complete/incomplete/unknown". Only the root is listed, since the assertion does
// not cascade and a package shared by a complete root and a partial one would otherwise get two
// contradicting assertions.
func cycloneDXGraph(inv Inventory, projectRef string) ([]cdx.Dependency, []cdx.Composition) {
	dependsOn := inv.dependsOn()
	deps := make([]cdx.Dependency, 0, len(inv.Components)+len(inv.Dependencies)+1)
	compositions := make([]cdx.Composition, 0, len(inv.Dependencies))

	roots := make([]string, 0, len(inv.Dependencies))
	for _, r := range inv.Dependencies {
		roots = append(roots, r.Ref())
	}
	deps = append(deps, cdx.Dependency{Ref: projectRef, Dependencies: &roots})

	for _, r := range inv.Dependencies {
		direct := inv.DirectMembers(r)
		deps = append(deps, cdx.Dependency{Ref: r.Ref(), Dependencies: &direct})
		compositions = append(compositions, cdx.Composition{
			Aggregate:    cycloneDXAggregate(r.Status),
			Dependencies: &[]cdx.BOMReference{cdx.BOMReference(r.Ref())},
		})
	}
	for _, c := range inv.Components {
		targets := dependsOn[c.Ref()]
		deps = append(deps, cdx.Dependency{Ref: c.Ref(), Dependencies: &targets})
	}
	return deps, compositions
}

// cycloneDXAggregate maps a root's status to the composition aggregate: a partial graph is
// usable but incomplete, an unreadable lockfile leaves the graph unknown.
func cycloneDXAggregate(s GraphStatus) cdx.CompositionAggregate {
	switch s {
	case GraphComplete:
		return cdx.CompositionAggregateComplete
	case GraphPartial:
		return cdx.CompositionAggregateIncomplete
	default:
		return cdx.CompositionAggregateUnknown
	}
}

// purlIdentities returns one purl evidence-identity per component PURL (with version
// appended), but only when the component has more than one PURL — a single PURL is
// already the component's canonical purl, so it needs no extra evidence.
func purlIdentities(comp Component) []cdx.EvidenceIdentity {
	purls := comp.AllPurls()
	if len(purls) < 2 {
		return nil
	}
	ids := make([]cdx.EvidenceIdentity, 0, len(purls))
	for _, p := range purls {
		value := p
		if comp.Version != "" && comp.Version != noAssertion {
			value = p + "@" + comp.Version
		}
		ids = append(ids, cdx.EvidenceIdentity{
			Field:          cdx.EvidenceIdentityFieldTypePURL,
			ConcludedValue: value,
		})
	}
	return ids
}

// cycloneDXLicense emits a license with its acknowledgement. The "id" field is an
// enum of the SPDX list in the schema, so only an identifier SPDX recognises may
// go there; anything else — a LicenseRef, a non-canonical id, an expression the
// API sent verbatim — goes to "name", which is free text. Putting an unrecognised
// value in "id" is what makes a document fail validation.
func cycloneDXLicense(l License) cdx.License {
	lic := cdx.License{Acknowledgement: cdxAcknowledgement(l.Acknowledgement)}
	canonical, ok := normalizeLicense(l.ID)
	switch {
	case ok && !isExpression(canonical) && !strings.HasPrefix(canonical, "LicenseRef-"):
		lic.ID = canonical
	case ok:
		// A valid expression, or a LicenseRef: both are legal here, but not in "id".
		lic.Name = canonical
	default:
		lic.Name = l.ID // unrecognised: keep what we were told, as free text
	}
	return lic
}

// cdxAcknowledgement maps a neutral acknowledgement to the CycloneDX enum, defaulting
// to declared.
func cdxAcknowledgement(ack LicenseAcknowledgement) cdx.LicenseAcknowledgement {
	if ack.resolved() == AckConcluded {
		return cdx.LicenseAcknowledgementConcluded
	}
	return cdx.LicenseAcknowledgementDeclared
}

// cycloneDXOccurrences turns matched files into evidence occurrences. Snippet matches
// carry the start line and the full matched ranges in additionalContext (CycloneDX
// occurrences have no native range field), followed by the classifier's verdict when the
// match was scored, since occurrences have no properties either. Transitive evidence is left out: the component
// does not occur in that manifest, its lockfile pulls it in, and the dependencies section is
// where that relationship is stated.
func cycloneDXOccurrences(files []FileEvidence) []cdx.EvidenceOccurrence {
	occurrences := make([]cdx.EvidenceOccurrence, 0, len(files))
	for _, f := range files {
		if f.MatchType == "transitive" {
			continue
		}
		o := cdx.EvidenceOccurrence{Location: f.Path}
		if f.MatchType == "snippet" {
			if len(f.InputLineRanges) > 0 {
				start := f.InputLineRanges[0].StartLine
				o.Line = &start
			}
			ctx := rangesContext(f.InputLineRanges, f.OssLineRanges)
			if cls := classificationContext(f.SnippetClassification); cls != "" {
				if ctx != "" {
					ctx += "; "
				}
				ctx += cls
			}
			o.AdditionalContext = ctx
		}
		occurrences = append(occurrences, o)
	}
	return occurrences
}

// rangesContext renders the matched line ranges as human-readable text, e.g.
// "input lines 12-48; oss lines 100-136". CycloneDX occurrences have no native range field,
// so this is the only place a range is rendered as text.
func rangesContext(input, oss []LineRange) string {
	var parts []string
	if len(input) > 0 {
		parts = append(parts, "input lines "+joinRanges(input))
	}
	if len(oss) > 0 {
		parts = append(parts, "oss lines "+joinRanges(oss))
	}
	return strings.Join(parts, "; ")
}

// classificationContext renders a snippet-classifier result as short, stable text, e.g.
// "classifier false_positive p=0.91 model=lr-d51f2e100211". It is "" for an unscored match.
func classificationContext(c *SnippetClassification) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("classifier %s p=%.2f model=%s", c.Verdict, c.Probability, c.ModelVersion)
}

// joinRanges renders ranges as a comma-separated "start-end" list.
func joinRanges(ranges []LineRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, strconv.Itoa(r.StartLine)+"-"+strconv.Itoa(r.EndLine))
	}
	return strings.Join(parts, ",")
}

// cycloneDXVulnerabilities emits one BOM-level vulnerability per inventory entry, with
// affects[] resolving to the bom-refs of components whose base PURL it lists.
func cycloneDXVulnerabilities(inv Inventory) []cdx.Vulnerability {
	if len(inv.Vulnerabilities) == 0 {
		return nil
	}

	// Indexed by versioned PURL first and bare PURL second, because an advisory names the version
	// it applies to whenever the source knew it. Resolving on the bare PURL alone would attach every
	// advisory to every version of that component — reporting vulnerabilities a release does not have.
	refsByPurl := make(map[string][]string, len(inv.Components)*2)
	for _, c := range inv.Components {
		ref := c.Ref()
		refsByPurl[ref] = append(refsByPurl[ref], ref)
		if ref != c.Purl {
			refsByPurl[c.Purl] = append(refsByPurl[c.Purl], ref)
		}
	}

	out := make([]cdx.Vulnerability, 0, len(inv.Vulnerabilities))
	for _, v := range inv.Vulnerabilities {
		cv := cdx.Vulnerability{ID: v.ID, Description: v.Summary}
		if v.Source != "" {
			cv.Source = &cdx.Source{Name: v.Source}
		}
		if rating := cycloneDXRating(v); rating != (cdx.VulnerabilityRating{}) {
			cv.Ratings = &[]cdx.VulnerabilityRating{rating}
		}
		if len(v.CWEs) > 0 {
			cwes := append([]int(nil), v.CWEs...)
			cv.CWEs = &cwes
		}
		// EPSS has no native CycloneDX field; carry it as a namespaced property.
		if v.EPSSScore != nil {
			cv.Properties = &[]cdx.Property{{Name: scanossEPSSProp, Value: strconv.FormatFloat(*v.EPSSScore, 'f', -1, 64)}}
		}
		if v.URL != "" {
			cv.Advisories = &[]cdx.Advisory{{URL: v.URL}}
		}

		var affects []cdx.Affects
		for _, purl := range v.Purls {
			for _, ref := range refsByPurl[purl] {
				affects = append(affects, cdx.Affects{Ref: ref})
			}
		}
		if len(affects) > 0 {
			cv.Affects = &affects
		}

		out = append(out, cv)
	}
	return out
}

// scanossEPSSProp is the CycloneDX vulnerability property carrying the EPSS score, which
// has no native CycloneDX field.
const scanossEPSSProp = "scanoss:epss_score"

// cycloneDXRating builds a single rating from the qualitative severity and any CVSS data.
// Returns the zero value when the vulnerability has neither, so no rating is emitted.
func cycloneDXRating(v Vulnerability) cdx.VulnerabilityRating {
	rating := cdx.VulnerabilityRating{Severity: mapSeverity(v.Severity)}
	if v.CVSSScore != nil {
		score := *v.CVSSScore
		rating.Score = &score
	}
	rating.Vector = v.CVSSVector
	if v.CVSSMethod != "" {
		rating.Method = cdx.ScoringMethod(v.CVSSMethod)
	}
	return rating
}

// mapSeverity maps a SCANOSS severity string to a CycloneDX severity. An empty input
// yields "" (no rating); an unrecognized value yields "unknown".
func mapSeverity(s string) cdx.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ""
	case "critical":
		return cdx.SeverityCritical
	case "high":
		return cdx.SeverityHigh
	case "medium", "moderate":
		return cdx.SeverityMedium
	case "low":
		return cdx.SeverityLow
	case "none":
		return cdx.SeverityNone
	case "info", "informational":
		return cdx.SeverityInfo
	default:
		return cdx.SeverityUnknown
	}
}
