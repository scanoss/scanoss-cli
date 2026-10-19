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

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ParseCycloneDX decodes a CycloneDX JSON document (any 1.x minor version the library
// accepts) into a neutral Inventory. It is the inverse of buildCycloneDX: components,
// licenses and vulnerabilities are mapped back. Fields outside the Inventory model — file
// evidence occurrences, hashes, component type — are not preserved (best-effort).
//
// The dependency graph is not read back: the dependencies and compositions sections are
// skipped, and so are the application components without a purl that stand for a lockfile
// root (ours, and the ones other SBOM tools write), which are not packages. Like match_index,
// the graph survives a round trip through the raw format only.
func ParseCycloneDX(data []byte) (Inventory, error) {
	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		return Inventory{}, fmt.Errorf("error decoding CycloneDX: %w", err)
	}

	var inv Inventory
	refToPurl := make(map[string]string)
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.Type == cdx.ComponentTypeApplication && c.PackageURL == "" {
				continue
			}
			comp := cycloneDXToComponent(c)
			if c.BOMRef != "" {
				refToPurl[c.BOMRef] = comp.Purl
			}
			inv.Components = append(inv.Components, comp)
		}
	}
	if bom.Vulnerabilities != nil {
		for _, v := range *bom.Vulnerabilities {
			inv.Vulnerabilities = append(inv.Vulnerabilities, cycloneDXToVulnerability(v, refToPurl))
		}
	}
	return inv, nil
}

// cycloneDXToComponent maps one CycloneDX component back to a neutral Component.
func cycloneDXToComponent(c cdx.Component) Component {
	version := normalizeAssertion(c.Version)

	// The writer stores the display name in Name and purl[@version] in PackageURL/BOMRef,
	// so the base PURL has to be recovered by stripping the version back off.
	purl := c.PackageURL
	if version != "" {
		purl = strings.TrimSuffix(purl, "@"+version)
	}
	if purl == "" {
		purl = c.Name
	}

	comp := Component{
		Purl:    purl,
		Vendor:  c.Publisher,
		Version: version,
	}

	if c.ExternalReferences != nil {
		for _, ref := range *c.ExternalReferences {
			if ref.Type == cdx.ERTypeWebsite {
				comp.URL = ref.URL
				break
			}
		}
	}

	if c.Licenses != nil {
		for _, lc := range *c.Licenses {
			if lc.License == nil {
				continue
			}
			id := lc.License.ID
			if id == "" {
				id = lc.License.Name
			}
			if id == "" {
				continue
			}
			comp.Licenses = append(comp.Licenses, License{
				ID:              id,
				Acknowledgement: fromCDXAcknowledgement(lc.License.Acknowledgement),
			})
		}
	}

	if c.Properties != nil {
		for _, p := range *c.Properties {
			switch p.Name {
			case scanossURLHashProp:
				comp.URLHash = p.Value
			case scanossLocalProp:
				comp.Local = p.Value == "true"
			}
		}
	}

	comp.AliasPurls = cycloneDXAliasPurls(c, purl, version)
	return comp
}

// cycloneDXAliasPurls recovers secondary PURLs from evidence.identity (the writer records
// every PURL there when a component has more than one), excluding the canonical PURL.
func cycloneDXAliasPurls(c cdx.Component, canonical, version string) []string {
	if c.Evidence == nil || c.Evidence.Identity == nil || c.Evidence.Identity.Identities == nil {
		return nil
	}
	var aliases []string
	for _, id := range *c.Evidence.Identity.Identities {
		if id.Field != cdx.EvidenceIdentityFieldTypePURL {
			continue
		}
		p := id.ConcludedValue
		if version != "" {
			p = strings.TrimSuffix(p, "@"+version)
		}
		if p != "" && p != canonical {
			aliases = append(aliases, p)
		}
	}
	return aliases
}

// cycloneDXToVulnerability maps one CycloneDX vulnerability back to a neutral
// Vulnerability, resolving affects[].ref (a bom-ref = purl[@version]) to base PURLs.
func cycloneDXToVulnerability(v cdx.Vulnerability, refToPurl map[string]string) Vulnerability {
	vuln := Vulnerability{ID: v.ID, Summary: v.Description}
	if v.Source != nil {
		vuln.Source = v.Source.Name
	}
	if v.Ratings != nil && len(*v.Ratings) > 0 {
		r := (*v.Ratings)[0]
		vuln.Severity = string(r.Severity)
		if r.Score != nil {
			score := *r.Score
			vuln.CVSSScore = &score
		}
		vuln.CVSSVector = r.Vector
		vuln.CVSSMethod = string(r.Method)
	}
	if v.CWEs != nil && len(*v.CWEs) > 0 {
		vuln.CWEs = append([]int(nil), (*v.CWEs)...)
	}
	if v.Properties != nil {
		for _, p := range *v.Properties {
			if p.Name == scanossEPSSProp {
				if f, err := strconv.ParseFloat(p.Value, 64); err == nil {
					vuln.EPSSScore = &f
				}
			}
		}
	}
	if v.Advisories != nil && len(*v.Advisories) > 0 {
		vuln.URL = (*v.Advisories)[0].URL
	}
	if v.Affects != nil {
		for _, a := range *v.Affects {
			purl := refToPurl[a.Ref]
			if purl == "" {
				purl = a.Ref
			}
			if !containsPurl(vuln.Purls, purl) {
				vuln.Purls = append(vuln.Purls, purl)
			}
		}
	}
	return vuln
}

// fromCDXAcknowledgement maps the CycloneDX acknowledgement enum to the neutral one,
// defaulting to declared.
func fromCDXAcknowledgement(a cdx.LicenseAcknowledgement) LicenseAcknowledgement {
	if a == cdx.LicenseAcknowledgementConcluded {
		return AckConcluded
	}
	return AckDeclared
}

// normalizeAssertion turns the SPDX/CycloneDX NOASSERTION placeholder back into "".
func normalizeAssertion(s string) string {
	if s == noAssertion {
		return ""
	}
	return s
}

// containsPurl reports whether purls already contains p.
func containsPurl(purls []string, p string) bool {
	for _, existing := range purls {
		if existing == p {
			return true
		}
	}
	return false
}
