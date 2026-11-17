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
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func sampleInventory() Inventory {
	return Inventory{
		Components: []Component{
			{
				Purl:     "pkg:github/scanoss/engine",
				Vendor:   "scanoss",
				Name:     "engine",
				Version:  "5.4.1",
				URL:      "https://github.com/scanoss/engine",
				Licenses: []License{{ID: "MIT", Acknowledgement: AckDeclared}, {ID: "Apache-2.0", Acknowledgement: AckDeclared}},
				URLHash:  "abc123",
				Evidence: []FileEvidence{
					{Path: "src/a.c", MatchType: "file"},
					{Path: "src/b.c", MatchType: "snippet", InputLineRanges: []LineRange{{StartLine: 12, EndLine: 48}}, OssLineRanges: []LineRange{{StartLine: 100, EndLine: 136}}},
				},
			},
			{
				Purl:     "pkg:npm/lodash",
				Version:  "4.17.21",
				Licenses: []License{{ID: "LicenseRef-scancode-unknown", Acknowledgement: AckDeclared}},
			},
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:       "CVE-2021-23337",
				Severity: "HIGH",
				Source:   "NVD",
				URL:      "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
				Summary:  "prototype pollution",
				Purls:    []string{"pkg:npm/lodash"},
			},
		},
	}
}

func decodeBOM(t *testing.T, s string) cdx.BOM {
	t.Helper()
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(strings.NewReader(s), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatalf("decode CycloneDX: %v", err)
	}
	return bom
}

func TestCycloneDX_AliasPurlsAsEvidenceIdentity(t *testing.T) {
	inv := Inventory{Components: []Component{{
		Purl:       "pkg:github/scanoss/scanoss.js",
		AliasPurls: []string{"pkg:npm/scanoss"},
		Version:    "1.3.0",
	}}}

	out, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("want 1 component")
	}
	c := (*bom.Components)[0]
	// canonical purl is the first, with version appended.
	if c.PackageURL != "pkg:github/scanoss/scanoss.js@1.3.0" {
		t.Errorf("purl = %q", c.PackageURL)
	}
	// all purls recorded as evidence.identity purl entries (standard CycloneDX).
	if c.Evidence == nil || c.Evidence.Identity == nil || c.Evidence.Identity.Identities == nil {
		t.Fatalf("want evidence.identity entries, got %+v", c.Evidence)
	}
	ids := *c.Evidence.Identity.Identities
	if len(ids) != 2 {
		t.Fatalf("want 2 identity entries, got %d: %+v", len(ids), ids)
	}
	for _, id := range ids {
		if id.Field != cdx.EvidenceIdentityFieldTypePURL {
			t.Errorf("identity field = %q, want purl", id.Field)
		}
	}
	if ids[0].ConcludedValue != "pkg:github/scanoss/scanoss.js@1.3.0" || ids[1].ConcludedValue != "pkg:npm/scanoss@1.3.0" {
		t.Errorf("identity purls = [%q, %q], want canonical then alias", ids[0].ConcludedValue, ids[1].ConcludedValue)
	}
	// no custom properties anymore.
	if c.Properties != nil {
		t.Errorf("expected no properties, got %+v", c.Properties)
	}
}

func TestCycloneDX_SpecAndMetadata(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX, WithProjectName("my-project"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)

	if bom.SpecVersion != cdx.SpecVersion1_7 {
		t.Errorf("specVersion = %v, want 1.7", bom.SpecVersion)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q", bom.BOMFormat)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatal("missing metadata component")
	}
	if got := bom.Metadata.Component.Name; got != "my-project" {
		t.Errorf("metadata component name = %q, want my-project", got)
	}
	if bom.Metadata.Component.Type != cdx.ComponentTypeApplication {
		t.Errorf("metadata component type = %q", bom.Metadata.Component.Type)
	}
	if bom.Metadata.Authors == nil || len(*bom.Metadata.Authors) != 1 || (*bom.Metadata.Authors)[0].Name != "SCANOSS" {
		t.Errorf("authors = %+v, want one SCANOSS", bom.Metadata.Authors)
	}
}

// scanoss/scanoss-cli#138: Grype keys Go vulnerabilities on the component name,
// so otel/sdk v1.45.0 (two known advisories) named "sdk" came out clean. The
// writer must name it by its module path.
func TestCycloneDX_GoComponentNamedByModulePath(t *testing.T) {
	var inv Inventory
	inv.Add(Component{
		Purl:    "pkg:golang/go.opentelemetry.io/otel/sdk",
		Version: "v1.45.0",
		Scope:   ScopeDeclared,
	})
	out, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Fatalf("want 1 component, got %v", bom.Components)
	}
	c := (*bom.Components)[0]
	if c.Name != "go.opentelemetry.io/otel/sdk" {
		t.Errorf("name = %q, want the full module path", c.Name)
	}
	if c.PackageURL != "pkg:golang/go.opentelemetry.io/otel/sdk@v1.45.0" {
		t.Errorf("purl = %q", c.PackageURL)
	}
}

func TestCycloneDX_Components(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	if bom.Components == nil || len(*bom.Components) != 2 {
		t.Fatalf("want 2 components, got %v", bom.Components)
	}
	c := (*bom.Components)[0]
	if c.Type != cdx.ComponentTypeLibrary {
		t.Errorf("type = %q, want library", c.Type)
	}
	// The name field holds a package name, not a PURL: the PURL has its own field
	// right below, and a consumer renders this one to a human.
	if c.Name != "engine" {
		t.Errorf("name = %q, want the component name", c.Name)
	}
	if c.PackageURL != "pkg:github/scanoss/engine@5.4.1" {
		t.Errorf("purl = %q, want @version appended", c.PackageURL)
	}
	if c.BOMRef != c.PackageURL {
		t.Errorf("bom-ref = %q, want = purl", c.BOMRef)
	}
	if c.Publisher != "scanoss" {
		t.Errorf("publisher = %q, want scanoss", c.Publisher)
	}
}

func TestCycloneDX_LicensesDeclared(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)

	first := (*bom.Components)[0]
	if first.Licenses == nil || len(*first.Licenses) != 2 {
		t.Fatalf("want 2 licenses, got %v", first.Licenses)
	}
	for _, lc := range *first.Licenses {
		if lc.License == nil {
			t.Fatal("license choice without license object")
		}
		if lc.License.Acknowledgement != cdx.LicenseAcknowledgementDeclared {
			t.Errorf("acknowledgement = %q, want declared", lc.License.Acknowledgement)
		}
		if lc.License.ID == "" {
			t.Errorf("standard SPDX license should use id, got name=%q", lc.License.Name)
		}
	}

	second := (*bom.Components)[1]
	lic := (*second.Licenses)[0].License
	if lic.Name != "LicenseRef-scancode-unknown" || lic.ID != "" {
		t.Errorf("LicenseRef should use name: name=%q id=%q", lic.Name, lic.ID)
	}

	// acknowledgement must appear (nested in the license object).
	if !strings.Contains(out, `"acknowledgement": "declared"`) {
		t.Error("expected declared acknowledgement in output")
	}
}

func TestCycloneDX_LicensesConcluded(t *testing.T) {
	inv := Inventory{Components: []Component{{
		Purl:    "pkg:github/test/proj",
		Version: "1.0.0",
		Licenses: []License{
			{ID: "GPL-2.0-only", Acknowledgement: AckDeclared},
			{ID: "GPL-2.0-only", Acknowledgement: AckConcluded},
			{ID: "3D-Slicer-1.0", Acknowledgement: AckConcluded},
		},
	}}}

	out, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)

	got := map[string]int{} // "id|ack" -> count
	for _, lc := range *(*bom.Components)[0].Licenses {
		got[lc.License.ID+"|"+string(lc.License.Acknowledgement)]++
	}
	for _, want := range []string{
		"GPL-2.0-only|declared",
		"GPL-2.0-only|concluded",
		"3D-Slicer-1.0|concluded",
	} {
		if got[want] != 1 {
			t.Errorf("want one %q license entry, got %d (all: %v)", want, got[want], got)
		}
	}
}

func TestCycloneDX_ExternalReferences(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	if refs := (*bom.Components)[0].ExternalReferences; refs == nil || len(*refs) != 1 || (*refs)[0].Type != cdx.ERTypeWebsite {
		t.Errorf("want one website external ref, got %v", (*bom.Components)[0].ExternalReferences)
	}
	if (*bom.Components)[1].ExternalReferences != nil {
		t.Error("component without URL should have no external references")
	}
}

func TestCycloneDX_FileEvidence(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	ev := (*bom.Components)[0].Evidence
	if ev == nil || ev.Occurrences == nil || len(*ev.Occurrences) != 2 {
		t.Fatalf("want 2 evidence occurrences, got %v", ev)
	}
	occ := *ev.Occurrences
	if occ[0].Location != "src/a.c" {
		t.Errorf("occurrence[0] location = %q", occ[0].Location)
	}
	snip := occ[1]
	if snip.Location != "src/b.c" {
		t.Errorf("occurrence[1] location = %q", snip.Location)
	}
	if snip.Line == nil || *snip.Line != 12 {
		t.Errorf("snippet line = %v, want 12", snip.Line)
	}
	if !strings.Contains(snip.AdditionalContext, "input lines 12-48") {
		t.Errorf("additionalContext = %q", snip.AdditionalContext)
	}
}

func TestCycloneDX_Vulnerabilities(t *testing.T) {
	out, err := Generate(sampleInventory(), FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability, got %v", bom.Vulnerabilities)
	}
	v := (*bom.Vulnerabilities)[0]
	if v.ID != "CVE-2021-23337" {
		t.Errorf("vuln id = %q", v.ID)
	}
	if v.Ratings == nil || (*v.Ratings)[0].Severity != cdx.SeverityHigh {
		t.Errorf("severity = %v, want high", v.Ratings)
	}
	if v.Affects == nil || len(*v.Affects) != 1 || (*v.Affects)[0].Ref != "pkg:npm/lodash@4.17.21" {
		t.Errorf("affects = %v, want lodash bom-ref", v.Affects)
	}
}

func TestCycloneDX_Empty(t *testing.T) {
	out, err := Generate(Inventory{}, FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bom := decodeBOM(t, out)
	if bom.Components != nil && len(*bom.Components) != 0 {
		t.Errorf("want no components, got %v", bom.Components)
	}
	if bom.Vulnerabilities != nil {
		t.Errorf("want no vulnerabilities, got %v", bom.Vulnerabilities)
	}
}

// affects[] must name the versions an advisory actually applies to. Resolving on the bare PURL
// attached every advisory to every release of a component, so a document reported CVEs against
// versions that were never vulnerable.
func TestCycloneDXAffectsOnlyTheAffectedVersions(t *testing.T) {
	purl := "pkg:github/denoland/deno"
	inv := Inventory{
		Components: []Component{
			{Purl: purl, Name: "deno", Version: "v1.24.0"},
			{Purl: purl, Name: "deno", Version: "v2.7.8"},
		},
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-27931", Purls: []string{purl + "@v1.24.0"}},
			{ID: "CVE-2023-0001", Purls: []string{purl + "@v1.24.0", purl + "@v2.7.8"}},
		},
	}

	doc, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(doc), &got); err != nil {
		t.Fatal(err)
	}

	for _, v := range got.Vulnerabilities {
		switch v.ID {
		case "CVE-2024-27931":
			if len(v.Affects) != 1 || v.Affects[0].Ref != purl+"@v1.24.0" {
				t.Errorf("%s affects %v, want only v1.24.0", v.ID, v.Affects)
			}
		case "CVE-2023-0001":
			if len(v.Affects) != 2 {
				t.Errorf("%s affects %d refs, want 2", v.ID, len(v.Affects))
			}
		}
	}
}

// CycloneDX has no field for the identify verdict, so it rides as a property alongside the
// url_hash. Both must survive together — the second must not overwrite the first.
func TestCycloneDXIdentifiedProperty(t *testing.T) {
	inv := Inventory{Components: []Component{
		{Purl: "pkg:npm/vue", Version: "2.6.14", URLHash: "abc123", Identified: true},
		{Purl: "pkg:npm/lodash", Version: "4.17.21", URLHash: "def456"},
	}}

	out, err := Generate(inv, FormatCycloneDX)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var doc struct {
		Components []struct {
			Purl       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, c := range doc.Components {
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		if props["scanoss:url_hash"] == "" {
			t.Errorf("%s lost its url_hash property", c.Purl)
		}
		wantIdentified := strings.Contains(c.Purl, "vue")
		if got := props["scanoss:identified"] == "true"; got != wantIdentified {
			t.Errorf("%s identified property = %v, want %v", c.Purl, got, wantIdentified)
		}
	}
}
