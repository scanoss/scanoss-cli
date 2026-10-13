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

package cmd

import (
	"strings"
	"testing"

	scanossapi "github.com/scanoss/scanoss.api-sdk"
	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

func testScanResult() *scanossapi.ScanResult {
	return &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{Path: "a.go", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h1"}}},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:npm/lodash"}, Vendor: "lodash", Version: "4.17.20"},
		},
	}
}

// sampleInventory is a gathered inventory (a detected component with a license, plus a
// vulnerability) used to exercise renderInventory independently of the pipeline.
func sampleInventory() sbom.Inventory {
	return sbom.Inventory{
		Components: []sbom.Component{{
			Purl:     "pkg:npm/lodash",
			Scope:    sbom.ScopeDetected,
			Name:     "lodash",
			Version:  "4.17.20",
			Licenses: []sbom.License{{ID: "MIT", Acknowledgement: sbom.AckDeclared}},
		}},
		Vulnerabilities: []sbom.Vulnerability{
			{ID: "CVE-2021-23337", Severity: "high", Source: "NVD", Purls: []string{"pkg:npm/lodash"}},
		},
	}
}

func TestRenderInventory_Raw(t *testing.T) {
	out, err := renderInventory(sampleInventory(), "raw", "proj", nil)
	if err != nil {
		t.Fatalf("renderInventory: %v", err)
	}
	if !strings.Contains(out, `"schema_version"`) || !strings.Contains(out, `"metadata"`) {
		t.Errorf("raw output should be the versioned envelope, got:\n%s", out)
	}
	if !strings.Contains(out, `"components"`) || !strings.Contains(out, "pkg:npm/lodash") {
		t.Errorf("raw output should carry the inventory components, got:\n%s", out)
	}
	if !strings.Contains(out, `"scope": "detected"`) {
		t.Errorf("raw output should carry the component scope, got:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2021-23337") {
		t.Errorf("raw output should carry the gathered vulnerabilities, got:\n%s", out)
	}
}

// A non-nil server block reaches the raw output; a nil one leaves it absent, so a scan whose
// report carried no `server` stays byte-identical to before this field existed.
func TestRenderInventory_RawServer(t *testing.T) {
	server := &sbom.RawServer{
		KnowledgeBase: &sbom.RawKnowledgeBase{MonthlyVersion: "26.04", DailyVersion: "25.03.19"},
		APIVersion:    "3.1.0",
	}
	out, err := renderInventory(sampleInventory(), "raw", "proj", server)
	if err != nil {
		t.Fatalf("renderInventory: %v", err)
	}
	for _, want := range []string{`"server"`, `"knowledge_base"`, `"monthly_version": "26.04"`, `"daily_version": "25.03.19"`, `"api_version": "3.1.0"`} {
		if !strings.Contains(out, want) {
			t.Errorf("raw output should carry %s, got:\n%s", want, out)
		}
	}

	bare, err := renderInventory(sampleInventory(), "raw", "proj", nil)
	if err != nil {
		t.Fatalf("renderInventory: %v", err)
	}
	if strings.Contains(bare, `"server"`) {
		t.Errorf("a nil server must omit the server key, got:\n%s", bare)
	}
}

// The server block is raw-only: the SBOM formats have no field for the engine/KB versions, so a
// non-nil server neither errors nor leaks into their output.
func TestRenderInventory_ServerDroppedBySBOMFormats(t *testing.T) {
	server := &sbom.RawServer{KnowledgeBase: &sbom.RawKnowledgeBase{MonthlyVersion: "26.04"}}
	for _, format := range []string{"spdx", "cyclonedx"} {
		out, err := renderInventory(sampleInventory(), format, "proj", server)
		if err != nil {
			t.Fatalf("renderInventory(%s): %v", format, err)
		}
		if strings.Contains(out, "26.04") {
			t.Errorf("%s output must not carry the server block, got:\n%s", format, out)
		}
	}
}

func TestRenderInventory_SPDXLite(t *testing.T) {
	out, err := renderInventory(sampleInventory(), "spdx", "proj", nil)
	if err != nil {
		t.Fatalf("renderInventory: %v", err)
	}
	if !strings.Contains(out, `"spdxVersion": "SPDX-2.3"`) {
		t.Errorf("expected SPDX 2.3 document, got:\n%s", out)
	}
	if !strings.Contains(out, `"licenseDeclared": "MIT"`) {
		t.Errorf("expected the license in licenseDeclared, got:\n%s", out)
	}
}

func TestRenderInventory_CycloneDX(t *testing.T) {
	out, err := renderInventory(sampleInventory(), "cyclonedx", "proj", nil)
	if err != nil {
		t.Fatalf("renderInventory: %v", err)
	}
	if !strings.Contains(out, `"specVersion": "1.7"`) {
		t.Errorf("expected CycloneDX 1.7, got:\n%s", out)
	}
	if !strings.Contains(out, `"id": "MIT"`) {
		t.Errorf("expected the license in the CycloneDX output, got:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2021-23337") {
		t.Errorf("expected the vulnerability in the CycloneDX output, got:\n%s", out)
	}
}

func TestRenderInventory_UnknownFormat(t *testing.T) {
	if _, err := renderInventory(sampleInventory(), "xml", "proj", nil); err == nil {
		t.Error("expected an error for an unsupported format")
	}
}

func TestUnsupportedLayers(t *testing.T) {
	all := Set{
		LayerDeps: true, LayerVulns: true, LayerLicenses: true,
		LayerCrypto: true, LayerGeo: true,
	}
	cases := []struct {
		format string
		layers Set
		want   []Layer
	}{
		{"raw", all, nil},
		{"cyclonedx", all, []Layer{LayerCrypto, LayerGeo}},
		{"spdx", all, []Layer{LayerVulns, LayerCrypto, LayerGeo}},
		{"spdx", Set{LayerDeps: true, LayerLicenses: true}, nil},
	}
	for _, c := range cases {
		got := unsupportedLayers(c.format, c.layers)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.format, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.format, got, c.want)
				break
			}
		}
	}
}

func TestEffectiveLayers(t *testing.T) {
	all := Set{
		LayerDeps: true, LayerVulns: true, LayerLicenses: true,
		LayerCrypto: true, LayerGeo: true,
	}
	// spdx keeps only deps + licenses; the rest are not gathered.
	eff := effectiveLayers("spdx", all)
	if len(eff) != 2 || !eff.Has(LayerDeps) || !eff.Has(LayerLicenses) {
		t.Errorf("spdx effective = %v, want {deps, licenses}", eff)
	}
	// cyclonedx additionally keeps vulns.
	if eff := effectiveLayers("cyclonedx", all); len(eff) != 3 || eff.Has(LayerCrypto) || eff.Has(LayerGeo) {
		t.Errorf("cyclonedx effective = %v, want {deps, licenses, vulns}", eff)
	}
	// raw keeps everything.
	if eff := effectiveLayers("raw", all); len(eff) != 5 {
		t.Errorf("raw effective = %v, want all 5", eff)
	}
}

func TestScanLayers(t *testing.T) {
	newCmd := func(include string) *cobra.Command {
		c := &cobra.Command{}
		c.Flags().StringSlice("include", nil, "")
		if include != "" {
			_ = c.Flags().Set("include", include)
		}
		return c
	}

	set, err := scanLayers(newCmd("deps,vulns"))
	if err != nil {
		t.Fatalf("scanLayers: %v", err)
	}
	if !set[LayerDeps] || !set[LayerVulns] || len(set) != 2 {
		t.Errorf("got %v, want {deps, vulns}", set)
	}

	if empty, err := scanLayers(newCmd("")); err != nil || len(empty) != 0 {
		t.Errorf("empty --include should yield an empty set, got %v (err %v)", empty, err)
	}

	if _, err := scanLayers(newCmd("bogus")); err == nil {
		t.Error("expected an error for an unknown --include layer")
	}
}
