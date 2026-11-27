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
	out, err := renderInventory(sampleInventory(), nil, "raw", "proj")
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

func TestRenderInventory_SPDXLite(t *testing.T) {
	out, err := renderInventory(sampleInventory(), nil, "spdx", "proj")
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
	out, err := renderInventory(sampleInventory(), nil, "cyclonedx", "proj")
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
	if _, err := renderInventory(sampleInventory(), nil, "xml", "proj"); err == nil {
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

// The ai layer is read from the scanned tree: scan accepts it, the commands that start from a
// result or an SBOM do not, and raw and CycloneDX carry the report.
func TestAILayer(t *testing.T) {
	if _, err := ParseLayers([]string{"ai"}, AllLayers()); err != nil {
		t.Fatalf("scan should accept --include ai: %v", err)
	}
	if _, err := ParseLayers([]string{"ai"}, PurlLayers()); err == nil {
		t.Fatal("a command without a scanned tree should refuse --include ai")
	}
	if got := unsupportedLayers("spdx", Set{LayerAI: true}); len(got) != 1 {
		t.Fatalf("spdx should not render the ai layer, got %v", got)
	}
	ai := &sbom.AIUsage{Format: sbom.AIUsageFormat, Findings: []sbom.AIUsageFinding{{
		RuleID: "ai.test.chat", Category: "model_usage", File: "a.py", Line: 1, Reachability: sbom.AIUnknown,
		Metadata: map[string]any{"ai": map[string]any{"provider": "acme", "model": "m-1", "risk": "info"}},
	}}}
	raw, err := renderInventory(sampleInventory(), ai, "raw", "proj")
	if err != nil || !strings.Contains(raw, `"ai_usage"`) || !strings.Contains(raw, `"ai.test.chat"`) {
		t.Fatalf("raw output lacks the ai_usage section (err %v)", err)
	}
	cdx, err := renderInventory(sampleInventory(), ai, "cyclonedx", "proj")
	if err != nil || !strings.Contains(cdx, `"machine-learning-model"`) || !strings.Contains(cdx, `"svc:acme"`) {
		t.Fatalf("cyclonedx output lacks the AI model and service (err %v)", err)
	}
}
