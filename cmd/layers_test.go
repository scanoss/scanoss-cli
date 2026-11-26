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

	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

func TestParseLayers(t *testing.T) {
	set, err := ParseLayers([]string{"deps", " vulns ", ""}, AllLayers())
	if err != nil {
		t.Fatalf("ParseLayers: %v", err)
	}
	if !set.Has(LayerDeps) || !set.Has(LayerVulns) {
		t.Errorf("set = %v, want deps and vulns (surrounding spaces trimmed, blanks ignored)", set)
	}
	if set.Has(LayerLicenses) {
		t.Error("licenses was not requested but is in the set")
	}
	if _, err := ParseLayers([]string{"bogus"}, AllLayers()); err == nil {
		t.Error("ParseLayers accepted an unknown layer")
	}
}

// A command that cannot gather a layer must not offer it. enrich works from an SBOM file, so
// declared dependencies — read from manifests in a scanned tree — are out of reach; listing deps
// as valid and then refusing it told the user two different things, the second one only after
// they had tried it.
func TestParseLayersRejectsWhatTheCommandCannotGather(t *testing.T) {
	_, err := ParseLayers([]string{"deps"}, PurlLayers())
	if err == nil {
		t.Fatal("deps was accepted for a PURL-only command")
	}
	// Assert on the valid list alone: "deps" also appears in the rejected-value part of the
	// message, so searching the whole string would pass however wrong the list is.
	_, valid, found := strings.Cut(err.Error(), "valid: ")
	if !found {
		t.Fatalf("error does not list the valid layers: %v", err)
	}
	if strings.Contains(valid, "deps") {
		t.Errorf("the valid list offers deps to a command that cannot gather it: %q", valid)
	}
	for _, want := range []string{"crypto", "geo", "licenses", "vulns"} {
		if !strings.Contains(valid, want) {
			t.Errorf("valid list %q does not mention %q", valid, want)
		}
	}

	// The same values are still accepted where they can be gathered.
	if _, err := ParseLayers([]string{"deps"}, AllLayers()); err != nil {
		t.Errorf("deps must stay valid for a command that scans a tree: %v", err)
	}
}

// The error has to name the layers that would have worked, and name them in a stable order:
// ranging a map is randomised, so an unsorted list reshuffles between runs.
func TestParseLayersErrorListsValidLayers(t *testing.T) {
	_, err := ParseLayers([]string{"vulnz"}, AllLayers())
	if err == nil {
		t.Fatal("ParseLayers accepted an unknown layer")
	}
	for _, want := range []string{"crypto", "deps", "geo", "licenses", "vulns"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention the valid layer %q", err, want)
		}
	}
	// The list is built by ranging a map, which Go randomises: without an explicit sort the
	// wording differs between runs, so repeat it enough times to catch that.
	for i := 0; i < 20; i++ {
		_, again := ParseLayers([]string{"vulnz"}, AllLayers())
		if again.Error() != err.Error() {
			t.Fatalf("the error wording changed between runs:\n %q\n %q", err, again)
		}
	}
}

// Translating layers into services is the whole of what the pipeline needs to know about
// --include: it is handed services and never learns a flag was involved.
func TestServicesForTranslatesLayers(t *testing.T) {
	got := servicesFor(Set{LayerVulns: true, LayerLicenses: true})
	want := []scanoss.Service{scanoss.ServiceLicenses, scanoss.ServiceVulnerabilities}
	if len(got) != len(want) {
		t.Fatalf("services = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i].Name {
			t.Errorf("service %d = %q, want %q (order must be stable across runs)", i, got[i].Name, want[i].Name)
		}
	}
}

// deps is a layer with no decoration service: declared dependencies are sourced from the parsed
// manifests, so asking for it alone must produce no service call at all.
func TestServicesForDepsHasNoService(t *testing.T) {
	if got := servicesFor(Set{LayerDeps: true}); len(got) != 0 {
		t.Errorf("services = %v, want none: deps is sourced from manifests, not fetched", got)
	}
}

// remediation is a PURL-keyed layer: enrich can gather it from an inventory alone, and it maps to
// the Remediation Intelligence service.
func TestRemediationLayer(t *testing.T) {
	set, err := ParseLayers([]string{"remediation"}, PurlLayers())
	if err != nil {
		t.Fatalf("ParseLayers: %v", err)
	}
	got := servicesFor(set)
	if len(got) != 1 || got[0].Name != scanoss.ServiceRemediation.Name {
		t.Errorf("services = %v, want only %q", got, scanoss.ServiceRemediation.Name)
	}
}
