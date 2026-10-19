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

package scanpipeline

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	scanossapi "github.com/scanoss/scanoss.api-sdk"

	"github.com/scanoss/scanoss.go/internal/logging"
	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/sbom"
	"github.com/scanoss/scanoss.go/pkg/sbom/depsource"
	"github.com/scanoss/scanoss.go/pkg/sbom/scansource"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
	"github.com/scanoss/scanoss.go/pkg/wfp"
)

// mustNewClient builds an SDK client against apiURL and fails the test if it cannot.
func mustNewClient(t *testing.T, apiURL string) *scanoss.Client {
	t.Helper()
	client, err := scanoss.New(scanoss.Config{APIURL: apiURL, APIKey: "x"})
	if err != nil {
		t.Fatalf("scanoss.New: %v", err)
	}
	return client
}

// decorationServer answers the licenses, vulnerabilities, dependency-resolve, cryptography,
// geoprovenance and copyright endpoints with canned responses so the enrichment path can be
// exercised without a live API.
func decorationServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/dependencies/dependencies"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/left-pad","version":"1.3.0"}],"status":{"status":"success"}}`))
		case strings.Contains(r.URL.Path, "/vulnerabilities"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/lodash","vulnerabilities":[{"id":"CVE-2021-23337","severity":"HIGH","source":"NVD"}]},{"purl":"pkg:npm/left-pad","vulnerabilities":[{"id":"CVE-2099-0001","severity":"LOW","source":"NVD"}]}]}`))
		case strings.Contains(r.URL.Path, "/licenses"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/lodash","requirement":"4.17.20","licenses":[{"id":"MIT"}]}]}`))
		case strings.Contains(r.URL.Path, "/cryptography/algorithms"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/lodash","requirement":"4.17.20","algorithms":[{"algorithm":"aes","strength":"256"}]}],"status":{"status":"success"}}`))
		case strings.Contains(r.URL.Path, "/geoprovenance/origin"):
			_, _ = w.Write([]byte(`{"components_locations":[{"purl":"pkg:npm/lodash","locations":[{"name":"US","percentage":80}]}],"status":{"status":"success"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func detectedResult() *scanossapi.ScanResult {
	return &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{Path: "a.go", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h1"}}},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:npm/lodash"}, Vendor: "lodash", Version: "4.17.20"},
		},
	}
}

// declaredLeftPad is the parsed-manifest input for a single declared dependency.
func declaredLeftPad() *parsers.LocalDependencies {
	return &parsers.LocalDependencies{
		Files: []parsers.LocalDependency{
			{File: "package.json", Purls: []parsers.LocalPurl{{Purl: "pkg:npm/left-pad", Requirement: "^1.3.0"}}},
		},
	}
}

func findComponent(inv sbom.Inventory, purl string) *sbom.Component {
	for i := range inv.Components {
		if inv.Components[i].Purl == purl {
			return &inv.Components[i]
		}
	}
	return nil
}

func hasVuln(inv sbom.Inventory, id string) bool {
	for _, v := range inv.Vulnerabilities {
		if v.ID == id {
			return true
		}
	}
	return false
}

// assembleAndEnrich reproduces what Run does once it holds a scan result: build the inventory,
// add the declared components when they were asked for, then gather the requested layers. The
// tests exercise that sequence rather than a single entry point, because the pipeline no longer
// has one for it — a caller with a scan result assembles and enriches in two visible steps.
func assembleAndEnrich(t *testing.T, client *scanoss.Client, result *scanossapi.ScanResult, services []scanoss.Service, includeDeclared bool, declared *parsers.LocalDependencies) sbom.Inventory {
	t.Helper()
	inv := scansource.Inventory(result)
	if includeDeclared && declared != nil && len(declared.Files) > 0 {
		inv.Add(depsource.Manifests(declared, "").Components...)
	}
	if err := (Enricher{Client: client, Services: services}).Enrich(context.Background(), &inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	return inv
}

func TestEnrichesDetected(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	inv := assembleAndEnrich(t, client, detectedResult(), []scanoss.Service{scanoss.ServiceLicenses, scanoss.ServiceVulnerabilities}, false, nil)

	lodash := findComponent(inv, "pkg:npm/lodash")
	if lodash == nil {
		t.Fatal("detected component pkg:npm/lodash missing")
	}
	if len(lodash.Licenses) != 1 || lodash.Licenses[0].ID != "MIT" {
		t.Errorf("expected MIT license on lodash, got %v", lodash.Licenses)
	}
	if !hasVuln(inv, "CVE-2021-23337") {
		t.Errorf("expected CVE-2021-23337, got %v", inv.Vulnerabilities)
	}
}

// TestEnrichHandBuiltInventory proves Enricher decorates an inventory that never came from a
// scan — the enrich command's entry point (parse an SBOM into an Inventory, then Enrich it
// with no fingerprinting or scan). Layers attach by PURL just as on the scan path.
func TestEnrichHandBuiltInventory(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	inv := sbom.Inventory{Components: []sbom.Component{
		{Purl: "pkg:npm/lodash", Version: "4.17.20"},
	}}
	enricher := Enricher{Client: client, Services: []scanoss.Service{scanoss.ServiceLicenses, scanoss.ServiceVulnerabilities}}
	if err := enricher.Enrich(context.Background(), &inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	lodash := findComponent(inv, "pkg:npm/lodash")
	if lodash == nil {
		t.Fatal("component pkg:npm/lodash missing")
	}
	if len(lodash.Licenses) != 1 || lodash.Licenses[0].ID != "MIT" {
		t.Errorf("expected MIT license on lodash, got %v", lodash.Licenses)
	}
	if !hasVuln(inv, "CVE-2021-23337") {
		t.Errorf("expected CVE-2021-23337, got %v", inv.Vulnerabilities)
	}
}

// TestLayersAreOptIn proves no purl-layer is gathered unless requested: an Enricher with no
// services enriches nothing, so a plain scan does no decoration work.
func TestLayersAreOptIn(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	inv := assembleAndEnrich(t, client, detectedResult(), nil, false, nil)
	lodash := findComponent(inv, "pkg:npm/lodash")
	if lodash == nil {
		t.Fatal("detected component pkg:npm/lodash missing")
	}
	if len(lodash.Licenses) != 0 {
		t.Errorf("licenses must not be gathered without --include licenses, got %v", lodash.Licenses)
	}
	if len(inv.Vulnerabilities) != 0 {
		t.Errorf("vulnerabilities must not be gathered without --include vulns, got %v", inv.Vulnerabilities)
	}
}

// TestDepsDrivenByLayer proves declared dependencies are gathered only when the deps layer is
// requested — never implicitly.
func TestDepsDrivenByLayer(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	// deps NOT requested: the declared input is ignored.
	inv := assembleAndEnrich(t, client, detectedResult(), nil, false, declaredLeftPad())
	if findComponent(inv, "pkg:npm/left-pad") != nil {
		t.Error("declared dependency must not appear without --include deps")
	}

	// deps requested: the declared dependency is sourced straight from the manifest (no service
	// call), so a package.json-only entry keeps its version range rather than a resolved version.
	inv = assembleAndEnrich(t, client, detectedResult(), nil, true, declaredLeftPad())
	leftPad := findComponent(inv, "pkg:npm/left-pad")
	if leftPad == nil {
		t.Fatal("declared dependency pkg:npm/left-pad missing with --include deps")
	}
	if !leftPad.IsDeclared() {
		t.Errorf("left-pad should have declared scope, got %q", leftPad.Scope)
	}
	if leftPad.Version != "^1.3.0" {
		t.Errorf("expected the manifest requirement ^1.3.0 (no service resolution), got %q", leftPad.Version)
	}
	if len(leftPad.Evidence) != 1 || leftPad.Evidence[0].Path != "package.json" || leftPad.Evidence[0].MatchType != "declared" {
		t.Errorf("expected declared evidence from package.json, got %+v", leftPad.Evidence)
	}
}

// TestDeclaredEnrichedForVulns proves declared dependencies are added before the decoration
// pipeline runs, so requesting vulns enriches them alongside the scan matches.
func TestDeclaredEnrichedForVulns(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	inv := assembleAndEnrich(t, client, detectedResult(), []scanoss.Service{scanoss.ServiceVulnerabilities}, true, declaredLeftPad())

	var forDetected, forDeclared bool
	for _, v := range inv.Vulnerabilities {
		for _, p := range v.Purls {
			if p == "pkg:npm/lodash" && v.ID == "CVE-2021-23337" {
				forDetected = true
			}
			if p == "pkg:npm/left-pad" && v.ID == "CVE-2099-0001" {
				forDeclared = true
			}
		}
	}
	if !forDetected {
		t.Error("expected the detected component's vulnerability")
	}
	if !forDeclared {
		t.Error("expected the declared dependency to be enriched with its vulnerability")
	}
}

// TestDepsWithoutDetectedMatches proves a project with only declared dependencies (no scan
// matches) still yields those components.
func TestDepsWithoutDetectedMatches(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	inv := assembleAndEnrich(t, client, &scanossapi.ScanResult{}, nil, true, declaredLeftPad())
	if len(inv.Components) != 1 || inv.Components[0].Purl != "pkg:npm/left-pad" {
		t.Fatalf("expected only the declared dependency, got %+v", inv.Components)
	}
	if !inv.Components[0].IsDeclared() {
		t.Errorf("the dependency should have declared scope, got %q", inv.Components[0].Scope)
	}
}

// TestEnrichesAllPurlLayers proves the crypto and geo layers are gathered and attached inline
// on the component when requested.
func TestEnrichesAllPurlLayers(t *testing.T) {
	srv := decorationServer()
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	inv := assembleAndEnrich(t, client, detectedResult(), []scanoss.Service{scanoss.ServiceCryptographyAlgorithms, scanoss.ServiceGeoprovenanceOrigin}, false, nil)
	lodash := findComponent(inv, "pkg:npm/lodash")
	if lodash == nil {
		t.Fatal("detected component pkg:npm/lodash missing")
	}
	if len(lodash.Cryptography) != 1 || lodash.Cryptography[0].Algorithm != "aes" {
		t.Errorf("expected the aes algorithm, got %v", lodash.Cryptography)
	}
	if len(lodash.Geoprovenance) != 1 || lodash.Geoprovenance[0].Name != "US" {
		t.Errorf("expected the US origin, got %v", lodash.Geoprovenance)
	}
}

// A nil Client used to reach the scan goroutine, where the panic was on a stack the caller could
// not recover from — and Run, unwinding through its deferred Wait, still handed back a nil error.
// A caller embedding the pipeline in a long-lived process lost the process and was told it went
// fine. The check has to happen before anything is spawned, so the error is the caller's to handle.
func TestRunRequiresAClient(t *testing.T) {
	// The tree needs a file worth fingerprinting: with nothing to scan the goroutine returns on the
	// empty WFP and never reaches the client, so an empty directory would pass either way.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), Options{SourcePath: root})
	if err == nil {
		t.Fatal("Run with a nil Client returned no error")
	}
	if !strings.Contains(err.Error(), "client is required") {
		t.Errorf("error should name the missing client, got: %v", err)
	}
}

// Run streams the WFP into the caller's WFPWriter while the scan generates it: the copy
// arrives complete even though Result no longer carries the stream.
func TestRunStreamsWFPToWriter(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "code.c"), []byte(strings.Repeat("int x;\n", 40)), 0o644); err != nil {
		t.Fatal(err)
	}

	// A minimal fake of the v3 scan endpoint: chunks are accepted, the first status
	// poll answers completed with one detected component.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"scan_id":"s1","status":"completed","phase":"done",
				"result":{"files":[{"path":"code.c","match_type":"file","matches":[{"url_hash":"h1"}]}],
				"components":{"h1":{"purls":["pkg:npm/lodash"],"version":"4.17.20"}}}}`))
		}
	}))
	defer srv.Close()

	var wfpCopy bytes.Buffer
	res, err := Run(context.Background(), Options{
		Client:      mustNewClient(t, srv.URL),
		SourcePath:  root,
		ScanFilters: filter.Scanning(nil),
		ScanOptions: []scanoss.ScanOption{scanoss.WithPollInterval(10 * time.Millisecond)},
		WFPWriter:   &wfpCopy,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	out := wfpCopy.String()
	if !strings.Contains(out, "file=") || !strings.Contains(out, "code.c") {
		t.Errorf("WFPWriter did not receive the stream; got:\n%s", out)
	}
	if findComponent(res.Inventory, "pkg:npm/lodash") == nil {
		t.Errorf("inventory missing the detected component; got %+v", res.Inventory.Components)
	}
}

// With the deps layer requested, Run resolves the lockfile beside the scanned code into the
// inventory's dependency graph: the resolved packages are declared components and the root is
// in Dependencies, while the manifest the lockfile covers contributes no flat range entry.
func TestRunResolvesLockfileGraph(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "code.c"), []byte(strings.Repeat("int x;\n", 40)), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join("..", "dependencies", "resolve", "lockfile", "testdata", "package-lock", "dev-scope")
	if err := os.CopyFS(root, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"left":"^1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"scan_id":"s1","status":"completed","phase":"done","result":{"files":[],"components":{}}}`))
		}
	}))
	defer srv.Close()

	depFilters := filter.Dependencies(nil)
	depFilters.BuiltinFileRules = false
	res, err := Run(context.Background(), Options{
		Client:            mustNewClient(t, srv.URL),
		SourcePath:        root,
		SourceDeclared:    true,
		ScanFilters:       filter.Scanning(nil),
		DependencyFilters: depFilters,
		ScanOptions:       []scanoss.ScanOption{scanoss.WithPollInterval(10 * time.Millisecond)},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var roots []string
	for _, r := range res.Inventory.Dependencies {
		roots = append(roots, r.Manifest+" "+string(r.Status))
	}
	if want := []string{"package.json complete", "packages/tool/package.json complete"}; !slices.Equal(roots, want) {
		t.Errorf("roots = %q, want %q", roots, want)
	}
	left := findComponent(res.Inventory, "pkg:npm/left")
	if left == nil || left.Version != "1.0.0" {
		t.Fatalf("want the resolved left@1.0.0 from the lockfile, got %+v", left)
	}
	if !left.IsDeclared() || len(left.Evidence) != 1 || left.Evidence[0].MatchType != "declared" || left.Evidence[0].Path != "package.json" {
		t.Errorf("left = %+v, want a declared component with the manifest as evidence", left)
	}
	for _, c := range res.Inventory.Components {
		if c.Purl == "pkg:npm/left" && c.Version == "^1.0.0" {
			t.Error("the range entry of a manifest its lockfile covers must not be emitted")
		}
	}
}

// A service that answers with an unexpected shape must not make its layer vanish in silence:
// the SBOM would come out valid and smaller, with no hint that licenses were dropped. The SDK
// now reports it as that service's failure, so the existing per-service warning names it.
func TestEnrichWarnsOnUndecodableLayer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/licenses") {
			// Valid JSON, wrong shape: components must be an array.
			_, _ = w.Write([]byte(`{"components":"not-an-array"}`))
			return
		}
		_, _ = w.Write([]byte(`{"components":[]}`))
	}))
	defer srv.Close()
	client := mustNewClient(t, srv.URL)

	// The warning goes to the configured sink, not to stderr: this module writes nothing
	// until an application asks for logs. Capture it by installing a logger.
	var out bytes.Buffer
	logging.Set(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer logging.Set(nil)

	inv := sbom.Inventory{Components: []sbom.Component{{Purl: "pkg:npm/lodash", Version: "4.17.20"}}}
	enricher := Enricher{Client: client, Services: []scanoss.Service{scanoss.ServiceLicenses, scanoss.ServiceVulnerabilities}}
	if err := enricher.Enrich(context.Background(), &inv); err == nil {
		t.Error("a layer whose response cannot be read must be reported, not only warned about")
	} else if !strings.Contains(err.Error(), scanoss.ServiceLicenses.Name) {
		t.Errorf("the error should name the licenses service, got %v", err)
	}

	if !strings.Contains(out.String(), scanoss.ServiceLicenses.Name) {
		t.Errorf("no warning naming the licenses service; log was %q", out.String())
	}
	if lodash := findComponent(inv, "pkg:npm/lodash"); lodash != nil && len(lodash.Licenses) != 0 {
		t.Errorf("licenses should be absent when the response cannot be read, got %v", lodash.Licenses)
	}
}

// An empty WFPOptions gets pkg/wfp's default, the header filter on; wfp.WithoutSkipHeaders turns
// it off. The CLI relies on the second: it passes the opt-out rather than leaving the option out.
func TestRunSkipsHeadersUnlessToldNot(t *testing.T) {
	root := t.TempDir()
	src := "/*\n * Copyright (c) 2026 Example Corp\n * Licensed under the MIT license\n */\n" +
		"#include <stdio.h>\n\n" + strings.Repeat("int compute(int x) { return x * 42 + 7; }\n", 30)
	if err := os.WriteFile(filepath.Join(root, "code.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusAccepted)
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"scan_id":"s1","status":"completed","phase":"done","result":{"files":[],"components":{}}}`))
		}
	}))
	defer srv.Close()

	run := func(opts ...wfp.Option) string {
		var out bytes.Buffer
		if _, err := Run(context.Background(), Options{
			Client:      mustNewClient(t, srv.URL),
			SourcePath:  root,
			ScanFilters: filter.Scanning(nil),
			ScanOptions: []scanoss.ScanOption{scanoss.WithPollInterval(10 * time.Millisecond)},
			WFPOptions:  opts,
			WFPWriter:   &out,
		}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return out.String()
	}

	if got := run(); !strings.Contains(got, "start_line=6\n") {
		t.Errorf("no WFPOptions: want start_line=6; got:\n%s", got)
	}
	if got := run(wfp.WithoutSkipHeaders()); !strings.Contains(got, "file=") || strings.Contains(got, "start_line=") {
		t.Errorf("WithoutSkipHeaders: want an unfiltered WFP; got:\n%s", got)
	}
}
