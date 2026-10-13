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

package scansource

import (
	"encoding/json"
	"strings"
	"testing"

	scanossapi "github.com/scanoss/scanoss.api-sdk"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

func sampleResult() *scanossapi.ScanResult {
	return &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{
				Path:      "src/a.c",
				MatchType: "file",
				Matches:   []scanossapi.MatchResult{{UrlHash: "h1"}},
			},
			{
				Path:      "src/b.c",
				MatchType: "snippet",
				Matches: []scanossapi.MatchResult{{
					UrlHash:         "h1",
					InputLineRanges: []scanossapi.LineRange{{StartLine: 12, EndLine: 48}},
					OssLineRanges:   []scanossapi.LineRange{{StartLine: 100, EndLine: 136}},
				}},
			},
			{Path: "ignored.c", MatchType: "none", Matches: nil},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {
				Purls:       []string{"pkg:github/scanoss/engine"},
				Vendor:      "scanoss",
				Component:   "engine",
				Version:     "5.4.1",
				Url:         "https://github.com/scanoss/engine",
				Rank:        6,
				ReleaseDate: "2026-03-12",
				File:        "v5.4.1.zip",
			},
			"h2": {
				Purls:   []string{"pkg:npm/lodash"},
				Version: "4.17.21",
			},
			"h3": {Purls: []string{""}}, // skipped: empty purl
		},
	}
}

func TestInventory_Extraction(t *testing.T) {
	inv := Inventory(sampleResult())
	if len(inv.Components) != 2 {
		t.Fatalf("want 2 components (empty-purl skipped), got %d", len(inv.Components))
	}

	// engine is the primary match of both files; lodash matches none, so it comes after.
	engine := inv.Components[0]
	if engine.Purl != "pkg:github/scanoss/engine" || engine.Vendor != "scanoss" {
		t.Errorf("engine mapping wrong: %+v", engine)
	}
	if engine.Version != "5.4.1" {
		t.Errorf("version should come from the component entry, got %q", engine.Version)
	}
	if len(engine.Licenses) != 0 {
		t.Errorf("Inventory should not populate licenses (they come from decoration), got %v", engine.Licenses)
	}

	lodash := inv.Components[1]
	if lodash.Version != "4.17.21" {
		t.Errorf("component version should map through, got %q", lodash.Version)
	}
}

// Every field the engine reports about a component reaches the inventory. Rank in
// particular: two components matching the same file are told apart by nothing else.
func TestInventory_ComponentFieldsAreNotDropped(t *testing.T) {
	engine := Inventory(sampleResult()).Components[0]

	if engine.Rank != 6 {
		t.Errorf("Rank = %d, want 6", engine.Rank)
	}
	if engine.ReleaseDate != "2026-03-12" {
		t.Errorf("ReleaseDate = %q, want 2026-03-12", engine.ReleaseDate)
	}
	if engine.ArtifactName != "v5.4.1.zip" {
		t.Errorf("ArtifactName = %q, want v5.4.1.zip", engine.ArtifactName)
	}
	if engine.URL != "https://github.com/scanoss/engine" || engine.URLHash != "h1" {
		t.Errorf("URL/URLHash = %q/%q", engine.URL, engine.URLHash)
	}
	if engine.Name != "engine" {
		t.Errorf("Name = %q, want engine", engine.Name)
	}
}

// A component the engine reported without them leaves them empty rather than inventing a
// value — the fields are omitempty, so an absent rank must not render as 0.
func TestInventory_AbsentComponentFieldsStayEmpty(t *testing.T) {
	lodash := Inventory(sampleResult()).Components[1]

	if lodash.Rank != 0 || lodash.ReleaseDate != "" || lodash.ArtifactName != "" {
		t.Errorf("want the three unset, got rank=%d release=%q artifact=%q",
			lodash.Rank, lodash.ReleaseDate, lodash.ArtifactName)
	}
}

func TestInventory_FileEvidence(t *testing.T) {
	inv := Inventory(sampleResult())
	files := inv.Components[0].Evidence
	if len(files) != 2 {
		t.Fatalf("want 2 file evidences (none-match excluded), got %d", len(files))
	}
	// sorted by path: a.c before b.c
	if files[0].Path != "src/a.c" || files[1].Path != "src/b.c" {
		t.Errorf("files not sorted by path: %v", files)
	}
	if files[1].MatchType != "snippet" || len(files[1].InputLineRanges) != 1 || files[1].InputLineRanges[0] != (sbom.LineRange{StartLine: 12, EndLine: 48}) {
		t.Errorf("snippet evidence wrong: %+v", files[1])
	}
}

func TestInventory_Nil(t *testing.T) {
	if inv := Inventory(nil); len(inv.Components) != 0 {
		t.Errorf("nil result should yield empty inventory, got %+v", inv)
	}
}

func TestInventory_MultiMatchFile(t *testing.T) {
	// One snippet file matching two components yields one file evidence under each
	// component's url_hash, with that match's own line ranges.
	result := &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{
				Path:      "src/multi.js",
				MatchType: "snippet",
				Matches: []scanossapi.MatchResult{
					{UrlHash: "h1", InputLineRanges: []scanossapi.LineRange{{StartLine: 12, EndLine: 48}}},
					{UrlHash: "h2", InputLineRanges: []scanossapi.LineRange{{StartLine: 12, EndLine: 40}}},
				},
			},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:github/scanoss/scanner.c", "pkg:npm/scanner"}, Vendor: "scanoss", Component: "scanner.c", Version: "v1.3.0", Url: "https://github.com/scanoss/scanner.c"},
			"h2": {Purls: []string{"pkg:github/example/other-lib"}, Version: "2.0.1"}, // only the purl and version: the optional fields stay empty
		},
	}

	inv := Inventory(result)
	if len(inv.Components) != 2 {
		t.Fatalf("want 2 components, got %d", len(inv.Components))
	}
	// the first purl is the canonical identity; the rest become aliases.
	if inv.Components[0].Purl != "pkg:github/scanoss/scanner.c" {
		t.Errorf("canonical Purl = %q", inv.Components[0].Purl)
	}
	if got := inv.Components[0].AliasPurls; len(got) != 1 || got[0] != "pkg:npm/scanner" {
		t.Errorf("AliasPurls = %v, want [pkg:npm/scanner]", got)
	}
	for _, c := range inv.Components {
		if len(c.Evidence) != 1 || c.Evidence[0].Path != "src/multi.js" {
			t.Errorf("component %s should carry the multi-match file as evidence: %+v", c.Purl, c.Evidence)
		}
	}
	// h1 sorts before h2; each gets its own match's ranges.
	if got := inv.Components[0].Evidence[0].InputLineRanges; len(got) != 1 || got[0] != (sbom.LineRange{StartLine: 12, EndLine: 48}) {
		t.Errorf("h1 evidence ranges = %v, want [{12 48}]", got)
	}
	if got := inv.Components[1].Evidence[0].InputLineRanges; len(got) != 1 || got[0] != (sbom.LineRange{StartLine: 12, EndLine: 40}) {
		t.Errorf("h2 evidence ranges = %v, want [{12 40}]", got)
	}
	// The minimal catalog entry — purl and version only — still maps cleanly.
	other := inv.Components[1]
	if other.Purl != "pkg:github/example/other-lib" || other.Version != "2.0.1" || other.URL != "" {
		t.Errorf("minimal component mapped wrong: %+v", other)
	}
}

func ptr[T any](v T) *T { return &v }

func TestLicenses(t *testing.T) {
	resp := &scanossapi.ComponentsLicenseResponse{
		Components: &[]scanossapi.ComponentLicenseInfo{
			{
				// one entry per queried version of the same base PURL
				Purl:        ptr("pkg:npm/lodash"),
				Requirement: ptr("4.17.20"),
				Licenses: &[]scanossapi.LicenseInfo{
					{Id: ptr("MIT")}, {Id: ptr("ISC")}, {Id: ptr("MIT")}, // in-entry dup dropped
				},
			},
			{
				Purl:        ptr("pkg:npm/lodash"),
				Requirement: ptr("4.17.21"),
				Licenses: &[]scanossapi.LicenseInfo{
					{Id: ptr("MIT")}, {Id: ptr("GPL-2.0-only")}, // distinct key (different version)
				},
			},
			{Purl: ptr("pkg:gem/rails")}, // no licenses -> absent from the map
		},
	}

	byKey := Licenses(resp)

	// Keyed by PURL + requirement (queried version), so each version is distinct.
	v20 := byKey[Key("pkg:npm/lodash", "4.17.20")]
	if len(v20) != 2 || v20[0].ID != "MIT" || v20[0].Acknowledgement != sbom.AckDeclared || v20[1].ID != "ISC" {
		t.Errorf("4.17.20 licenses = %v, want [MIT ISC] declared (in-entry dup dropped)", v20)
	}
	v21 := byKey[Key("pkg:npm/lodash", "4.17.21")]
	if len(v21) != 2 || v21[0].ID != "MIT" || v21[1].ID != "GPL-2.0-only" {
		t.Errorf("4.17.21 licenses = %v, want [MIT GPL-2.0-only]", v21)
	}
	if _, ok := byKey[Key("pkg:gem/rails", "")]; ok {
		t.Error("component with no licenses should be absent from the map")
	}
}

func TestLicenses_Nil(t *testing.T) {
	if v := Licenses(nil); v != nil {
		t.Errorf("nil resp should yield nil, got %v", v)
	}
}

func TestVulnerabilities(t *testing.T) {
	src := scanossapi.VulnerabilitySource("NVD")
	resp := &scanossapi.VulnerabilitiesResponse{
		Components: []scanossapi.ComponentVulnerabilityInfo{
			{
				Purl: ptr("pkg:npm/lodash"),
				Vulnerabilities: &[]scanossapi.Vulnerability{
					{Id: ptr("CVE-2021-23337"), Severity: ptr("HIGH"), Source: &src, Summary: ptr("cmd injection")},
					{Cve: ptr("CVE-2020-8203")}, // id empty -> falls back to cve
				},
			},
			{
				// same CVE affecting another component -> purls accumulate
				Purl: ptr("pkg:npm/lodash.template"),
				Vulnerabilities: &[]scanossapi.Vulnerability{
					{Id: ptr("CVE-2021-23337")},
				},
			},
		},
	}

	vulns := Vulnerabilities(resp)
	if len(vulns) != 2 {
		t.Fatalf("want 2 deduped vulnerabilities, got %d: %+v", len(vulns), vulns)
	}

	first := vulns[0]
	if first.ID != "CVE-2021-23337" {
		t.Errorf("id = %q", first.ID)
	}
	if first.Severity != "high" {
		t.Errorf("severity should be lower-cased, got %q", first.Severity)
	}
	if first.Source != "NVD" {
		t.Errorf("source = %q", first.Source)
	}
	if len(first.Purls) != 2 {
		t.Errorf("purls should accumulate across components, got %v", first.Purls)
	}
	if vulns[1].ID != "CVE-2020-8203" {
		t.Errorf("second id should fall back to cve, got %q", vulns[1].ID)
	}
}

func TestVulnerabilities_Nil(t *testing.T) {
	if v := Vulnerabilities(nil); v != nil {
		t.Errorf("nil resp should yield nil, got %v", v)
	}
}

// The service answers per version — asked about two releases of one component it returns different
// advisories for each — so an advisory has to record which version it came back for. Keying on the
// bare PURL attached every advisory to every version, reporting vulnerabilities a release did not
// have.
func TestVulnerabilitiesKeepTheVersionTheyAnswerFor(t *testing.T) {
	old, recent := "v1.24.0", "v2.7.8"
	purl := "pkg:github/denoland/deno"
	cveOld, cveBoth := "CVE-2024-27931", "CVE-2023-0001"

	resp := &scanossapi.VulnerabilitiesResponse{
		Components: []scanossapi.ComponentVulnerabilityInfo{
			{
				Purl: &purl, Version: &old,
				Vulnerabilities: &[]scanossapi.Vulnerability{{Cve: &cveOld}, {Cve: &cveBoth}},
			},
			{
				Purl: &purl, Version: &recent,
				Vulnerabilities: &[]scanossapi.Vulnerability{{Cve: &cveBoth}},
			},
		},
	}

	byID := map[string][]string{}
	for _, v := range Vulnerabilities(resp) {
		byID[v.ID] = v.Purls
	}

	if got := byID[cveOld]; len(got) != 1 || got[0] != purl+"@"+old {
		t.Errorf("%s affects %v, want only %s@%s — it was not reported for the newer release",
			cveOld, got, purl, old)
	}
	if got := byID[cveBoth]; len(got) != 2 {
		t.Errorf("%s affects %v, want both releases", cveBoth, got)
	}
}

// Without a version the entry still has to land somewhere: the bare PURL, as before.
func TestVulnerabilitiesWithoutAVersionKeepTheBarePurl(t *testing.T) {
	purl, cve := "pkg:npm/lodash", "CVE-2020-0001"
	resp := &scanossapi.VulnerabilitiesResponse{
		Components: []scanossapi.ComponentVulnerabilityInfo{
			{Purl: &purl, Vulnerabilities: &[]scanossapi.Vulnerability{{Cve: &cve}}},
		},
	}
	got := Vulnerabilities(resp)
	if len(got) != 1 || len(got[0].Purls) != 1 || got[0].Purls[0] != purl {
		t.Errorf("purls = %v, want [%s]", got, purl)
	}
}

// The identify verdict reaches the inventory through the option, since the scan result has
// nowhere to carry it. It lands on the evidence, and the component summarises it.
func TestInventoryMarksIdentifiedComponents(t *testing.T) {
	result := &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{{
			Path:      "src/app.js",
			MatchType: "file",
			Matches:   []scanossapi.MatchResult{{UrlHash: "h1"}, {UrlHash: "h2"}},
		}},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:npm/vue"}, Version: "2.6.14"},
			"h2": {Purls: []string{"pkg:npm/lodash"}, Version: "4.17.21"},
		},
	}

	inv := Inventory(result, WithIdentified(func(path, urlHash string) bool {
		return urlHash == "h1"
	}))

	for _, c := range inv.Components {
		want := c.Purl == "pkg:npm/vue"
		if c.Identified != want {
			t.Errorf("%s component identified = %v, want %v", c.Purl, c.Identified, want)
		}
		for _, e := range c.Evidence {
			if e.Identified != want {
				t.Errorf("%s evidence %s identified = %v, want %v", c.Purl, e.Path, e.Identified, want)
			}
		}
	}
}

// A path-scoped rule claims a component in some of its files and not others. That is the whole
// reason the flag is per-evidence: the component-level one cannot say which.
func TestInventoryMarksIdentifiedPerFile(t *testing.T) {
	result := &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{Path: "vendor/vue.js", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h1"}}},
			{Path: "src/app.js", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h1"}}},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:npm/vue"}, Version: "2.6.14"},
		},
	}

	// As a rule scoped to "vendor/" would answer.
	inv := Inventory(result, WithIdentified(func(path, urlHash string) bool {
		return strings.HasPrefix(path, "vendor/")
	}))

	if len(inv.Components) != 1 {
		t.Fatalf("got %d components, want 1", len(inv.Components))
	}
	c := inv.Components[0]
	if !c.Identified {
		t.Error("the component should be identified: one of its files was claimed")
	}
	byPath := map[string]bool{}
	for _, e := range c.Evidence {
		byPath[e.Path] = e.Identified
	}
	if !byPath["vendor/vue.js"] {
		t.Error("vendor/vue.js should be identified")
	}
	if byPath["src/app.js"] {
		t.Error("src/app.js is outside the rule's scope and must not be identified")
	}
}

// Without the option nothing is marked: an inventory built from a result alone makes no claim
// about what the user declared.
func TestInventoryWithoutIdentifiedMarksNothing(t *testing.T) {
	result := &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{{
			Path: "src/app.js", MatchType: "file",
			Matches: []scanossapi.MatchResult{{UrlHash: "h1"}},
		}},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:npm/vue"}, Version: "2.6.14"},
		},
	}

	for _, c := range Inventory(result).Components {
		if c.Identified {
			t.Errorf("%s should not be marked identified", c.Purl)
		}
		for _, e := range c.Evidence {
			if e.Identified {
				t.Errorf("%s evidence %s should not be marked identified", c.Purl, e.Path)
			}
		}
	}
}

// orderedResult is one file the scanner matched to two components, origin first: "hb" is the
// component the file comes from and "ha" a fork of it. Their url_hashes sort the other way round,
// which is what grouping the result by url_hash used to report as the file's order.
func orderedResult() *scanossapi.ScanResult {
	return &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{{
			Path: "src/x.c", MatchType: "file",
			Matches: []scanossapi.MatchResult{{UrlHash: "hb"}, {UrlHash: "ha"}},
		}},
		Components: map[string]scanossapi.ComponentResult{
			"ha": {Purls: []string{"pkg:github/fork/x"}, Version: "1.0"},
			"hb": {Purls: []string{"pkg:github/origin/x"}, Version: "1.0"},
		},
	}
}

// evidenceAt returns the match index each component recorded for path, keyed by PURL. A missing
// index is -1, so a test can tell it from the primary.
func evidenceAt(inv sbom.Inventory, path string) map[string]int {
	out := make(map[string]int)
	for _, c := range inv.Components {
		for _, e := range c.Evidence {
			if e.Path != path {
				continue
			}
			out[c.Purl] = -1
			if e.MatchIndex != nil {
				out[c.Purl] = *e.MatchIndex
			}
		}
	}
	return out
}

func TestInventory_MatchIndexKeepsTheFilesOrder(t *testing.T) {
	inv := Inventory(orderedResult())

	got := evidenceAt(inv, "src/x.c")
	if got["pkg:github/origin/x"] != 0 || got["pkg:github/fork/x"] != 1 {
		t.Fatalf("want origin at 0 and fork at 1, the scanner's order, got %v", got)
	}
	if inv.Components[0].Purl != "pkg:github/origin/x" {
		t.Errorf("the file's primary should lead the inventory despite its later url_hash, got %s first",
			inv.Components[0].Purl)
	}
	if !inv.Components[0].Evidence[0].IsPrimary() || inv.Components[1].Evidence[0].IsPrimary() {
		t.Errorf("IsPrimary should hold for the origin's evidence only")
	}
}

// Server maps the SDK's ScanServer onto the neutral sbom.RawServer, and returns nil for a report
// with no server block so the raw output is left unchanged.
func TestServer(t *testing.T) {
	if got := Server(nil); got != nil {
		t.Errorf("Server(nil) = %+v, want nil", got)
	}

	got := Server(&scanossapi.ScanServer{
		ApiVersion:    "3.1.0",
		Hostname:      "scanner-01",
		ElapsedMs:     1234,
		KnowledgeBase: &scanossapi.KnowledgeBase{MonthlyVersion: "26.04", DailyVersion: "25.03.19"},
	})
	if got == nil {
		t.Fatal("Server returned nil for a populated block")
	}
	if got.APIVersion != "3.1.0" || got.Hostname != "scanner-01" || got.ElapsedMs != 1234 {
		t.Errorf("server metadata not mapped: %+v", got)
	}
	if got.KnowledgeBase == nil || got.KnowledgeBase.MonthlyVersion != "26.04" || got.KnowledgeBase.DailyVersion != "25.03.19" {
		t.Errorf("knowledge_base not mapped: %+v", got.KnowledgeBase)
	}

	// A server block with no knowledge_base maps to a nil pointer, not an empty object.
	if got := Server(&scanossapi.ScanServer{ApiVersion: "3.1.0"}); got.KnowledgeBase != nil {
		t.Errorf("absent knowledge_base should map to nil, got %+v", got.KnowledgeBase)
	}
}

// A scan result's `server` block, as it arrives on the wire, deserializes into the SDK type and
// maps through to the raw document — proving the end-to-end path a real API response takes.
func TestServer_FromWire(t *testing.T) {
	const body = `{
	  "components": {},
	  "files": [],
	  "server": {
	    "knowledge_base": {"monthly_version": "26.04", "daily_version": "25.03.19"},
	    "api_version": "3.1.0",
	    "hostname": "scanner-01",
	    "elapsed_ms": 1234
	  }
	}`
	var result scanossapi.ScanResult
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal scan result: %v", err)
	}
	srv := Server(result.Server)
	if srv == nil || srv.KnowledgeBase == nil {
		t.Fatalf("server/knowledge_base not carried from the wire: %+v", srv)
	}
	if srv.KnowledgeBase.MonthlyVersion != "26.04" || srv.APIVersion != "3.1.0" {
		t.Errorf("server block not mapped from wire: %+v", srv)
	}

	doc := sbom.NewRawDocument(sbom.Inventory{}, sbom.RawMetadata{})
	doc.Server = srv
	out, err := doc.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(out, `"monthly_version": "26.04"`) || !strings.Contains(out, `"api_version": "3.1.0"`) {
		t.Errorf("wire server block did not reach the raw document:\n%s", out)
	}
}

// The raw document is where a consumer reads the order back, so the primary's 0 must be written
// rather than dropped as an empty value, and must survive being parsed again.
func TestInventory_MatchIndexInRawDocument(t *testing.T) {
	out, err := sbom.NewRawDocument(Inventory(orderedResult()), sbom.RawMetadata{}).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Components []struct {
			Purl     string                       `json:"purl"`
			Evidence []map[string]json.RawMessage `json:"evidence"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"pkg:github/origin/x": "0", "pkg:github/fork/x": "1"}
	for _, c := range doc.Components {
		if got := string(c.Evidence[0]["match_index"]); got != want[c.Purl] {
			t.Errorf("%s: match_index = %q, want %q", c.Purl, got, want[c.Purl])
		}
	}

	parsed, err := sbom.ParseRaw([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	got := evidenceAt(parsed, "src/x.c")
	if got["pkg:github/origin/x"] != 0 || got["pkg:github/fork/x"] != 1 {
		t.Errorf("match_index lost on parse: %v", got)
	}
}

// Two catalog entries for one PURL at one version fold into a single component. Each file keeps
// the position its own match had; a file both entries matched keeps the better of the two.
func TestInventory_MatchIndexSurvivesTheMerge(t *testing.T) {
	res := &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{Path: "a.c", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h2"}, {UrlHash: "other"}}},
			{Path: "b.c", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "other"}, {UrlHash: "h1"}}},
			{Path: "c.c", MatchType: "file", Matches: []scanossapi.MatchResult{
				{UrlHash: "other"}, {UrlHash: "h2", OssFilePath: "second"}, {UrlHash: "h1", OssFilePath: "third"},
			}},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1":    {Purls: []string{"pkg:github/lib/lib"}, Version: "2.0"},
			"h2":    {Purls: []string{"pkg:github/lib/lib"}, Version: "2.0"},
			"other": {Purls: []string{"pkg:github/other/other"}, Version: "1.0"},
		},
	}
	inv := Inventory(res)

	if len(inv.Components) != 2 {
		t.Fatalf("h1 and h2 should fold into one component, got %d", len(inv.Components))
	}
	var lib sbom.Component
	for _, c := range inv.Components {
		if c.Purl == "pkg:github/lib/lib" {
			lib = c
		}
	}
	want := map[string]int{"a.c": 0, "b.c": 1, "c.c": 1}
	if len(lib.Evidence) != len(want) {
		t.Fatalf("want one evidence per file, got %+v", lib.Evidence)
	}
	for _, e := range lib.Evidence {
		if e.MatchIndex == nil || *e.MatchIndex != want[e.Path] {
			t.Errorf("%s: match index %v, want %d", e.Path, e.MatchIndex, want[e.Path])
		}
		if e.Path == "c.c" && e.OssFilePath != "second" {
			t.Errorf("c.c should keep the details of the better-placed match, got %q", e.OssFilePath)
		}
	}
}

// Components are ordered by how many files they are the primary match of, then by how many files
// they match at all, and only then by url_hash.
func TestInventory_ComponentOrder(t *testing.T) {
	res := &scanossapi.ScanResult{
		Files: []scanossapi.FileResult{
			{Path: "1.c", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h9"}, {UrlHash: "h1"}, {UrlHash: "h2"}}},
			{Path: "2.c", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h9"}, {UrlHash: "h1"}}},
			{Path: "3.c", MatchType: "file", Matches: []scanossapi.MatchResult{{UrlHash: "h5"}, {UrlHash: "h1"}}},
		},
		Components: map[string]scanossapi.ComponentResult{
			"h1": {Purls: []string{"pkg:github/mirror/one"}},
			"h2": {Purls: []string{"pkg:github/mirror/two"}},
			"h3": {Purls: []string{"pkg:github/mirror/three"}},
			"h5": {Purls: []string{"pkg:github/vendored/dep"}},
			"h9": {Purls: []string{"pkg:github/project/self"}},
		},
	}
	var got []string
	for _, c := range Inventory(res).Components {
		got = append(got, c.URLHash)
	}
	// h9 leads two files, h5 one; h1 leads none but matches three, h2 one, h3 none.
	if want := "h9 h5 h1 h2 h3"; strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}
