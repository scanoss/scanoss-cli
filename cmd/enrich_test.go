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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/internal/config"
)

// rawInput is a scanoss raw inventory (the scan raw output envelope) with one component.
const rawInput = `{"schema_version":"1.0","metadata":{"tool":"scanoss"},"components":[{"purl":"pkg:npm/lodash","version":"4.17.20","name":"lodash"}]}`

// enrichDecorationServer stubs the decoration endpoints enrich exercises.
func enrichDecorationServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/licenses"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/lodash","requirement":"4.17.20","licenses":[{"id":"MIT"}]}]}`))
		case strings.Contains(r.URL.Path, "/remediation/intelligence"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/lodash","requirement":"4.17.20","version":"4.17.20","risk":{"band":"at_risk","score":41}}],"data_as_of":{"scored_at":"2026-10-27T21:29:42Z"},"status":{"status":"SUCCESS","message":"Resolved 1 of 1 purls"}}`))
		case strings.Contains(r.URL.Path, "/vulnerabilities"):
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:npm/lodash","vulnerabilities":[{"id":"CVE-2021-23337","severity":"HIGH","source":"NVD"}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// runEnrichTest invokes the enrich command's RunE with the given flags/args.
func runEnrichTest(t *testing.T, input string, flags map[string]string, include ...string) error {
	t.Helper()
	c := &cobra.Command{RunE: runEnrich}
	c.Flags().String("api-url", config.DefaultAPIURL, "")
	c.Flags().String("api-key", "", "")
	c.Flags().StringP("output", "o", "", "")
	c.Flags().StringP("format", "f", "", "")
	c.Flags().Bool("ignore-cert-errors", false, "")
	c.Flags().StringSlice("include", nil, "")
	for k, v := range flags {
		if err := c.Flags().Set(k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}
	if len(include) > 0 {
		_ = c.Flags().Set("include", strings.Join(include, ","))
	}
	return runEnrich(c, []string{input})
}

func TestIdentifyAndParse(t *testing.T) {
	cases := []struct {
		name, input, wantFormat string
		wantErr                 bool
	}{
		{name: "cyclonedx", input: cdxInput, wantFormat: config.FormatCycloneDX},
		{name: "spdx", input: spdxInput, wantFormat: config.FormatSPDX},
		{name: "raw", input: rawInput, wantFormat: config.FormatRaw},
		{name: "v3-scan-result", input: `{"components":{"h1":{"purls":["pkg:npm/x"]}},"files":[]}`, wantErr: true},
		{name: "non-inventory-json", input: `{"foo":"bar"}`, wantErr: true},
		{name: "garbage", input: `{not json`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, format, err := identifyAndParse([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got format %q", format)
				}
				return
			}
			if err != nil {
				t.Fatalf("identifyAndParse: %v", err)
			}
			if format != tc.wantFormat {
				t.Errorf("got format %q, want %q", format, tc.wantFormat)
			}
		})
	}
}

// TestEnrich_RawEnrichesLicenses proves raw in / raw out (default format) with a layer actually
// gathered from the decoration service.
func TestEnrich_RawEnrichesLicenses(t *testing.T) {
	srv := enrichDecorationServer()
	defer srv.Close()

	dir := t.TempDir()
	in := filepath.Join(dir, "inv.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, []byte(rawInput), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runEnrichTest(t, in, map[string]string{"api-url": srv.URL, "output": out}, "licenses")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, `"schema_version"`) {
		t.Errorf("expected raw output (default format = input), got:\n%s", s)
	}
	if !strings.Contains(s, "MIT") {
		t.Errorf("expected the gathered MIT license in the output, got:\n%s", s)
	}
}

// TestEnrich_DefaultFormatFollowsInput proves the output format defaults to the input's when
// --format is omitted (spdx in → spdx out). No layers requested → no API call.
func TestEnrich_DefaultFormatFollowsInput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.spdx.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, []byte(spdxInput), 0o644); err != nil {
		t.Fatal(err)
	}

	// Custom (non-default) endpoint → keyless allowed; no --include → no request is made.
	err := runEnrichTest(t, in, map[string]string{"api-url": "http://enrich.invalid", "output": out})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), `"spdxVersion": "SPDX-2.3"`) {
		t.Errorf("expected SPDX output when the input is SPDX, got:\n%s", got)
	}
}

// TestEnrich_ConvertsWithFormat proves --format converts in the same pass (cyclonedx in →
// spdx out).
func TestEnrich_ConvertsWithFormat(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.cdx.json")
	out := filepath.Join(dir, "out.spdx.json")
	if err := os.WriteFile(in, []byte(cdxInput), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runEnrichTest(t, in, map[string]string{"api-url": "http://enrich.invalid", "format": "spdx", "output": out})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	got, _ := os.ReadFile(out)
	s := string(got)
	if !strings.Contains(s, `"spdxVersion": "SPDX-2.3"`) {
		t.Errorf("expected SPDX output with --format spdx, got:\n%s", s)
	}
	if !strings.Contains(s, "pkg:github/scanoss/engine") {
		t.Errorf("expected the component carried through, got:\n%s", s)
	}
}

// TestEnrich_SkipsUnsupportedLayer proves a layer the output format can't render is skipped up
// front (spdx can't carry vulns) — reported on stderr and never gathered.
func TestEnrich_SkipsUnsupportedLayer(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.spdx.json")
	out := filepath.Join(dir, "out.spdx.json")
	if err := os.WriteFile(in, []byte(spdxInput), 0o644); err != nil {
		t.Fatal(err)
	}

	stderr := captureStderr(t, func() {
		// vulns is unsupported by spdx → skipped → effective set is empty → no API call needed.
		if err := runEnrichTest(t, in, map[string]string{"api-url": "http://enrich.invalid", "output": out}, "vulns"); err != nil {
			t.Fatalf("enrich: %v", err)
		}
	})
	if !strings.Contains(stderr, "vulnerabilities") || !strings.Contains(stderr, "skipped") {
		t.Errorf("expected an up-front skip notice for vulnerabilities, got stderr:\n%s", stderr)
	}
}

func TestEnrich_Errors(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "inv.json")
	_ = os.WriteFile(rawPath, []byte(rawInput), 0o644)
	badPath := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(badPath, []byte(`{"components":{"h1":{}}}`), 0o644) // v3-result shape → rejected

	// deps is not a valid enrich layer.
	if err := runEnrichTest(t, rawPath, map[string]string{"api-url": "http://enrich.invalid"}, "deps"); err == nil {
		t.Error("expected an error for --include deps")
	}
	// A v3 scan result (components as an object) is not accepted.
	if err := runEnrichTest(t, badPath, map[string]string{"api-url": "http://enrich.invalid"}); err == nil {
		t.Error("expected an error for a verbatim v3 scan result")
	}
	// Missing key on the default endpoint fails checkAuth up front.
	if err := runEnrichTest(t, rawPath, map[string]string{"api-url": config.DefaultAPIURL}); err == nil {
		t.Error("expected checkAuth to fail with no key on the default endpoint")
	}
	// Invalid output format.
	if err := runEnrichTest(t, rawPath, map[string]string{"api-url": "http://enrich.invalid", "format": "xml"}); err == nil {
		t.Error("expected an error for an invalid --format")
	}
	// Missing input file.
	if err := runEnrichTest(t, filepath.Join(dir, "missing.json"), map[string]string{"api-url": "http://enrich.invalid"}); err == nil {
		t.Error("expected an error for a missing input file")
	}
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = orig
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	_ = r.Close()
	return string(buf[:n])
}

// The remediation layer attaches the Remediation Intelligence answer to the component it was asked
// for, joined by purl and version, without repeating the request echo.
func TestEnrich_RawEnrichesRemediation(t *testing.T) {
	srv := enrichDecorationServer()
	defer srv.Close()

	dir := t.TempDir()
	in := filepath.Join(dir, "inv.json")
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(in, []byte(rawInput), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runEnrichTest(t, in, map[string]string{"api-url": srv.URL, "output": out}, "remediation"); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Components    []struct {
			Purl        string                     `json:"purl"`
			Remediation map[string]json.RawMessage `json:"remediation"`
		} `json:"components"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, got)
	}
	if doc.SchemaVersion != "2.2" {
		t.Errorf("schema_version = %q, want 2.2", doc.SchemaVersion)
	}
	if len(doc.Components) != 1 || doc.Components[0].Remediation == nil {
		t.Fatalf("expected remediation on the component, got:\n%s", got)
	}
	rem := doc.Components[0].Remediation
	if !strings.Contains(string(rem["risk"]), `"at_risk"`) {
		t.Errorf("risk = %s, want the at_risk band", rem["risk"])
	}
	if _, ok := rem["purl"]; ok {
		t.Error("remediation repeats the purl echo; the component already carries it")
	}
}
