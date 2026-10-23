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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type scanRequests struct {
	mu      sync.Mutex
	queries []url.Values // upload (POST) requests only
}

func (s *scanRequests) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.mu.Lock()
			s.queries = append(s.queries, r.URL.Query())
			s.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "completed",
			"result": map[string]any{"files": []any{}, "components": map[string]any{}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runScanWFPCmd(t *testing.T, srvURL string, extra ...string) error {
	t.Helper()
	wfpPath := filepath.Join(t.TempDir(), "in.wfp")
	if err := os.WriteFile(wfpPath, []byte("file=abc,10,a.c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := runBare(t, append([]string{
		"scan", "wfp", wfpPath, "--api-url", srvURL, "--api-key", "test", "--output", out,
		"--poll-interval", "10ms",
	}, extra...)...)
	return err
}

// runScanDirCmd drives `scan <dir>`, which fingerprints a directory and goes through
// scanpipeline.Run rather than the `scan wfp` path.
func runScanDirCmd(t *testing.T, srvURL string, extra ...string) error {
	t.Helper()
	dir := t.TempDir()
	src := "package main\n\nfunc main() {\n\tprintln(\"hello components\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	_, _, err := runBare(t, append([]string{
		"scan", dir, "--api-url", srvURL, "--api-key", "test", "--output", out,
		"--poll-interval", "10ms",
	}, extra...)...)
	return err
}

func TestScanRejectsInvalidMaxComponents(t *testing.T) {
	for _, bad := range []string{"0", "-1", "2.5", "ALL", "+3", "abc"} {
		t.Run(bad, func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			err := runScanWFPCmd(t, srv.URL, "--max-components="+bad)
			if err == nil || !strings.Contains(err.Error(), "--max-components") {
				t.Fatalf("error = %v, want one naming --max-components", err)
			}
			if n := len(rec.queries); n != 0 {
				t.Errorf("server saw %d requests, want 0: the value must be refused before any upload", n)
			}
		})
	}
}

func TestScanSendsMaxComponents(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"number", []string{"--max-components", "7"}, "7"},
		{"all", []string{"--max-components", "all"}, "all"},
		{"unset", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			if err := runScanWFPCmd(t, srv.URL, tc.args...); err != nil {
				t.Fatal(err)
			}
			if len(rec.queries) == 0 {
				t.Fatal("server saw no upload")
			}
			for _, q := range rec.queries {
				if tc.want == "" {
					if len(q) != 0 {
						t.Errorf("an unset flag sent a query: %v", q)
					}
					continue
				}
				if got := q["max_components"]; len(got) != 1 || got[0] != tc.want {
					t.Errorf("upload query %v, want max_components=%q", q, tc.want)
				}
			}
		})
	}
}

func TestScanDirRejectsInvalidMaxComponents(t *testing.T) {
	for _, bad := range []string{"0", "-1", "2.5", "ALL", "+3", "abc", ""} {
		t.Run("value="+bad, func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			err := runScanDirCmd(t, srv.URL, "--max-components="+bad)
			if err == nil || !strings.Contains(err.Error(), "--max-components") {
				t.Fatalf("error = %v, want one naming --max-components", err)
			}
			if n := len(rec.queries); n != 0 {
				t.Errorf("server saw %d requests, want 0: the value must be refused before any upload", n)
			}
		})
	}
}

func TestScanDirSendsMaxComponents(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"number", []string{"--max-components", "7"}, "7"},
		{"all", []string{"--max-components", "all"}, "all"},
		{"unset", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			if err := runScanDirCmd(t, srv.URL, tc.args...); err != nil {
				t.Fatal(err)
			}
			if len(rec.queries) == 0 {
				t.Fatal("server saw no upload")
			}
			for _, q := range rec.queries {
				if tc.want == "" {
					if len(q) != 0 {
						t.Errorf("an unset flag sent a query: %v", q)
					}
					continue
				}
				if got := q["max_components"]; len(got) != 1 || got[0] != tc.want {
					t.Errorf("upload query %v, want max_components=%q", q, tc.want)
				}
			}
		})
	}
}

// An explicitly empty value is a mistake (an unset shell variable, say), not an unset limit.
func TestScanWFPRejectsEmptyMaxComponents(t *testing.T) {
	var rec scanRequests
	srv := rec.server(t)
	err := runScanWFPCmd(t, srv.URL, "--max-components", "")
	if err == nil || !strings.Contains(err.Error(), "--max-components") {
		t.Fatalf("error = %v, want one naming --max-components", err)
	}
	if n := len(rec.queries); n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
}
