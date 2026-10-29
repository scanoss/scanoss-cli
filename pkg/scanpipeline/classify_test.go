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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

// The local file and the OSS file a snippet match pairs share no informative line: the
// classifier proposes it as a false positive.
const (
	classifyLocal = "func handler(w http.ResponseWriter, r *http.Request) {\n\tuser := loadUser(r)\n\tif user == nil {\n\t\thttp.Error(w, \"forbidden\", 403)\n\t\treturn\n\t}\n\trender(w, user.Profile)\n}\n"
	classifyOSS   = "def parse_config(path):\n    with open(path) as fh:\n        data = yaml.safe_load(fh)\n    validate(data)\n    return Config(**data)\n"
)

// classifyServer answers the scan with one snippet match of handler.go against pkg:github/acme/fp,
// serves file contents with contentsStatus, and records the bodies of the vulnerability requests.
type classifyServer struct {
	contentsStatus int
	mu             sync.Mutex
	vulnBodies     []string
}

func (s *classifyServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v3/file-contents/"):
			if s.contentsStatus != http.StatusOK {
				http.Error(w, `{"error":"forbidden"}`, s.contentsStatus)
				return
			}
			_, _ = w.Write([]byte(classifyOSS))
		case strings.Contains(r.URL.Path, "/vulnerabilities"):
			body, _ := io.ReadAll(r.Body)
			s.mu.Lock()
			s.vulnBodies = append(s.vulnBodies, string(body))
			s.mu.Unlock()
			_, _ = w.Write([]byte(`{"components":[]}`))
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusAccepted)
		default:
			_, _ = w.Write([]byte(`{"scan_id":"s1","status":"completed","phase":"done","result":{
				"files":[{"path":"handler.go","match_type":"snippet","file_hash":"0123456789abcdef","matches":[{"url_hash":"h1",
					"input_line_ranges":[{"start_line":1,"end_line":8}],"oss_line_ranges":[{"start_line":1,"end_line":5}]}]}],
				"components":{"h1":{"purls":["pkg:github/acme/fp"],"version":"1.0.0"}}}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runClassify(t *testing.T, srvURL string, filterFP bool, services []scanoss.Service) Result {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "handler.go"), []byte(classifyLocal), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), Options{
		Client:               mustNewClient(t, srvURL),
		Services:             services,
		SourcePath:           root,
		ScanFilters:          filter.Scanning(nil),
		ScanOptions:          []scanoss.ScanOption{scanoss.WithPollInterval(10 * time.Millisecond)},
		ClassifySnippets:     true,
		FilterFalsePositives: filterFP,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Classification == nil {
		t.Fatal("no classification summary for a run that asked for one")
	}
	return res
}

// Without the filter, the match is scored and kept.
func TestRunClassifiesWithoutRemoving(t *testing.T) {
	s := &classifyServer{contentsStatus: http.StatusOK}
	res := runClassify(t, s.start(t).URL, false, nil)

	c := res.Classification
	if c.Matches != 1 || c.Scored != 1 || c.FalsePositives != 1 || c.Removed != 0 || c.DeniedStatus != 0 {
		t.Errorf("summary = %+v, want 1 match scored as a false positive, none removed", *c)
	}
	comp := findComponent(res.Inventory, "pkg:github/acme/fp")
	if comp == nil || comp.Evidence[0].SnippetClassification == nil {
		t.Fatalf("component = %+v, want it kept with its classification", comp)
	}
}

// With the filter, the false positive goes, its component with it, and the component is never
// sent to the decoration services.
func TestRunFiltersFalsePositivesBeforeEnrichment(t *testing.T) {
	s := &classifyServer{contentsStatus: http.StatusOK}
	res := runClassify(t, s.start(t).URL, true, []scanoss.Service{scanoss.ServiceVulnerabilities})

	if c := res.Classification; c.Removed != 1 {
		t.Errorf("removed = %d, want 1", c.Removed)
	}
	if comp := findComponent(res.Inventory, "pkg:github/acme/fp"); comp != nil {
		t.Errorf("component left with no evidence must be removed, got %+v", comp)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, body := range s.vulnBodies {
		if strings.Contains(body, "acme/fp") {
			t.Errorf("a removed component was sent for vulnerabilities: %s", body)
		}
	}
}

// A key without file-contents access scores nothing; the summary says why rather than only
// counting failures.
func TestRunReportsFileContentsDenied(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		s := &classifyServer{contentsStatus: status}
		res := runClassify(t, s.start(t).URL, true, nil)

		c := res.Classification
		if c.DeniedStatus != status || c.Scored != 0 || c.Matches != 1 || c.Removed != 0 {
			t.Errorf("status %d: summary = %+v, want DeniedStatus %d, nothing scored or removed", status, *c, status)
		}
		if findComponent(res.Inventory, "pkg:github/acme/fp") == nil {
			t.Errorf("status %d: an unscored match must never be filtered", status)
		}
	}
}

// Any other failure is counted as unscored but is not reported as an access problem.
func TestRunDoesNotReportOtherFailuresAsDenied(t *testing.T) {
	s := &classifyServer{contentsStatus: http.StatusNotFound}
	res := runClassify(t, s.start(t).URL, false, nil)
	if c := res.Classification; c.DeniedStatus != 0 || c.Scored != 0 {
		t.Errorf("summary = %+v, want an unscored match and no access denial", *c)
	}
}
