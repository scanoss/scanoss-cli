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

package scanoss

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// remediationStub answers each request like the API does: a hit for every purl except those
// containing "missing", with that request's own status and a data_as_of whose dates depend on the
// purls it got, so merging across chunks can be checked.
func remediationStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/remediation/intelligence" {
			http.NotFound(w, r)
			return
		}
		var comps []Component
		if r.Method == http.MethodGet {
			comps = []Component{{Purl: r.URL.Query().Get("purl"), Requirement: r.URL.Query().Get("requirement")}}
		} else {
			var req componentsRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			comps = req.Components
		}
		var entries []string
		hits := 0
		scored := "2026-11-20T00:00:00Z"
		for _, c := range comps {
			echo := fmt.Sprintf(`"purl":%q`, c.Purl)
			if c.Requirement != "" {
				echo += fmt.Sprintf(`,"requirement":%q`, c.Requirement)
			}
			if strings.Contains(c.Purl, "missing") {
				entries = append(entries, `{`+echo+`,"info_code":"COMPONENT_NOT_FOUND","info_message":"not found"}`)
				continue
			}
			hits++
			if strings.Contains(c.Purl, "old") {
				scored = "2026-10-01T00:00:00Z"
			}
			entries = append(entries, `{`+echo+`,"version":"1.0.0","risk":{"band":"watch"}}`)
		}
		asOf := "null"
		if hits > 0 {
			asOf = fmt.Sprintf(`{"scored_at":%q,"kev_snapshot":"2026-11-01","epss_snapshot":"2026-11-02"}`, scored)
		}
		status := "SUCCESS"
		if hits == 0 {
			status = "ERROR"
		} else if hits < len(comps) {
			status = "PARTIAL_SUCCESS"
		}
		fmt.Fprintf(w, `{"components":[%s],"data_as_of":%s,"status":{"status":%q,"message":"Resolved %d of %d purls"}}`,
			strings.Join(entries, ","), asOf, status, hits, len(comps))
	}))
}

// Over several chunks the batch reads like one request: entries in request order, the status
// counted over every chunk, and data_as_of the oldest date among the hits.
func TestRemediationComponentsMergesChunks(t *testing.T) {
	srv := remediationStub(t)
	defer srv.Close()

	comps := []Component{
		{Purl: "pkg:npm/a@1.0.0"},
		{Purl: "pkg:npm/missing-b@1.0.0"},
		{Purl: "pkg:npm/old-c@1.0.0"},
		{Purl: "pkg:npm/d", Requirement: "1.0.0"},
		{Purl: "pkg:npm/missing-e@1.0.0"},
	}
	client := mustNew(t, Config{APIURL: srv.URL, ChunkSize: 1, Workers: 5})
	got, err := client.Remediation.Components(context.Background(), comps)
	if err != nil {
		t.Fatalf("Components: %v", err)
	}

	if len(got.Components) != len(comps) {
		t.Fatalf("entries = %d, want %d", len(got.Components), len(comps))
	}
	for i, c := range comps {
		if got.Components[i].Purl != c.Purl {
			t.Errorf("entry %d = %q, want %q (request order)", i, got.Components[i].Purl, c.Purl)
		}
	}
	if got.Status.Status != "PARTIAL_SUCCESS" || got.Status.Message != "Resolved 3 of 5 purls" {
		t.Errorf("status = %+v, want PARTIAL_SUCCESS \"Resolved 3 of 5 purls\"", got.Status)
	}
	if got.DataAsOf == nil || got.DataAsOf.ScoredAt == nil {
		t.Fatalf("data_as_of = %+v, want the oldest scored_at", got.DataAsOf)
	}
	if want := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC); !got.DataAsOf.ScoredAt.Equal(want) {
		t.Errorf("data_as_of.scored_at = %v, want %v", got.DataAsOf.ScoredAt, want)
	}
	if _, ok := got.Components[0].Get("risk"); !ok {
		t.Error("a hit lost its payload: no risk key")
	}
	if got.Components[1].InfoCode == nil || *got.Components[1].InfoCode != "COMPONENT_NOT_FOUND" {
		t.Errorf("miss info_code = %v, want COMPONENT_NOT_FOUND", got.Components[1].InfoCode)
	}
}

func TestRemediationComponentsStatusAllOrNone(t *testing.T) {
	srv := remediationStub(t)
	defer srv.Close()
	client := mustNew(t, Config{APIURL: srv.URL, ChunkSize: 1})

	all, err := client.Remediation.Components(context.Background(), Components("pkg:npm/a@1", "pkg:npm/b@1"))
	if err != nil {
		t.Fatalf("Components: %v", err)
	}
	if all.Status.Status != "SUCCESS" {
		t.Errorf("all hits: status = %q, want SUCCESS", all.Status.Status)
	}

	none, err := client.Remediation.Components(context.Background(), Components("pkg:npm/missing-a@1", "pkg:npm/missing-b@1"))
	if err != nil {
		t.Fatalf("Components: %v", err)
	}
	if none.Status.Status != "ERROR" || none.DataAsOf != nil {
		t.Errorf("no hits: status = %q, data_as_of = %+v, want ERROR and none", none.Status.Status, none.DataAsOf)
	}
}

func TestRemediationComponentSingle(t *testing.T) {
	srv := remediationStub(t)
	defer srv.Close()
	client := mustNew(t, Config{APIURL: srv.URL})

	got, err := client.Remediation.Component(context.Background(), Component{Purl: "pkg:npm/left-pad", Requirement: "1.3.0"})
	if err != nil {
		t.Fatalf("Component: %v", err)
	}
	if len(got.Components) != 1 || got.Status.Message != "Resolved 1 of 1 purls" {
		t.Fatalf("got %+v, want one hit", got)
	}
	if r := got.Components[0].Requirement; r == nil || *r != "1.3.0" {
		t.Errorf("requirement echo = %v, want 1.3.0", r)
	}
}

// The pipeline keeps the remediation layer, merged the same way as the batch method.
func TestPipelineRemediationLayer(t *testing.T) {
	srv := remediationStub(t)
	defer srv.Close()
	client := mustNew(t, Config{APIURL: srv.URL, ChunkSize: 1})

	res, err := client.DecorationPipeline(ServiceRemediation).Run(context.Background(),
		Components("pkg:npm/a@1", "pkg:npm/missing-b@1"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Remediation == nil || res.Remediation.Response == nil {
		t.Fatalf("no remediation layer: errors %v", res.Errors)
	}
	if got := res.Remediation.Response.Status.Message; got != "Resolved 1 of 2 purls" {
		t.Errorf("status message = %q, want \"Resolved 1 of 2 purls\"", got)
	}
	if !strings.Contains(res.String(), `"remediation"`) {
		t.Error("keyed JSON has no remediation entry")
	}
}
