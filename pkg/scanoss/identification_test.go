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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/internal/version"
)

func captureServer(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header { return got }
}

func callAPI(t *testing.T, c *Client) {
	t.Helper()
	if _, err := c.Components.Versions(context.Background(), "pkg:github/scanoss/engine", 1); err != nil {
		t.Fatalf("Versions: %v", err)
	}
}

func TestUserAgent(t *testing.T) {
	sdk := "scanoss.go/" + strings.TrimPrefix(version.Version(), "v")
	tests := []struct {
		name, userAgent, want string
	}{
		{"sdk token alone", "", sdk},
		{"caller product first", "earnie/1.8.2 (deploy=self-hosted)", "earnie/1.8.2 (deploy=self-hosted) " + sdk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, headers := captureServer(t)
			callAPI(t, mustNew(t, Config{APIURL: srv.URL, UserAgent: tt.userAgent}))
			if got := headers().Get("User-Agent"); got != tt.want {
				t.Errorf("User-Agent = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHeadersSentAlongsideAuth(t *testing.T) {
	srv, headers := captureServer(t)
	callAPI(t, mustNew(t, Config{
		APIURL:  srv.URL,
		APIKey:  "secret",
		Headers: http.Header{"X-Scanoss-Client-Instance": {"0192f3c4-7b1e-7c3a-9a55-5f0c2f9f6a10"}},
	}))
	got := headers()
	if v := got.Get("X-Scanoss-Client-Instance"); v != "0192f3c4-7b1e-7c3a-9a55-5f0c2f9f6a10" {
		t.Errorf("X-Scanoss-Client-Instance = %q", v)
	}
	if got.Get("X-Api-Key") != "secret" || got.Get("X-Session") != "secret" {
		t.Errorf("auth headers = %q / %q, want the API key in both", got.Get("X-Api-Key"), got.Get("X-Session"))
	}
}

func TestHeadersRejectReservedNames(t *testing.T) {
	for _, name := range []string{"x-api-key", "X-Session", "Content-Type", "user-agent", "content-range", "X-Scan-Id"} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Config{Headers: http.Header{name: {"x"}}}); err == nil {
				t.Errorf("New accepted Headers carrying %s", name)
			}
		})
	}
}

type ctxKey struct{}

type recordingTransport struct {
	next      http.RoundTripper
	requests  int
	requestID any
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.requests++
	rt.requestID = req.Context().Value(ctxKey{})
	return rt.next.RoundTrip(req)
}

func TestHTTPClientSendsRequests(t *testing.T) {
	srv, headers := captureServer(t)
	rt := &recordingTransport{next: http.DefaultTransport}
	c := mustNew(t, Config{
		APIURL:     srv.URL,
		APIKey:     "secret",
		HTTPClient: &http.Client{Transport: rt},
	})
	ctx := context.WithValue(context.Background(), ctxKey{}, "req_01")
	if _, err := c.Components.Versions(ctx, "pkg:github/scanoss/engine", 1); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if rt.requests != 1 {
		t.Fatalf("caller's transport saw %d requests, want 1", rt.requests)
	}
	if rt.requestID != "req_01" {
		t.Errorf("request context value = %v, want req_01", rt.requestID)
	}
	if got := headers().Get("X-Api-Key"); got != "secret" {
		t.Errorf("X-Api-Key = %q through the caller's client", got)
	}
}

func TestHTTPClientRejectsTransportSettings(t *testing.T) {
	tests := map[string]Config{
		"proxy":    {Proxy: "http://proxy.example.com:8080"},
		"ca":       {CACertFile: "ca.pem"},
		"insecure": {InsecureTLS: true},
		"timeout":  {Timeout: 1},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			cfg.HTTPClient = &http.Client{}
			if _, err := New(cfg); err == nil {
				t.Error("New accepted HTTPClient with a transport setting it would ignore")
			}
		})
	}
}
