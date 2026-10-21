// SPDX-License-Identifier: MIT

package scanoss

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hops serves api.test on ports 80, 443 and 8443, and other.test, each from a real
// httptest server. A request to /to/<url> redirects there; any other request records its
// headers under "<scheme> <path>".
type hops struct {
	seen   map[string]http.Header
	client *http.Client
}

func newHops(t *testing.T) *hops {
	t.Helper()
	h := &hops{seen: map[string]http.Header{}}
	handler := func(scheme string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if to, ok := strings.CutPrefix(r.URL.Path, "/to/"); ok {
				http.Redirect(w, r, to, http.StatusTemporaryRedirect)
				return
			}
			h.seen[scheme+" "+r.URL.Path] = r.Header.Clone()
			_, _ = w.Write([]byte("{}"))
		}
	}
	plain := httptest.NewServer(handler("http"))
	secure := httptest.NewTLSServer(handler("https"))
	t.Cleanup(plain.Close)
	t.Cleanup(secure.Close)
	addr := map[string]string{
		"api.test:80":    plain.Listener.Addr().String(),
		"api.test:443":   secure.Listener.Addr().String(),
		"api.test:8443":  secure.Listener.Addr().String(),
		"other.test:443": secure.Listener.Addr().String(),
	}
	var d net.Dialer
	h.client = &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if mapped, ok := addr[strings.ToLower(a)]; ok {
				a = mapped
			}
			return d.DialContext(ctx, network, a)
		},
	}}
	return h
}

func TestRedirectIdentityByOrigin(t *testing.T) {
	tests := []struct {
		name, apiURL, redirect, final string
		keep                          bool
	}{
		{"https to http on the same host drops it", "https://api.test", "http://api.test/final", "http /final", false},
		{"http to https on the same host keeps it", "http://api.test", "https://api.test/final", "https /final", true},
		{"an explicit default port is the same origin", "https://api.test", "https://api.test:443/final", "https /final", true},
		{"hostname case is ignored", "https://api.test", "https://API.test/final", "https /final", true},
		{"another port drops it", "https://api.test", "https://api.test:8443/final", "https /final", false},
		{"another host drops it", "https://api.test", "https://other.test/final", "https /final", false},
		{"leaving and coming back does not restore it", "https://api.test",
			"https://other.test/to/https://api.test/final", "https /final", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHops(t)
			c := mustNew(t, identifyingConfig(tt.apiURL, h.client))
			req, err := c.newRequest(http.MethodGet, "/to/"+tt.redirect, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.transport.do(context.Background(), req); err != nil {
				t.Fatalf("do: %v", err)
			}
			got, ok := h.seen[tt.final]
			if !ok {
				t.Fatalf("%s saw no request", tt.redirect)
			}
			for _, name := range identifyingHeaders {
				if kept := got.Get(name) != ""; kept != tt.keep {
					t.Errorf("%s kept = %v, want %v", name, kept, tt.keep)
				}
			}
		})
	}
}

func TestNewLeavesCallersClientUnchanged(t *testing.T) {
	client := &http.Client{}
	_ = mustNew(t, identifyingConfig("https://api.test", client))
	if client.CheckRedirect != nil {
		t.Error("New installed a CheckRedirect on the caller's client")
	}
}
