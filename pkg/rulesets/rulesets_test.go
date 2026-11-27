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

package rulesets

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKeyID = "test-key"

var t0 = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

// fakeAPI serves one ruleset the way the rulesets API does.
type fakeAPI struct {
	t    *testing.T
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey

	mu        sync.Mutex
	name      string
	version   string
	files     map[string]string
	leaseTTL  time.Duration
	status    int                // non-zero: every request answers it
	checksum  string             // overrides X-Checksum-SHA256
	mutate    func(*Lease)       // edits the lease before signing
	signWith  ed25519.PrivateKey // signs with another key
	now       func() time.Time
	downloads int
	releases  int
	lastKey   string
	lastSess  string
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAPI{t: t, priv: priv, pub: pub, name: "ai", version: "v1.0.0",
		files: map[string]string{"python/models.cards": "card: one\n"}, leaseTTL: 720 * time.Hour,
		now: func() time.Time { return t0 }}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAPI) payload() []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range f.files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastKey, f.lastSess = r.Header.Get("X-Api-Key"), r.Header.Get("X-Session")
	if f.status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"status":"error","error":{"code":"SOME_CODE","message":"refused"}}`))
		return
	}
	base := "/v3/ai/rulesets"
	p := strings.TrimPrefix(r.URL.Path, base)
	parts := strings.Split(strings.Trim(p, "/"), "/")
	payload := f.payload()
	switch {
	case p == "":
		_ = json.NewEncoder(w).Encode([]Summary{{Name: f.name, Domain: "ai", Latest: f.version, Versions: []string{f.version}}})
	case len(parts) >= 2 && parts[0] == f.name && (parts[1] == "latest" || parts[1] == f.version):
		if len(parts) == 2 {
			f.releases++
			_ = json.NewEncoder(w).Encode(Release{Format: ReleaseFormat, Name: f.name, Domain: "ai", Version: f.version,
				CreatedAt: t0, PayloadSHA256: sha256Hex(payload), PayloadSize: int64(len(payload))})
			return
		}
		f.downloads++
		now := f.now()
		l := Lease{Format: LeaseFormat, Name: f.name, Domain: "ai", Version: f.version, PayloadSHA256: sha256Hex(payload),
			BundleSHA256: sha256Hex(payload), KeyRef: "k1", Tenant: "acme", IssuedAt: now, ExpiresAt: now.Add(f.leaseTTL), SigningKeyID: testKeyID}
		if f.mutate != nil {
			f.mutate(&l)
		}
		leaseJSON, _ := json.Marshal(l)
		key := f.priv
		if f.signWith != nil {
			key = f.signWith
		}
		env, _ := json.Marshal(envelope{Format: LeaseFormat, Lease: leaseJSON, Signature: ed25519.Sign(key, leaseJSON)})
		sum := sha256Hex(payload)
		if f.checksum != "" {
			sum = f.checksum
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set(ChecksumHeader, sum)
		w.Header().Set(LeaseHeader, base64.StdEncoding.EncodeToString(env))
		_, _ = w.Write(payload)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":"error","error":{"code":"RULESET_NOT_FOUND","message":"nope"}}`))
	}
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newTestClient(t *testing.T, f *fakeAPI, url, cacheDir string, clk *clock, apiKey string) *Client {
	t.Helper()
	c, err := New(Options{Domain: "ai", APIURL: url, APIKey: apiKey, CacheDir: cacheDir, RunDir: t.TempDir(),
		Keys: map[string]ed25519.PublicKey{testKeyID: f.pub}, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fetch(t *testing.T, c *Client, version string) *Ruleset {
	t.Helper()
	rs, err := c.Fetch(context.Background(), "ai", version)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	t.Cleanup(func() { _ = rs.Close() })
	return rs
}

func TestFetchDownloadsVerifiesCachesAndExtracts(t *testing.T) {
	f, srv := newFakeAPI(t)
	cacheDir := t.TempDir()
	clk := &clock{t0}
	c := newTestClient(t, f, srv.URL, cacheDir, clk, "secret-key")

	list, err := c.List(context.Background())
	if err != nil || len(list) != 1 || list[0].Latest != "v1.0.0" {
		t.Fatalf("List = %+v, %v", list, err)
	}
	rel, err := c.Release(context.Background(), "ai", "latest")
	if err != nil || rel.Version != "v1.0.0" {
		t.Fatalf("Release = %+v, %v", rel, err)
	}

	rs := fetch(t, c, "latest")
	if rs.Source != SourceNetwork || rs.Version != "v1.0.0" || rs.Lease.Tenant != "acme" {
		t.Fatalf("ruleset = %+v", rs)
	}
	if f.lastKey != "secret-key" || f.lastSess != "secret-key" {
		t.Fatalf("API key headers = %q, %q", f.lastKey, f.lastSess)
	}
	got, err := os.ReadFile(filepath.Join(rs.Dir, "python", "models.cards"))
	if err != nil || string(got) != "card: one\n" {
		t.Fatalf("extracted file = %q, %v", got, err)
	}
	if fi, _ := os.Stat(rs.Dir); fi.Mode().Perm() != 0o700 || !strings.HasPrefix(filepath.Base(rs.Dir), "run-") {
		t.Fatalf("run dir %s mode %v", rs.Dir, fi.Mode().Perm())
	}

	host := strings.ReplaceAll(strings.TrimPrefix(srv.URL, "http://"), ":", "_")
	dir := filepath.Join(cacheDir, host, "ai", "latest")
	for _, name := range []string{bundleFile, leaseFile, metaFile} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("cache file %s: %v %v", name, fi, err)
		}
	}
	sealed, _ := os.ReadFile(filepath.Join(dir, bundleFile))
	if bytes.Contains(sealed, f.payload()[:16]) {
		t.Fatal("bundle.enc holds the plaintext bundle")
	}

	runDir := rs.Dir
	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Close left the run dir")
	}
}

func TestFetchTTLAndRevalidation(t *testing.T) {
	f, srv := newFakeAPI(t)
	clk := &clock{t0}
	c := newTestClient(t, f, srv.URL, t.TempDir(), clk, "k")

	fetch(t, c, "latest")
	clk.now = t0.Add(23 * time.Hour)
	if rs := fetch(t, c, "latest"); rs.Source != SourceCache {
		t.Fatalf("within 24h: source %s", rs.Source)
	}
	if f.downloads != 1 || f.releases != 0 {
		t.Fatalf("cache hit asked the API: downloads=%d releases=%d", f.downloads, f.releases)
	}

	clk.now = t0.Add(25 * time.Hour)
	if rs := fetch(t, c, "latest"); rs.Source != SourceRevalidated {
		t.Fatalf("past TTL, same release: source %s", rs.Source)
	}
	if f.downloads != 1 {
		t.Fatalf("revalidation downloaded again")
	}

	clk.now = t0.Add(50 * time.Hour)
	f.version, f.files = "v1.1.0", map[string]string{"python/models.cards": "card: two\n"}
	rs := fetch(t, c, "latest")
	if rs.Source != SourceNetwork || rs.Version != "v1.1.0" || f.downloads != 2 {
		t.Fatalf("new release: %+v downloads=%d", rs, f.downloads)
	}
}

func TestFetchPinnedTTL(t *testing.T) {
	f, srv := newFakeAPI(t)
	clk := &clock{t0}
	c := newTestClient(t, f, srv.URL, t.TempDir(), clk, "k")
	fetch(t, c, "v1.0.0")
	clk.now = t0.Add(6 * 24 * time.Hour)
	if rs := fetch(t, c, "v1.0.0"); rs.Source != SourceCache {
		t.Fatalf("pinned at 6d: %s", rs.Source)
	}
	clk.now = t0.Add(8 * 24 * time.Hour)
	if rs := fetch(t, c, "v1.0.0"); rs.Source == SourceCache {
		t.Fatalf("pinned at 8d still served from cache without asking")
	}
}

func TestFetchStaleWhenUnreachable(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.leaseTTL = 90 * 24 * time.Hour
	clk := &clock{t0}
	cacheDir := t.TempDir()
	c := newTestClient(t, f, srv.URL, cacheDir, clk, "k")
	fetch(t, c, "latest")
	srv.Close()

	clk.now = t0.Add(29 * 24 * time.Hour)
	if rs := fetch(t, c, "latest"); rs.Source != SourceStale || !rs.FetchedAt.Equal(t0) {
		t.Fatalf("API down at 29d: %+v", rs)
	}
	clk.now = t0.Add(31 * 24 * time.Hour)
	if _, err := c.Fetch(context.Background(), "ai", "latest"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("API down at 31d: %v", err)
	}
}

func TestFetchStaleOnServerErrorButNotOnRefusal(t *testing.T) {
	f, srv := newFakeAPI(t)
	clk := &clock{t0}
	c := newTestClient(t, f, srv.URL, t.TempDir(), clk, "k")
	fetch(t, c, "latest")
	clk.now = t0.Add(48 * time.Hour)

	f.status = http.StatusServiceUnavailable
	if rs := fetch(t, c, "latest"); rs.Source != SourceStale {
		t.Fatalf("503: source %s", rs.Source)
	}
	f.status = http.StatusForbidden
	_, err := c.Fetch(context.Background(), "ai", "latest")
	var se *StatusError
	if !errors.Is(err, ErrUnavailable) || !errors.As(err, &se) || se.StatusCode != 403 || se.Code != "SOME_CODE" {
		t.Fatalf("403: %v", err)
	}
}

func TestFetchExpiredCachedLeaseIsNotUsed(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.leaseTTL = 36 * time.Hour
	clk := &clock{t0}
	c := newTestClient(t, f, srv.URL, t.TempDir(), clk, "k")
	fetch(t, c, "latest")
	srv.Close()
	clk.now = t0.Add(40 * time.Hour)
	_, err := c.Fetch(context.Background(), "ai", "latest")
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired cached lease with API down: %v", err)
	}
}

func TestFetchUpgradeRequired(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusUpgradeRequired} {
		f, srv := newFakeAPI(t)
		f.status = status
		c := newTestClient(t, f, srv.URL, t.TempDir(), &clock{t0}, "k")
		_, err := c.Fetch(context.Background(), "ai", "latest")
		if !errors.Is(err, ErrUpgradeRequired) || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%d: %v", status, err)
		}
		if _, err := c.List(context.Background()); !errors.Is(err, ErrUpgradeRequired) {
			t.Fatalf("%d list: %v", status, err)
		}
	}
}

func TestFetchRejectsBadBundles(t *testing.T) {
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name  string
		setup func(*fakeAPI)
		want  error
	}{
		{"checksum header", func(f *fakeAPI) { f.checksum = strings.Repeat("0", 64) }, ErrChecksum},
		{"lease bundle hash", func(f *fakeAPI) { f.mutate = func(l *Lease) { l.BundleSHA256 = strings.Repeat("a", 64) } }, ErrChecksum},
		{"signature", func(f *fakeAPI) { f.signWith = otherKey }, ErrSignature},
		{"unknown key", func(f *fakeAPI) { f.mutate = func(l *Lease) { l.SigningKeyID = "other" } }, ErrUnknownKey},
		{"expired", func(f *fakeAPI) { f.leaseTTL = -time.Second }, ErrLeaseExpired},
		{"other ruleset", func(f *fakeAPI) { f.mutate = func(l *Lease) { l.Name = "ai-open" } }, ErrBadLease},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFakeAPI(t)
			tc.setup(f)
			cacheDir := t.TempDir()
			c := newTestClient(t, f, srv.URL, cacheDir, &clock{t0}, "k")
			_, err := c.Fetch(context.Background(), "ai", "latest")
			if !errors.Is(err, tc.want) || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if entries, _ := os.ReadDir(cacheDir); len(entries) != 0 {
				t.Fatal("a rejected bundle was cached")
			}
		})
	}
}

func TestFetchNoTrustedKeys(t *testing.T) {
	f, srv := newFakeAPI(t)
	c, err := New(Options{Domain: "ai", APIURL: srv.URL, NoCache: true, Keys: map[string]ed25519.PublicKey{}})
	if err != nil {
		t.Fatal(err)
	}
	_ = f
	if _, err := c.Fetch(context.Background(), "ai", "latest"); !errors.Is(err, ErrNoTrustedKeys) {
		t.Fatalf("err = %v", err)
	}
}

func TestCacheEncryptionRoundTripAndKeyBinding(t *testing.T) {
	f, srv := newFakeAPI(t)
	cacheDir := t.TempDir()
	clk := &clock{t0}
	c := newTestClient(t, f, srv.URL, cacheDir, clk, "key-one")

	plain := []byte("bundle bytes")
	aad := c.aad("ai", "latest")
	sealed, err := c.encrypt(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.decrypt(sealed, aad); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q, %v", got, err)
	}
	if _, err := c.decrypt(sealed, c.aad("ai", "v1.0.0")); err == nil {
		t.Fatal("decrypted under another version's AAD")
	}
	other := newTestClient(t, f, srv.URL, cacheDir, clk, "key-two")
	if _, err := other.decrypt(sealed, aad); err == nil {
		t.Fatal("decrypted with another API key")
	}

	// A cache written under one key is re-downloaded under another.
	fetch(t, c, "latest")
	if rs := fetch(t, other, "latest"); rs.Source != SourceNetwork || f.downloads != 2 {
		t.Fatalf("other key: source %s downloads %d", rs.Source, f.downloads)
	}
}

func TestNoCacheNeitherReadsNorWrites(t *testing.T) {
	f, srv := newFakeAPI(t)
	c, err := New(Options{Domain: "ai", APIURL: srv.URL, NoCache: true, Keys: map[string]ed25519.PublicKey{testKeyID: f.pub},
		Now: (&clock{t0}).Now, RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	fetch(t, c, "latest")
	fetch(t, c, "latest")
	if f.downloads != 2 {
		t.Fatalf("downloads = %d", f.downloads)
	}
}

func TestExtractRefusesEscapesAndLinks(t *testing.T) {
	build := func(hdr *tar.Header, body string) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		hdr.Size = int64(len(body))
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write([]byte(body))
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes()
	}
	for _, hdr := range []*tar.Header{
		{Name: "../evil", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "/abs", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "a/../../evil", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	} {
		if err := extractTarGz(build(hdr, "x"), t.TempDir()); err == nil {
			t.Errorf("%q was extracted", hdr.Name)
		}
	}
}

func TestExtractSkipsPAXGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "abc"}})
	_ = tw.WriteHeader(&tar.Header{Name: "a/rules.cards", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("x"))
	_ = tw.Close()
	_ = gz.Close()
	dir := t.TempDir()
	if err := extractTarGz(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a", "rules.cards")); err != nil {
		t.Fatal(err)
	}
}

func TestParseRefAndKeys(t *testing.T) {
	if n, v, err := ParseRef("ai"); err != nil || n != "ai" || v != "latest" {
		t.Fatalf("ParseRef(ai) = %s %s %v", n, v, err)
	}
	if n, v, err := ParseRef("ai-open@v0.2.1"); err != nil || n != "ai-open" || v != "v0.2.1" {
		t.Fatalf("ParseRef = %s %s %v", n, v, err)
	}
	for _, bad := range []string{"AI", "ai@main", "../x@latest", ""} {
		if _, _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) accepted", bad)
		}
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	b64 := base64.StdEncoding.EncodeToString(pub)
	t.Setenv(PubKeysEnv, " srv-x:"+b64+" , ")
	keys, err := TrustedKeys()
	if err != nil || !keys["srv-x"].Equal(pub) {
		t.Fatalf("TrustedKeys = %v, %v", keys, err)
	}
	for _, bad := range []string{"nokey", "id:notbase64!", "id:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParsePublicKeys(bad); err == nil {
			t.Errorf("ParsePublicKeys(%q) accepted", bad)
		}
	}
}
