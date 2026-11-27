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

// Package rulesets downloads leased rulesets from the SCANOSS rulesets API
// (/v3/<domain>/rulesets), verifies them, caches them encrypted at rest and
// unpacks them into a private run directory.
//
//	c, err := rulesets.New(rulesets.Options{Domain: "ai", APIURL: url, APIKey: key})
//	rs, err := c.Fetch(ctx, "ai", "latest")
//	if errors.Is(err, rulesets.ErrUnavailable) { os.Exit(rulesets.ExitCode) }
//	defer rs.Close()
//	// rules are under rs.Dir
package rulesets

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// DefaultAPIURL is used when Options.APIURL is empty.
const DefaultAPIURL = "https://api.scanoss.com"

// Bounds on what is read from the API.
const (
	maxBundleSize   = 256 << 20
	maxMetadataSize = 4 << 20
)

const latest = "latest"

// Options configures a Client. Domain is required.
type Options struct {
	// Domain is the API path segment the rulesets live under, e.g. "ai".
	Domain string
	// APIURL is the API base URL (default DefaultAPIURL), without /v3.
	APIURL string
	// APIKey is sent as x-api-key and x-Session, like the SCANOSS SDK does. It
	// also derives the cache encryption key.
	APIKey string
	// HTTPClient sends the requests (default: a client with a 120s timeout).
	// scanoss.NewHTTPClient builds one with the CLI's proxy and TLS settings.
	HTTPClient *http.Client
	// UserAgent is sent as User-Agent when set.
	UserAgent string
	// CacheDir is the cache root (default DefaultCacheDir()).
	CacheDir string
	// NoCache neither reads nor writes the cache.
	NoCache bool
	// RunDir is where run-* directories are created (default os.TempDir()).
	RunDir string
	// Keys are the trusted lease signing keys (default TrustedKeys()).
	Keys map[string]ed25519.PublicKey
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Client talks to one rulesets domain of one API.
type Client struct {
	opts    Options
	base    *url.URL
	baseURL string
	http    *http.Client
	keys    map[string]ed25519.PublicKey
	now     func() time.Time
}

var validDomain = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// New validates opts and returns a Client.
func New(opts Options) (*Client, error) {
	if !validDomain.MatchString(opts.Domain) {
		return nil, fmt.Errorf("rulesets: invalid domain %q", opts.Domain)
	}
	apiURL := strings.TrimRight(opts.APIURL, "/")
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	base, err := url.Parse(apiURL)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("rulesets: invalid API URL %q", opts.APIURL)
	}
	keys := opts.Keys
	if keys == nil {
		if keys, err = TrustedKeys(); err != nil {
			return nil, fmt.Errorf("rulesets: %w", err)
		}
	}
	if opts.CacheDir == "" && !opts.NoCache {
		if opts.CacheDir, err = DefaultCacheDir(); err != nil {
			return nil, err
		}
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 120 * time.Second}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Client{opts: opts, base: base, baseURL: apiURL + "/v3/" + opts.Domain + "/rulesets", http: hc, keys: keys, now: now}, nil
}

// DefaultCacheDir is ~/.scanoss/scanoss-cli/cache/rulesets.
func DefaultCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("rulesets: locating home directory: %w", err)
	}
	return filepath.Join(home, ".scanoss", "scanoss-cli", "cache", "rulesets"), nil
}

// ParseRef splits "name@version"; a missing version is "latest".
func ParseRef(ref string) (name, version string, err error) {
	name, version, _ = strings.Cut(strings.TrimSpace(ref), "@")
	if version == "" {
		version = latest
	}
	if err := validateRef(name, version); err != nil {
		return "", "", err
	}
	return name, version, nil
}

var (
	validName    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	validVersion = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,2}([-+][0-9A-Za-z.+-]+)?$`)
)

func validateRef(name, version string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("rulesets: invalid ruleset name %q", name)
	}
	if version != latest && !validVersion.MatchString(version) {
		return fmt.Errorf("rulesets: version %q must be %q or a semver version", version, latest)
	}
	return nil
}

// List returns the rulesets the API serves for the domain.
func (c *Client) List(ctx context.Context) ([]Summary, error) {
	var out []Summary
	if err := c.getJSON(ctx, c.baseURL, &out); err != nil {
		return nil, fmt.Errorf("%w: list %s rulesets: %w", ErrUnavailable, c.opts.Domain, err)
	}
	return out, nil
}

// Release returns the release metadata of name@version ("latest" resolves).
func (c *Client) Release(ctx context.Context, name, version string) (Release, error) {
	if err := validateRef(name, version); err != nil {
		return Release{}, unavailable(name, version, err)
	}
	rel, err := c.release(ctx, name, version)
	if err != nil {
		return Release{}, unavailable(name, version, err)
	}
	return rel, nil
}

func (c *Client) release(ctx context.Context, name, version string) (Release, error) {
	var rel Release
	if err := c.getJSON(ctx, c.baseURL+"/"+name+"/"+version, &rel); err != nil {
		return Release{}, err
	}
	if rel.Format != ReleaseFormat {
		return Release{}, fmt.Errorf("unsupported release format %q", rel.Format)
	}
	return rel, nil
}

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	resp, err := c.get(ctx, u)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize))
	if err != nil {
		return &networkError{err}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", u, err)
	}
	return nil
}

// download fetches the bundle of name@version and verifies checksum and lease.
func (c *Client) download(ctx context.Context, name, version string) (bundle, envJSON []byte, l Lease, err error) {
	resp, err := c.get(ctx, c.baseURL+"/"+name+"/"+version+"/download")
	if err != nil {
		return nil, nil, Lease{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	bundle, err = io.ReadAll(io.LimitReader(resp.Body, maxBundleSize+1))
	if err != nil {
		return nil, nil, Lease{}, &networkError{err}
	}
	if len(bundle) > maxBundleSize {
		return nil, nil, Lease{}, fmt.Errorf("bundle larger than %d bytes", maxBundleSize)
	}
	if want := strings.ToLower(strings.TrimSpace(resp.Header.Get(ChecksumHeader))); want == "" || want != sha256Hex(bundle) {
		return nil, nil, Lease{}, fmt.Errorf("%w: %s %q", ErrChecksum, ChecksumHeader, want)
	}
	envJSON, err = base64.StdEncoding.DecodeString(strings.TrimSpace(resp.Header.Get(LeaseHeader)))
	if err != nil || len(envJSON) == 0 {
		return nil, nil, Lease{}, fmt.Errorf("%w: missing or malformed %s header", ErrBadLease, LeaseHeader)
	}
	if l, err = parseLease(envJSON, c.keys); err != nil {
		return nil, nil, Lease{}, err
	}
	if err := l.check(name, version, bundle, c.now()); err != nil {
		return nil, nil, Lease{}, err
	}
	return bundle, envJSON, l, nil
}

// get sends a GET with the API key headers and turns a non-200 into a
// StatusError and a transport failure into a networkError.
func (c *Client) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.opts.APIKey != "" {
		req.Header.Set("x-api-key", c.opts.APIKey)
		req.Header.Set("x-Session", c.opts.APIKey)
	}
	if c.opts.UserAgent != "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &networkError{err}
	}
	if resp.StatusCode == http.StatusOK {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	se := &StatusError{StatusCode: resp.StatusCode}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if data, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); rerr == nil && json.Unmarshal(data, &body) == nil {
		se.Code, se.Message = body.Error.Code, body.Error.Message
	}
	return nil, se
}
