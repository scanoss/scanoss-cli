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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/scanoss/scanoss.go/internal/version"
)

// Defaults applied when the caller does not override them.
const (
	DefaultAPIURL     = "https://api.scanoss.com"
	DefaultChunkSize  = 10
	DefaultWorkers    = 5
	DefaultMaxRetries = 5
	// DefaultMaxServerRetryWait caps a single Retry-After wait. It is generous because it
	// bounds a wait the server asked for; the SDK's own waits are capped by maxRetryBackoff.
	DefaultMaxServerRetryWait = 5 * time.Minute
	// DefaultRetryBackoffBase is the first backoff wait; it doubles per attempt. With
	// DefaultMaxRetries that totals under 8s of waiting before a call gives up.
	DefaultRetryBackoffBase = 250 * time.Millisecond
	// DefaultTimeout bounds one request attempt, body transfer included. Sized for the
	// largest the SDK sends — a 1 MiB WFP chunk — over a poor link.
	DefaultTimeout = 120 * time.Second
)

// Config is the SDK's configuration. The zero value is the default configuration:
// every unset field falls back to its Default* constant.
type Config struct {
	// APIKey authenticates the requests. Empty means keyless, which the public
	// endpoint rejects and an on-prem one may allow.
	APIKey string
	// APIURL is the API base URL (default DefaultAPIURL). A trailing slash is trimmed.
	APIURL string

	// Proxy overrides HTTP_PROXY and HTTPS_PROXY for this client. It needs an http://
	// or https:// scheme; NO_PROXY still applies. Empty leaves Go's own environment
	// handling in place.
	Proxy string
	// CACertFile is a PEM file whose certificates are trusted in addition to the system
	// pool. Verification stays on: this adds an authority, it does not stop checking.
	CACertFile string
	// InsecureTLS disables certificate verification entirely. For self-signed or
	// internal endpoints only; prefer CACertFile, which keeps verification on.
	InsecureTLS bool
	// Timeout bounds one request attempt, body transfer included (default
	// DefaultTimeout). A negative value disables it. Retry-After waits happen between
	// attempts, so this does not cut them short.
	Timeout time.Duration

	// ChunkSize is the number of PURLs per decoration request (default
	// DefaultChunkSize), shared by every decoration service.
	ChunkSize int
	// Workers caps the concurrent requests (default DefaultWorkers). The effective
	// number is never larger than the number of chunks.
	Workers int
	// MaxRetries caps the retry count for a transient failure — a network error, a
	// truncated response, or a 429/5xx status (default DefaultMaxRetries). A negative
	// value disables retries; a request that fails once then fails the call.
	MaxRetries int
	// RetryBackoffBase is the first wait the SDK computes for itself, doubled per attempt
	// and capped internally (default DefaultRetryBackoffBase). A Retry-After the server
	// sent takes precedence over it.
	RetryBackoffBase time.Duration
	// MaxServerRetryWait caps a single Retry-After wait (default DefaultMaxServerRetryWait),
	// bounding a pathological server value. It does not bound RetryBackoffBase's waits.
	MaxServerRetryWait time.Duration

	// UserAgent is the caller's product token(s), e.g. "earnie/1.8.2 (deploy=hosted)".
	// The SDK appends its own "scanoss.go/<version>"; empty sends that token alone.
	UserAgent string
	// Headers are sent on every request, e.g. X-Scanoss-Client-Instance. New rejects
	// the headers the SDK sets itself: User-Agent, Content-Type, x-api-key, x-Session,
	// Content-Range and X-Scan-Id.
	Headers http.Header
	// HTTPClient, when set, sends every request instead of a client the SDK builds, so
	// a caller can wrap its transport (tracing, per-request headers). The SDK does not
	// modify it: its own Timeout, proxy and TLS settings apply, and New rejects a Config
	// that also sets Proxy, CACertFile, InsecureTLS or Timeout.
	HTTPClient *http.Client
}

var reservedHeaders = map[string]bool{
	"User-Agent": true, "Content-Type": true, "X-Api-Key": true, "X-Session": true,
	"Content-Range": true, "X-Scan-Id": true,
}

func (cfg Config) requestHeader() (http.Header, error) {
	header := http.Header{}
	for name, values := range cfg.Headers {
		// A map literal can hold a key in any case; Add canonicalizes it, so check that form.
		if reservedHeaders[http.CanonicalHeaderKey(name)] {
			return nil, fmt.Errorf("Config.Headers may not set %s, which the SDK sets itself", name)
		}
		for _, v := range values {
			header.Add(name, v)
		}
	}
	header.Set("User-Agent", userAgent(cfg.UserAgent))
	return header, nil
}

func userAgent(product string) string {
	sdk := "scanoss.go/" + strings.TrimPrefix(version.Version(), "v")
	if product = strings.TrimSpace(product); product != "" {
		return product + " " + sdk
	}
	return sdk
}

func (cfg Config) httpClient() (*http.Client, error) {
	if cfg.HTTPClient != nil {
		if cfg.Proxy != "" || cfg.CACertFile != "" || cfg.InsecureTLS || cfg.Timeout != 0 {
			return nil, errors.New("HTTPClient cannot be combined with Proxy, CACertFile, InsecureTLS or Timeout; configure them on the client")
		}
		return cfg.HTTPClient, nil
	}
	// With nothing to customise, leave Transport nil so the client shares
	// http.DefaultTransport, and with it one connection pool per process rather than a
	// private pool per client.
	if cfg.Proxy == "" && cfg.CACertFile == "" && !cfg.InsecureTLS {
		return &http.Client{Timeout: resolveTimeout(cfg.Timeout)}, nil
	}
	return newHTTPClient(httpClientOptions{
		Proxy:      cfg.Proxy,
		CACertFile: cfg.CACertFile,
		Insecure:   cfg.InsecureTLS,
		Timeout:    cfg.Timeout,
	})
}

// net/http strips only its built-in auth and cookie headers on a cross-host redirect and
// forwards every other header, X-Api-Key included. The 10-hop cap mirrors net/http's
// unexported defaultCheckRedirect.
func dropOnHostChange(client *http.Client, names []string) *http.Client {
	wrapped := *client
	next := client.CheckRedirect
	wrapped.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != via[0].URL.Host {
			for _, name := range names {
				req.Header.Del(name)
			}
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &wrapped
}

// retryCount resolves Config.MaxRetries: unset takes the default, and a negative value
// disables retries — the convention Timeout already uses in this Config.
func retryCount(n int) int {
	if n < 0 {
		return 0
	}
	return positiveOr(n, DefaultMaxRetries)
}

// positiveOr returns value when it is above zero and fallback otherwise: how an unset
// Config field falls back to its default. A negative value is a typo, not a setting.
func positiveOr[T int | time.Duration](value, fallback T) T {
	if value > 0 {
		return value
	}
	return fallback
}
