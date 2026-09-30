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

// Package scanoss is a Go SDK for the SCANOSS component services
// (cryptography, vulnerabilities, licenses, geoprovenance).
//
// Each decoration is a grouped service on the Client; chunking the request into
// batches and querying those batches concurrently with a pool of workers is
// handled internally and is transparent to the caller:
//
//	client, err := scanoss.New(scanoss.Config{APIKey: key})
//	res, err := client.Vulnerabilities.Components(ctx, comps) // batch
//	res, err := client.Vulnerabilities.Component(ctx, comp)   // single
//	res, err := client.Licenses.Components(ctx, comps)
//	res, err := client.Cryptography.Algorithms(ctx, comps)
//	res, err := client.Geoprovenance.Origins(ctx, comps)
//
// New is the only way to build a Client. Everything client-wide — credentials,
// endpoint, proxy and TLS, concurrency, retries — is a field of Config, whose zero
// value is the default configuration.
//
// The client also exposes a batch scan service that uploads WFP fingerprints and
// returns match results:
//
//	res, err := client.Scan.WFP(ctx, wfp) // upload (parallel chunks) + poll
//
// Per-call tuning stays a functional option: WithChunkBytes for the upload block size,
// WithScanReporter for progress, WithScanIDNotify to capture the scan id for optional
// recovery via Scan.Wait.
package scanoss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/scanoss/scanoss.go/internal/logging"
)

// Client is the SCANOSS SDK entry point. Create one with New and reuse it; it
// is safe for concurrent use.
type Client struct {
	apiURL string
	header http.Header
	// transport is the SDK's HTTP transport layer (http client + auth + retries).
	// The Client composes it rather than being one — see transport.go.
	transport *httpTransport
	// chunkSize is the number of PURLs per decoration request (Config.ChunkSize),
	// shared by every decoration service.
	chunkSize int
	workers   int
	// Decoration services (grouped public API). Wired in New.
	Vulnerabilities VulnerabilityAPI
	Licenses        LicenseAPI
	Cryptography    CryptographyAPI
	Geoprovenance   GeoprovenanceAPI
	Copyright       CopyrightAPI
	Components      ComponentsAPI
	Dependencies    DependencyAPI

	// Contents service (raw source retrieval by file hash). Wired in New.
	Contents ContentsAPI

	// Scan service (batch WFP scanning). Wired in New.
	Scan ScanAPI
}

// New creates a Client from cfg. It reports a configuration it cannot apply — an
// unreadable CA file, a proxy without a scheme — so a bad setting fails here instead of
// on the first request.
func New(cfg Config) (*Client, error) {
	httpClient, err := cfg.httpClient()
	if err != nil {
		return nil, err
	}
	header, err := cfg.requestHeader()
	if err != nil {
		return nil, err
	}
	identifying := []string{"X-Api-Key", "X-Session"}
	for name := range cfg.Headers {
		identifying = append(identifying, name)
	}
	httpClient = dropOnHostChange(httpClient, identifying)
	apiURL := DefaultAPIURL
	if cfg.APIURL != "" {
		apiURL = strings.TrimRight(cfg.APIURL, "/")
	}

	c := &Client{
		apiURL:    apiURL,
		header:    header,
		chunkSize: positiveOr(cfg.ChunkSize, DefaultChunkSize),
		workers:   positiveOr(cfg.Workers, DefaultWorkers),
		transport: &httpTransport{
			httpClient:         httpClient,
			apiKey:             cfg.APIKey,
			maxRetries:         retryCount(cfg.MaxRetries),
			retryBackoffBase:   positiveOr(cfg.RetryBackoffBase, DefaultRetryBackoffBase),
			maxServerRetryWait: positiveOr(cfg.MaxServerRetryWait, DefaultMaxServerRetryWait),
		},
	}
	// Wire the per-service handles to this client.
	c.Vulnerabilities = vulnerabilityService{c}
	c.Licenses = licenseService{c}
	c.Cryptography = cryptographyService{c}
	c.Geoprovenance = geoprovenanceService{c}
	c.Copyright = copyrightService{c}
	c.Components = componentsService{c}
	c.Dependencies = dependencyService{c}
	c.Contents = contentsService{c}
	c.Scan = scanService{c}
	return c, nil
}

// newRequest builds a request against endpoint, resolved relative to the API base
// URL. Every request the SDK sends is built here, so the base URL is joined — and the
// failure wrapped — in one place.
func (c *Client) newRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.apiURL+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header = c.header.Clone()
	return req, nil
}

// do sends req through the transport and turns an unacceptable status into an error.
// Any 2xx is success — restricting this to 200/202 used to turn a 201 Created or a
// 204 No Content into a failure.
//
// Deciding which statuses are failures is an API-level call, so it is made here rather
// than in the transport, which only reports what came back. Every response the SDK
// receives passes through this method.
func (c *Client) do(ctx context.Context, req *http.Request) (response, error) {
	res, err := c.transport.do(ctx, req)
	if err != nil {
		return res, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res, &StatusError{StatusCode: res.StatusCode, Body: string(res.Body)}
	}
	return res, nil
}

// get issues a GET to endpoint with the given query parameters and returns the raw
// response body.
//
// err alone tells the caller the call failed, status included — see do. The body comes
// back even then, so the caller can report what the server said.
func (c *Client) get(ctx context.Context, endpoint string, query url.Values) ([]byte, error) {
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := c.newRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.do(ctx, req)
	return res.Body, err
}

// postJSON sends payload as the JSON body of a POST to endpoint and returns the raw
// response body. Status handling and the body-on-error rule are the same as in get.
func (c *Client) postJSON(ctx context.Context, endpoint string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body: %w", err)
	}
	req, err := c.newRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.do(ctx, req)
	return res.Body, err
}

// SetLogger routes the SDK's diagnostics to lg — every package it is built from, not
// just this one. A nil lg restores silence.
//
// The SDK logs nothing until this is called: it will not write to its consumer's stderr
// uninvited. Pass slog.Default() to fold its records into the application's own stream,
// or a handler of your own to keep them apart or drop them.
//
// It is process-wide rather than per-client because most of this SDK is local work —
// filtering, fingerprinting, parsing manifests, rendering SBOMs — with no client to hang
// a logger off. Call it during initialisation.
func SetLogger(lg *slog.Logger) { logging.Set(lg) }
