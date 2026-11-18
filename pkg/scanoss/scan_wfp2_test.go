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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// uploadQueries runs a short chunked scan and returns the query string of every upload
// POST, so a test can assert what rode along with each block.
func uploadQueries(t *testing.T, opts ...ScanOption) []url.Values {
	t.Helper()
	mock := &scanMock{completeAt: 1, result: json.RawMessage(`{"files":[],"components":{}}`)}
	inner := mock.handler()
	var mu sync.Mutex
	var queries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			queries = append(queries, r.URL.Query())
			mu.Unlock()
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)

	c := mustNew(t, Config{APIURL: srv.URL, Workers: 1, RetryBackoffBase: time.Millisecond})
	all := append([]ScanOption{WithChunkBytes(4), WithPollInterval(time.Millisecond)}, opts...)
	if _, err := c.Scan.WFP(context.Background(), []byte("0123456789abc"), all...); err != nil {
		t.Fatalf("scan: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(queries) == 0 {
		t.Fatal("no upload POST was recorded")
	}
	return queries
}

// WithWFP2 must put enable_wfp2=true on every block: the server rejects a session whose
// blocks disagree, and max_components already proves the per-block query survives chunking
// and retries, so wfp2 rides the same path.
func TestWFP2OptInSentOnEveryBlock(t *testing.T) {
	for i, q := range uploadQueries(t, WithWFP2()) {
		if got := q[enableWFP2Param]; len(got) != 1 || got[0] != "true" {
			t.Errorf("block %d: %s = %v, want [true]", i, enableWFP2Param, got)
		}
	}
}

// Without the option the parameter is absent entirely — the one thing that keeps a
// non-opting scan byte-for-byte identical to today.
func TestWFP2NotSentByDefault(t *testing.T) {
	for i, q := range uploadQueries(t) {
		if _, present := q[enableWFP2Param]; present {
			t.Errorf("block %d carried %s though WithWFP2 was not set: %v", i, enableWFP2Param, q[enableWFP2Param])
		}
	}
}

// The opt-in and the component limit are independent query parameters; setting both must
// send both on every block.
func TestWFP2CoexistsWithMaxComponents(t *testing.T) {
	for i, q := range uploadQueries(t, WithWFP2(), fiveComponents(t)) {
		if got := q[enableWFP2Param]; len(got) != 1 || got[0] != "true" {
			t.Errorf("block %d: %s = %v, want [true]", i, enableWFP2Param, got)
		}
		if got := q[maxComponentsParam]; len(got) != 1 || got[0] != "5" {
			t.Errorf("block %d: %s = %v, want [5]", i, maxComponentsParam, got)
		}
	}
}
