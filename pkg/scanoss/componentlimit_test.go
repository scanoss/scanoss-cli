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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseComponentLimit(t *testing.T) {
	valid := map[string]string{"1": "1", "5": "5", "007": "7", "all": "all"}
	for in, want := range valid {
		l, err := ParseComponentLimit(in)
		if err != nil {
			t.Errorf("ParseComponentLimit(%q): %v", in, err)
			continue
		}
		if !l.IsSet() || l.String() != want {
			t.Errorf("ParseComponentLimit(%q) = %q (set %v), want %q", in, l.String(), l.IsSet(), want)
		}
	}

	invalid := []string{"0", "-1", "2.5", "", " 3", "3 ", "ALL", "All", "+3", "1e3", "0x10", "99999999999999999999"}
	for _, in := range invalid {
		_, err := ParseComponentLimit(in)
		if err == nil {
			t.Errorf("ParseComponentLimit(%q) accepted", in)
			continue
		}
		if want := `must be a positive integer or "all"`; !strings.Contains(err.Error(), want) {
			t.Errorf("ParseComponentLimit(%q) error %q lacks %q", in, err, want)
		}
	}
}

func TestComponentLimitConstructors(t *testing.T) {
	var zero ComponentLimit
	if zero.IsSet() || zero.String() != "" {
		t.Errorf("zero value must be unset, got %q", zero.String())
	}
	if _, err := ComponentsUpTo(0); err == nil {
		t.Error("ComponentsUpTo(0) accepted")
	}
	if _, err := ComponentsUpTo(-3); err == nil {
		t.Error("ComponentsUpTo(-3) accepted")
	}
	if l, err := ComponentsUpTo(4); err != nil || l.String() != "4" {
		t.Errorf("ComponentsUpTo(4) = %q, %v", l.String(), err)
	}
	if AllComponents().String() != "all" {
		t.Errorf("AllComponents() = %q", AllComponents().String())
	}
}

type queryRecorder struct {
	mu      sync.Mutex
	queries []url.Values
	inner   http.HandlerFunc
}

func (q *queryRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		q.mu.Lock()
		q.queries = append(q.queries, r.URL.Query())
		q.mu.Unlock()
	}
	q.inner(w, r)
}

func scanWithOptions(t *testing.T, opts ...ScanOption) []url.Values {
	t.Helper()
	mock := &scanMock{completeAt: 1, result: json.RawMessage(`{"files":[],"components":{}}`)}
	rec := &queryRecorder{inner: mock.handler()}
	c := newTestClient(t, rec)
	opts = append([]ScanOption{WithChunkBytes(4), WithPollInterval(time.Millisecond)}, opts...)
	if _, err := c.Scan.WFP(context.Background(), []byte("0123456789abc"), opts...); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rec.queries) != 4 {
		t.Fatalf("recorded %d uploads, want 4 so that \"every chunk\" is meaningful", len(rec.queries))
	}
	return rec.queries
}

func TestMaxComponentsSentOnEveryChunk(t *testing.T) {
	five, err := ComponentsUpTo(5)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		opt  ScanOption
		want string
	}{
		{"number", WithMaxComponents(five), "5"},
		{"all", WithMaxComponents(AllComponents()), "all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, q := range scanWithOptions(t, tt.opt) {
				if got := q[maxComponentsParam]; len(got) != 1 || got[0] != tt.want {
					t.Errorf("chunk %d: %s = %v, want [%s]", i, maxComponentsParam, got, tt.want)
				}
			}
		})
	}
}

func TestMaxComponentsUnsetSendsNothing(t *testing.T) {
	for name, opts := range map[string][]ScanOption{
		"option absent": nil,
		"zero limit":    {WithMaxComponents(ComponentLimit{})},
	} {
		t.Run(name, func(t *testing.T) {
			for i, q := range scanWithOptions(t, opts...) {
				if len(q) != 0 {
					t.Errorf("chunk %d carried a query %v, want none", i, q)
				}
			}
		})
	}
}

func fiveComponents(t *testing.T) ScanOption {
	t.Helper()
	l, err := ComponentsUpTo(5)
	if err != nil {
		t.Fatal(err)
	}
	return WithMaxComponents(l)
}

// A server that refuses the parameter (a session whose blocks disagree, or a bad value) answers 400.
// The scan has to fail and say so; swallowing it like a 409 would report a scan that never ran.
func TestMaxComponentsRejectedBlockFailsTheScan(t *testing.T) {
	mock := &scanMock{completeAt: 1, result: json.RawMessage(`{"files":[],"components":{}}`)}
	inner := mock.handler()
	var rejected int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Range"), "bytes 4-") {
			atomic.AddInt32(&rejected, 1)
			http.Error(w, "max_components must be the same on every block", http.StatusBadRequest)
			return
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	c := mustNew(t, Config{APIURL: srv.URL, Workers: 1, RetryBackoffBase: time.Millisecond})

	_, err := c.Scan.WFP(context.Background(), []byte("0123456789abc"),
		WithChunkBytes(4), WithPollInterval(time.Millisecond), fiveComponents(t))
	if err == nil {
		t.Fatal("a 400 on one block was swallowed, want the scan to fail")
	}
	var statusErr *StatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusBadRequest {
		t.Errorf("error = %v, want a StatusError with status 400", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error %q does not name the status", err)
	}
	if n := atomic.LoadInt32(&rejected); n != 1 {
		t.Errorf("the 400 block was sent %d times, want 1: a client error is not retryable", n)
	}
}

// The retry rebuilds nothing by hand, but it must still carry the parameter: a block that
// reaches the server without it would split the session and earn a 400.
func TestMaxComponentsSurvivesARetry(t *testing.T) {
	mock := &scanMock{completeAt: 1, result: json.RawMessage(`{"files":[],"components":{}}`)}
	var mu sync.Mutex
	var queries []url.Values
	var posts int32
	inner := mock.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			queries = append(queries, r.URL.Query())
			mu.Unlock()
			if atomic.AddInt32(&posts, 1) == 1 {
				http.Error(w, "briefly unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	c := mustNew(t, Config{APIURL: srv.URL, Workers: 1, RetryBackoffBase: time.Millisecond})

	if _, err := c.Scan.WFP(context.Background(), []byte("0123456789abc"),
		WithChunkBytes(4), WithPollInterval(time.Millisecond), fiveComponents(t)); err != nil {
		t.Fatalf("a scan must survive one 503: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(queries) != 5 { // 4 blocks + the one that failed
		t.Fatalf("recorded %d uploads, want 5 (4 blocks and 1 retry)", len(queries))
	}
	for i, q := range queries {
		if got := q[maxComponentsParam]; len(got) != 1 || got[0] != "5" {
			t.Errorf("upload %d (the first is the failed attempt, the second its retry): %s = %v, want [5]", i, maxComponentsParam, got)
		}
	}
}
