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
	"testing"
)

// File GETs /v3/file-contents/{md5} and returns the raw body, with no line-range query when
// start and end are both 0.
func TestContentsFileWholeFile(t *testing.T) {
	const body = "line one\nline two\nline three\n"
	var gotMethod, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := mustNew(t, Config{APIURL: srv.URL})
	got, err := client.Contents.File(context.Background(), "abc123", 0, 0)
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v3/file-contents/abc123" {
		t.Errorf("got %s %s, want GET /v3/file-contents/abc123", gotMethod, gotPath)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want empty for a whole-file fetch", gotQuery)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

// A line range is passed through as start/end query params.
func TestContentsFileLineRange(t *testing.T) {
	var gotStart, gotEnd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotStart = r.URL.Query().Get("start")
		gotEnd = r.URL.Query().Get("end")
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	client := mustNew(t, Config{APIURL: srv.URL})
	if _, err := client.Contents.File(context.Background(), "abc123", 10, 42); err != nil {
		t.Fatalf("File: %v", err)
	}
	if gotStart != "10" || gotEnd != "42" {
		t.Errorf("range params = start:%q end:%q, want 10/42", gotStart, gotEnd)
	}
}

// A non-2xx status becomes an error (a missing file is a 404).
func TestContentsFileNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"FILE_NOT_FOUND"}}`, http.StatusNotFound)
	}))
	defer srv.Close()

	client := mustNew(t, Config{APIURL: srv.URL})
	if _, err := client.Contents.File(context.Background(), "missing", 0, 0); err == nil {
		t.Fatal("want an error for a 404")
	}
}
