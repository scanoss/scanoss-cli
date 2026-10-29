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

package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/scanpipeline"
	"github.com/scanoss/scanoss.go/pkg/snippetmatch"
)

// A threshold outside (0, 1) is refused before anything is fingerprinted or uploaded.
func TestScanRejectsClassifyThresholdOutOfRange(t *testing.T) {
	for _, bad := range []string{"0", "1", "-0.1", "1.5", "NaN"} {
		t.Run("value="+bad, func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			err := runScanDirCmd(t, srv.URL, "--classify-snippets", "--classify-threshold="+bad)
			if err == nil || !strings.Contains(err.Error(), "--classify-threshold") {
				t.Fatalf("error = %v, want one naming --classify-threshold", err)
			}
			if n := len(rec.queries); n != 0 {
				t.Errorf("server saw %d uploads, want 0", n)
			}
		})
	}
}

// --classify-threshold and --classify-filter do nothing without --classify-snippets, so they are
// refused rather than ignored in silence.
func TestScanClassifyFlagsRequireClassifySnippets(t *testing.T) {
	for _, args := range [][]string{
		{"--classify-threshold", "0.9"},
		{"--classify-filter"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			err := runScanDirCmd(t, srv.URL, args...)
			if err == nil || !strings.Contains(err.Error(), args[0]+" requires --classify-snippets") {
				t.Fatalf("error = %v, want %q", err, args[0]+" requires --classify-snippets")
			}
			if n := len(rec.queries); n != 0 {
				t.Errorf("server saw %d uploads, want 0", n)
			}
		})
	}
}

// Classification is no longer raw-only: every format accepts it, with a valid threshold and the
// filter.
func TestScanClassifyAcceptsEveryFormat(t *testing.T) {
	for _, format := range []string{"raw", "cyclonedx", "spdx"} {
		t.Run(format, func(t *testing.T) {
			var rec scanRequests
			srv := rec.server(t)
			if err := runScanDirCmd(t, srv.URL, "-f", format, "--classify-snippets", "--classify-threshold", "0.9", "--classify-filter"); err != nil {
				t.Fatal(err)
			}
			if len(rec.queries) == 0 {
				t.Error("server saw no upload")
			}
		})
	}
}

func TestClassificationSummary(t *testing.T) {
	base := snippetmatch.Summary{ModelVersion: "lr-d51f2e100211", Threshold: 0.7}
	with := func(f func(*scanpipeline.ClassifySummary)) scanpipeline.ClassifySummary {
		c := scanpipeline.ClassifySummary{Summary: base}
		f(&c)
		return c
	}
	for _, tc := range []struct {
		name     string
		in       scanpipeline.ClassifySummary
		filtered bool
		want     string
	}{
		{
			name: "partly scored",
			in:   with(func(c *scanpipeline.ClassifySummary) { c.Matches, c.Scored, c.FalsePositives = 56, 52, 6 }),
			want: "Snippet classifier (model lr-d51f2e100211, threshold 0.7): scored 52 of 56 snippet matches, 6 proposed as false positives; 4 could not be scored",
		},
		{
			name:     "filtered, all scored",
			in:       with(func(c *scanpipeline.ClassifySummary) { c.Matches, c.Scored, c.FalsePositives, c.Removed = 10, 10, 3, 3 }),
			filtered: true,
			want:     "Snippet classifier (model lr-d51f2e100211, threshold 0.7): scored 10 of 10 snippet matches, 3 proposed as false positives, 3 removed",
		},
		{
			name: "file contents denied",
			in: with(func(c *scanpipeline.ClassifySummary) {
				c.Matches, c.DeniedStatus, c.Threshold = 5, 403, 0.9
			}),
			filtered: true,
			want:     "Snippet classifier (model lr-d51f2e100211, threshold 0.9): scored 0 of 5 snippet matches, 0 proposed as false positives, 0 removed; 5 could not be scored (the API refused file contents with HTTP 403: the API key needs file-contents access)",
		},
		{
			name: "no snippets",
			in:   with(func(*scanpipeline.ClassifySummary) {}),
			want: "Snippet classifier (model lr-d51f2e100211, threshold 0.7): no snippet matches to score",
		},
		{
			name: "could not start",
			in:   scanpipeline.ClassifySummary{Err: errors.New("bad model")},
			want: "Snippet classifier could not start, no snippet match was scored: bad model",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classificationSummary(tc.in, tc.filtered); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}
