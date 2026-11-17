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

package parsers

import (
	"testing"
)

// TestParseGoModSourceLocation verifies that ParseGoMod populates Line and DeclaredText
// correctly, including cases with blank lines and comments before the first require.
func TestParseGoModSourceLocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    []LocalPurl
	}{
		{
			name: "blank lines and comments before first require",
			// line 1: module github.com/example/mod
			// line 2: (blank)
			// line 3: go 1.22
			// line 4: (blank)
			// line 5: // This is a comment
			// line 6: (blank)
			// line 7: require github.com/foo/bar v1.2.3
			content: `module github.com/example/mod

go 1.22

// This is a comment

require github.com/foo/bar v1.2.3
`,
			want: []LocalPurl{
				{
					Purl:         "pkg:golang/github.com/foo/bar@v1.2.3",
					Requirement:  "v1.2.3",
					Line:         7,
					DeclaredText: "require github.com/foo/bar v1.2.3",
				},
				{
					Purl:         "pkg:golang/stdlib@go1.22",
					Requirement:  "go1.22",
					Line:         3,
					DeclaredText: "go 1.22",
				},
			},
		},
		{
			name: "require block with multiple entries",
			content: `module github.com/example/mod

go 1.22

require (
	github.com/spf13/cobra v1.10.2
	github.com/google/uuid v1.6.0
)
`,
			want: []LocalPurl{
				{
					Purl:         "pkg:golang/github.com/spf13/cobra@v1.10.2",
					Requirement:  "v1.10.2",
					Line:         6,
					DeclaredText: "github.com/spf13/cobra v1.10.2",
				},
				{
					Purl:         "pkg:golang/github.com/google/uuid@v1.6.0",
					Requirement:  "v1.6.0",
					Line:         7,
					DeclaredText: "github.com/google/uuid v1.6.0",
				},
				{
					Purl:         "pkg:golang/stdlib@go1.22",
					Requirement:  "go1.22",
					Line:         3,
					DeclaredText: "go 1.22",
				},
			},
		},
		{
			name: "single require line",
			content: `module github.com/example/mod
go 1.22
require github.com/spf13/pflag v1.0.10
`,
			want: []LocalPurl{
				{
					Purl:         "pkg:golang/github.com/spf13/pflag@v1.0.10",
					Requirement:  "v1.0.10",
					Line:         3,
					DeclaredText: "require github.com/spf13/pflag v1.0.10",
				},
				{
					Purl:         "pkg:golang/stdlib@go1.22",
					Requirement:  "go1.22",
					Line:         2,
					DeclaredText: "go 1.22",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseGoMod([]byte(tc.content), "go.mod")
			if err != nil {
				t.Fatalf("ParseGoMod error: %v", err)
			}
			if len(result.Purls) != len(tc.want) {
				t.Fatalf("got %d purls, want %d; purls: %+v", len(result.Purls), len(tc.want), result.Purls)
			}
			for i, got := range result.Purls {
				w := tc.want[i]
				if got.Purl != w.Purl {
					t.Errorf("[%d] Purl: got %q, want %q", i, got.Purl, w.Purl)
				}
				if got.Requirement != w.Requirement {
					t.Errorf("[%d] Requirement: got %q, want %q", i, got.Requirement, w.Requirement)
				}
				if got.Line != w.Line {
					t.Errorf("[%d] Line: got %d, want %d", i, got.Line, w.Line)
				}
				if got.DeclaredText != w.DeclaredText {
					t.Errorf("[%d] DeclaredText: got %q, want %q", i, got.DeclaredText, w.DeclaredText)
				}
			}
		})
	}
}

// TestParseGoSumSourceLocation verifies that ParseGoSum populates Line and DeclaredText.
func TestParseGoSumSourceLocation(t *testing.T) {
	t.Parallel()

	content := `github.com/foo/bar v1.2.3 h1:abcdef==
github.com/foo/bar v1.2.3/go.mod h1:xyz==
github.com/baz/qux v0.1.0 h1:hello==
`
	result, err := ParseGoSum([]byte(content), "go.sum")
	if err != nil {
		t.Fatalf("ParseGoSum error: %v", err)
	}
	// go.sum deduplicates: /go.mod variant is dropped, so we get 2 entries.
	if len(result.Purls) != 2 {
		t.Fatalf("got %d purls, want 2; purls: %+v", len(result.Purls), result.Purls)
	}
	if result.Purls[0].Line != 1 {
		t.Errorf("first entry Line: got %d, want 1", result.Purls[0].Line)
	}
	if result.Purls[0].DeclaredText != "github.com/foo/bar v1.2.3 h1:abcdef==" {
		t.Errorf("first entry DeclaredText: got %q", result.Purls[0].DeclaredText)
	}
	if result.Purls[1].Line != 3 {
		t.Errorf("second entry Line: got %d, want 3", result.Purls[1].Line)
	}
}

// TestParseGoNoDepMatchZeroLine verifies that when no deps match, result is empty (no zero-Line entries).
func TestParseGoNoDepMatchZeroLine(t *testing.T) {
	t.Parallel()

	content := `module github.com/example/mod

go 1.22
`
	result, err := ParseGoMod([]byte(content), "go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod error: %v", err)
	}
	// The standard library is the only dependency of a module that requires nothing.
	if len(result.Purls) != 1 || result.Purls[0].Purl != "pkg:golang/stdlib@go1.22" {
		t.Errorf("expected only the standard library for a module-only go.mod, got %+v", result.Purls)
	}
}

// The standard library is declared at the toolchain the module builds with:
// the toolchain directive when there is one, else the go directive.
func TestParseGoModStdlib(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, content, purl string
		line                int
	}{
		{"go directive", "module m\n\ngo 1.26.11\n", "pkg:golang/stdlib@go1.26.11", 3},
		{"toolchain wins over go", "module m\n\ngo 1.26\n\ntoolchain go1.26.11\n", "pkg:golang/stdlib@go1.26.11", 5},
		{"go directive without patch kept as is", "module m\ngo 1.26\n", "pkg:golang/stdlib@go1.26", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseGoMod([]byte(tc.content), "go.mod")
			if err != nil {
				t.Fatalf("ParseGoMod error: %v", err)
			}
			if len(result.Purls) != 1 || result.Purls[0].Purl != tc.purl || result.Purls[0].Line != tc.line {
				t.Errorf("got %+v, want %s at line %d", result.Purls, tc.purl, tc.line)
			}
		})
	}

	result, err := ParseGoMod([]byte("module m\n"), "go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod error: %v", err)
	}
	if len(result.Purls) != 0 {
		t.Errorf("a go.mod without a go directive names no toolchain, got %+v", result.Purls)
	}
}

func TestGoStdVersion(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ goDir, toolchain, want string }{
		{"1.26.11", "", "go1.26.11"},
		{"1.26", "go1.26.11", "go1.26.11"},
		{"1.26", "default", "go1.26"},
		{"", "", ""},
	} {
		if got := GoStdVersion(tc.goDir, tc.toolchain); got != tc.want {
			t.Errorf("GoStdVersion(%q, %q) = %q, want %q", tc.goDir, tc.toolchain, got, tc.want)
		}
	}
}
