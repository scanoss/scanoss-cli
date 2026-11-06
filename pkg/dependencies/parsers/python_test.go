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

// TestParseRequirementsTxtSourceLocation verifies Line and DeclaredText for requirements.txt.
func TestParseRequirementsTxtSourceLocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    []LocalPurl
	}{
		{
			name: "blank lines above first dep",
			// line 1: # comment
			// line 2: (blank)
			// line 3: requests==2.28.0
			// line 4: flask==2.3.0
			content: `# comment

requests==2.28.0
flask==2.3.0
`,
			want: []LocalPurl{
				{
					Purl:         "pkg:pypi/requests@2.28.0",
					Requirement:  "2.28.0",
					Line:         3,
					DeclaredText: "requests==2.28.0",
				},
				{
					Purl:         "pkg:pypi/flask@2.3.0",
					Requirement:  "2.3.0",
					Line:         4,
					DeclaredText: "flask==2.3.0",
				},
			},
		},
		{
			name: "unmappable edge case — no match gives no entry",
			// Only a comment and blank lines; no deps should be emitted.
			content: `# just a comment
`,
			want: []LocalPurl{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParseRequirementsTxt([]byte(tc.content), "requirements.txt")
			if err != nil {
				t.Fatalf("ParseRequirementsTxt error: %v", err)
			}
			if len(result.Purls) != len(tc.want) {
				t.Fatalf("got %d purls, want %d; purls: %+v", len(result.Purls), len(tc.want), result.Purls)
			}
			for i, got := range result.Purls {
				w := tc.want[i]
				if got.Purl != w.Purl {
					t.Errorf("[%d] Purl: got %q, want %q", i, got.Purl, w.Purl)
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

func TestParsePyprojectToml(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    []LocalPurl
	}{
		{
			name: "project dependencies and a dev extra",
			content: `[project]
name = "earnie-staging-probe"
version = "0.1.0"
dependencies = ["requests>=2.31"]
[project.optional-dependencies]
dev = [
    "pytest>=7.4",
    "pylint>=2.17",
]
`,
			want: []LocalPurl{
				{Purl: "pkg:pypi/requests", Requirement: ">=2.31", Scope: "project.dependencies", Line: 4, DeclaredText: `dependencies = ["requests>=2.31"]`},
				{Purl: "pkg:pypi/pytest", Requirement: ">=7.4", Scope: "project.optional-dependencies.dev", Dev: true, Line: 7, DeclaredText: `"pytest>=7.4",`},
				{Purl: "pkg:pypi/pylint", Requirement: ">=2.17", Scope: "project.optional-dependencies.dev", Dev: true, Line: 8, DeclaredText: `"pylint>=2.17",`},
			},
		},
		{
			name: "other project strings and build requirements are not dependencies",
			content: `[build-system]
requires = ["setuptools>=61", "wheel"]

[project]
name = "app"
description = "A tool"
requires-python = ">=3.9"
dependencies = [
    "django==4.2.0", "flask",
]
readme = "README.md"
`,
			want: []LocalPurl{
				{Purl: "pkg:pypi/django@4.2.0", Requirement: "4.2.0", Scope: "project.dependencies", Line: 9, DeclaredText: `"django==4.2.0", "flask",`},
				{Purl: "pkg:pypi/flask", Scope: "project.dependencies", Line: 9, DeclaredText: `"django==4.2.0", "flask",`},
			},
		},
		{
			name: "an extra is dev only when its name says so",
			content: `[project]
name = "app"
optional-dependencies = { socks = ["PySocks"], Test_Integration = ["tox"], docs = ["sphinx"] }
`,
			want: []LocalPurl{
				{Purl: "pkg:pypi/PySocks", Scope: "project.optional-dependencies.socks", Line: 3},
				{Purl: "pkg:pypi/tox", Scope: "project.optional-dependencies.Test_Integration", Dev: true, Line: 3},
				{Purl: "pkg:pypi/sphinx", Scope: "project.optional-dependencies.docs", Dev: true, Line: 3},
			},
		},
		{
			name: "every PEP 735 group is dev, and an include-group adds nothing",
			content: `[dependency-groups]
test = ["pytest>=8", {include-group = "typing"}]
typing = ["mypy"]
release = ["twine"]
`,
			want: []LocalPurl{
				{Purl: "pkg:pypi/pytest", Requirement: ">=8", Scope: "dependency-groups.test", Dev: true, Line: 2},
				{Purl: "pkg:pypi/mypy", Scope: "dependency-groups.typing", Dev: true, Line: 3},
				{Purl: "pkg:pypi/twine", Scope: "dependency-groups.release", Dev: true, Line: 4},
			},
		},
		{
			name: "poetry dependencies, dev-dependencies and groups",
			content: `[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.31"
flask = { version = "2.3.0", optional = true }
click = "*"

[tool.poetry.dev-dependencies]
black = "23.1"

[tool.poetry.group.main.dependencies]
attrs = ">=23"

[tool.poetry.group.test.dependencies]
pytest = { path = "../pytest" }
`,
			want: []LocalPurl{
				{Purl: "pkg:pypi/requests", Requirement: "^2.31", Scope: "tool.poetry.dependencies", Line: 6},
				{Purl: "pkg:pypi/flask@2.3.0", Requirement: "2.3.0", Scope: "tool.poetry.dependencies", Line: 7},
				{Purl: "pkg:pypi/click", Scope: "tool.poetry.dependencies", Line: 8},
				{Purl: "pkg:pypi/black@23.1", Requirement: "23.1", Scope: "tool.poetry.dev-dependencies", Dev: true, Line: 11},
				{Purl: "pkg:pypi/attrs", Requirement: ">=23", Scope: "tool.poetry.group.main.dependencies", Line: 14},
				{Purl: "pkg:pypi/pytest", Scope: "tool.poetry.group.test.dependencies", Dev: true, Line: 17},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := ParsePyprojectToml([]byte(tc.content), "pyproject.toml")
			if err != nil {
				t.Fatalf("ParsePyprojectToml error: %v", err)
			}
			if len(result.Purls) != len(tc.want) {
				t.Fatalf("got %d purls, want %d; purls: %+v", len(result.Purls), len(tc.want), result.Purls)
			}
			for i, got := range result.Purls {
				w := tc.want[i]
				if w.DeclaredText == "" {
					w.DeclaredText = got.DeclaredText
				}
				if got != w {
					t.Errorf("[%d] got %+v, want %+v", i, got, w)
				}
			}
		})
	}
}

func TestParsePyprojectTomlMalformed(t *testing.T) {
	t.Parallel()
	if _, err := ParsePyprojectToml([]byte("[project\ndependencies = [\"requests\"]\n"), "pyproject.toml"); err == nil {
		t.Fatal("want an error for a malformed pyproject.toml")
	}
}
