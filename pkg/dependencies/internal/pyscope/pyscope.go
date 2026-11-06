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

// Package pyscope decides which pyproject.toml dependencies are only needed to
// develop the project. The manifest parser and the poetry.lock and uv.lock
// resolvers share it, so a dependency reads as dev with or without a lockfile.
//
// Every PEP 735 [dependency-groups] group, Poetry's dev-dependencies and every
// Poetry group but main are for development: none of them is installed with
// the package. An extra is installed by any user who asks for it, so it is
// dev only when its name says it is (DevExtra).
package pyscope

import (
	"regexp"
	"strings"
)

// devExtraNames are the extra names the Python ecosystem uses for tests,
// linting, type checking, documentation and other development tooling.
var devExtraNames = map[string]bool{
	"dev": true, "devel": true, "develop": true, "development": true,
	"test": true, "tests": true, "testing": true,
	"lint": true, "linting": true, "typing": true, "mypy": true,
	"doc": true, "docs": true, "coverage": true, "qa": true,
}

var separators = regexp.MustCompile(`[-_.]+`)

// DevExtra reports whether an extra is for development: its normalized name
// (PEP 685), or the part of it before the first dash, is a development name,
// so dev, Test, docs and test-integration are dev, and socks and devices are
// not.
func DevExtra(name string) bool {
	n := separators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	head, _, _ := strings.Cut(n, "-")
	return devExtraNames[n] || devExtraNames[head]
}

// DevPoetryGroup reports whether a Poetry dependency group is for development.
func DevPoetryGroup(name string) bool {
	return name != "main"
}
