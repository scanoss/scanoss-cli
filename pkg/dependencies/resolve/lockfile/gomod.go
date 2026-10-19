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

package lockfile

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// goModule is a module path and version. A replacement without a version
// is a local directory.
type goModule struct {
	path, version string
}

// parseGoMod reads go.mod, which since Go 1.17 requires every module the
// build needs, marking with "// indirect" those the main module does not
// import. It records no edges. A replace directive gives a module the
// identity of its replacement, or makes it a local node when the
// replacement is a directory. Go has no dev dependencies: a module that only
// tests need looks like any other.
func parseGoMod(b *builder, data, _ []byte, _ map[string][]byte) {
	type require struct {
		goModule
		indirect bool
	}
	var requires []require
	replaces := map[goModule]goModule{} // keyed with and without a version
	block := ""
	for n, line := range strings.Split(string(data), "\n") {
		text, comment, _ := strings.Cut(line, "//")
		f := strings.Fields(text)
		for i, tok := range f {
			if s, err := strconv.Unquote(tok); err == nil {
				f[i] = s
			}
		}
		verb := block
		switch {
		case len(f) == 0:
			continue
		case block != "":
			if len(f) == 1 && f[0] == ")" {
				block = ""
				continue
			}
		case len(f) == 2 && f[1] == "(":
			block = f[0]
			continue
		default:
			verb, f = f[0], f[1:]
		}
		ok := true
		switch verb {
		case "require":
			if ok = len(f) == 2; ok {
				c := strings.TrimSpace(comment)
				requires = append(requires, require{goModule{f[0], f[1]}, c == "indirect" || strings.HasPrefix(c, "indirect;")})
			}
		case "replace":
			var from, to goModule
			if from, to, ok = goReplace(f); ok {
				replaces[from] = to
			}
		}
		if !ok {
			b.flag(resolve.ReasonMalformed, fmt.Sprintf("line %d: %q", n+1, strings.TrimSpace(line)))
			return
		}
	}
	if block != "" {
		b.flag(resolve.ReasonMalformed, fmt.Sprintf("%s block is not closed", block))
		return
	}

	b.flag(resolve.ReasonEdgesUnknown, "go.mod records no edges")
	r := b.root("")
	for _, req := range requires {
		to, replaced := replaces[req.goModule]
		if !replaced {
			to, replaced = replaces[goModule{path: req.path}]
		}
		add, m := b.node, req.goModule
		switch {
		case replaced && to.version == "":
			add, m = b.local, goModule{path: req.path}
		case replaced:
			m = to
		}
		i := strings.LastIndex(m.path, "/")
		if id, ok := add(m.path[:max(i, 0)], m.path[i+1:], m.version); ok && !req.indirect {
			r.declare(id, false)
		}
	}
}

// goReplace parses the arguments of a replace directive:
// "path [version] => path [version]".
func goReplace(f []string) (from, to goModule, ok bool) {
	i := slices.Index(f, "=>")
	if i < 1 || i > 2 || len(f)-i-1 < 1 || len(f)-i-1 > 2 {
		return from, to, false
	}
	from.path, to.path = f[0], f[i+1]
	if i == 2 {
		from.version = f[1]
	}
	if len(f)-i-1 == 2 {
		to.version = f[i+2]
	}
	return from, to, true
}
