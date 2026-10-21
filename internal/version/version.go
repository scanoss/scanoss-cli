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

// Package version reports this module's version, resolved in order from: ldflags
// (release builds) → the module version in the build info (go install @tag, or the
// version a program importing the SDK requires) → a "dev" fallback.
package version

import (
	"runtime/debug"
	"strings"
)

// version is set at release build time via -ldflags, e.g.:
//
//	-X github.com/scanoss/scanoss.go/internal/version.version=v0.9.0
var version = ""

const modulePath = "github.com/scanoss/scanoss.go"

// Version returns the module version, e.g. "v0.9.0" or "dev".
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := moduleVersion(bi); v != "" {
			return v
		}
	}
	return "dev"
}

func moduleVersion(bi *debug.BuildInfo) string {
	mod := &bi.Main
	if mod.Path != modulePath {
		mod = nil
		for _, dep := range bi.Deps {
			if dep.Path == modulePath {
				mod = dep
				break
			}
		}
	}
	if mod == nil {
		return ""
	}
	if mod.Replace != nil {
		mod = mod.Replace
	}
	if v := strings.TrimSuffix(mod.Version, "+dirty"); v != "(devel)" {
		return v
	}
	return ""
}
