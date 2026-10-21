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

package version

import (
	"runtime/debug"
	"testing"
)

func TestModuleVersion(t *testing.T) {
	tests := []struct {
		name string
		bi   debug.BuildInfo
		want string
	}{
		{"cli build", debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v0.13.0"}}, "v0.13.0"},
		{"dirty cli build", debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v0.13.0+dirty"}}, "v0.13.0"},
		{"local build", debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}}, ""},
		{"imported by a program", debug.BuildInfo{
			Main: debug.Module{Path: "example.com/earnie", Version: "v1.8.2"},
			Deps: []*debug.Module{{Path: "example.com/other", Version: "v9.0.0"}, {Path: modulePath, Version: "v0.13.0"}},
		}, "v0.13.0"},
		{"replaced dependency", debug.BuildInfo{
			Main: debug.Module{Path: "example.com/earnie"},
			Deps: []*debug.Module{{Path: modulePath, Version: "v0.12.0", Replace: &debug.Module{Path: "../scanoss.go"}}},
		}, ""},
		{"not in the build", debug.BuildInfo{Main: debug.Module{Path: "example.com/earnie", Version: "v1.8.2"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := moduleVersion(&tt.bi); got != tt.want {
				t.Errorf("moduleVersion = %q, want %q", got, tt.want)
			}
		})
	}
}
