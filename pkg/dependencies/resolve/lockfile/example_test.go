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

package lockfile_test

import (
	"fmt"
	"testing/fstest"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/lockfile"
)

func ExampleParseFS() {
	fsys := fstest.MapFS{"web/package-lock.json": {Data: []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"express": "^4.19.0"}},
    "node_modules/express": {"version": "4.19.2", "dependencies": {"debug": "2.6.9"}},
    "node_modules/debug": {"version": "2.6.9"}
  }
}`)}}

	g, err := lockfile.ParseFS(fsys, "web/package-lock.json", lockfile.DefaultLimits())
	if err != nil {
		panic(err)
	}
	for _, r := range g.Roots {
		fmt.Println(r.Manifest, r.Status)
		for _, m := range r.Members {
			fmt.Println(" ", m.ID, "direct:", m.Direct)
		}
		for _, e := range r.Edges {
			fmt.Println(" ", e.From, "->", e.To)
		}
	}
	// Output:
	// web/package.json complete
	//   pkg:npm/debug@2.6.9 direct: false
	//   pkg:npm/express@4.19.2 direct: true
	//   pkg:npm/express@4.19.2 -> pkg:npm/debug@2.6.9
}
