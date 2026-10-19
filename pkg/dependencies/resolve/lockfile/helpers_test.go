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
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/graphtest"
)

var update = flag.Bool("update", false, "rewrite the graph.golden.json files")

// fuzzLimits are small so that fuzzing reaches the node and edge caps.
var fuzzLimits = Limits{MaxBytes: 1 << 20, MaxNodes: 6, MaxEdges: 8}

// parseChecked parses in, checks every graph invariant, and checks that a
// second parse gives the same graph.
func parseChecked(t testing.TB, in Input, lim Limits) resolve.Graph {
	t.Helper()
	g, err := Parse(in, lim)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	checkGraph(t, in, lim, g)
	again, _ := Parse(in, lim)
	if !reflect.DeepEqual(g, again) {
		t.Fatalf("Parse is not deterministic:\n%+v\n%+v", g, again)
	}
	return g
}

func checkGraph(t testing.TB, in Input, lim Limits, g resolve.Graph) {
	t.Helper()
	graphtest.Check(t, g, in.Path, build.Limits{MaxNodes: lim.MaxNodes, MaxEdges: lim.MaxEdges})
}

// loadCase reads the lockfile in dir, its sibling manifest when the format
// reads one and the case has it, and the member manifests the format collects.
func loadCase(t testing.TB, dir string) Input {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !Supported(e.Name()) {
			continue
		}
		in := Input{Path: e.Name()}
		if in.Lockfile, err = os.ReadFile(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
		if m, ok := ManifestFor(e.Name()); ok {
			in.Manifest, err = os.ReadFile(filepath.Join(dir, m))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		if f, _ := lookup(e.Name()); f.members != nil {
			lim := DefaultLimits()
			in.Members = f.members(os.DirFS(dir), ".", in.Manifest, lim.MaxBytes, lim.MaxNodes)
		}
		return in
	}
	t.Fatalf("no lockfile in %s", dir)
	return Input{}
}

func caseDirs(t testing.TB, format string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join("testdata", format, "*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no cases for %s: %v", format, err)
	}
	return dirs
}

// runGolden parses every case under testdata/<format> and compares the graph
// with the case's graph.golden.json.
func runGolden(t *testing.T, format string) {
	for _, dir := range caseDirs(t, format) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			g := parseChecked(t, loadCase(t, dir), DefaultLimits())
			got, err := json.MarshalIndent(g, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			golden := filepath.Join(dir, "graph.golden.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("graph differs from %s (rerun with -update to accept):\n%s", golden, got)
			}
		})
	}
}

// fuzzFormat seeds f with every case of format and checks the invariants of
// whatever Parse makes of the mutated input.
func fuzzFormat(f *testing.F, format string) {
	var lockfile string
	for _, dir := range caseDirs(f, format) {
		in := loadCase(f, dir)
		lockfile = in.Path
		f.Add(in.Lockfile, in.Manifest, in.Manifest != nil)
	}
	f.Fuzz(func(t *testing.T, data, manifest []byte, hasManifest bool) {
		in := Input{Path: lockfile, Lockfile: data}
		if hasManifest {
			in.Manifest = manifest
		}
		parseChecked(t, in, fuzzLimits)
	})
}
