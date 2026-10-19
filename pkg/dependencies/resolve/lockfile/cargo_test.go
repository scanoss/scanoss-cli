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
	"maps"
	"os"
	"reflect"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

func TestCargoLockGolden(t *testing.T) { runGolden(t, "cargo") }

// directs maps each root to its direct members, and its status and reason.
func directs(g resolve.Graph) map[string][]string {
	out := map[string][]string{}
	for _, r := range g.Roots {
		out[r.Manifest] = []string{string(r.Status) + "/" + string(r.Reason)}
		for _, m := range r.Members {
			if m.Direct {
				out[r.Manifest] = append(out[r.Manifest], string(m.ID))
			}
		}
	}
	return out
}

func TestParseFSCargoWorkspace(t *testing.T) {
	g, err := ParseFS(os.DirFS("testdata/fs"), "rust/Cargo.lock", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	checkGraph(t, Input{Path: "rust/Cargo.lock"}, DefaultLimits(), g)
	want := map[string][]string{
		"rust/Cargo.toml":            {"complete/"},
		"rust/crates/app/Cargo.toml": {"complete/", "pkg:cargo/lib@0.1.0", "pkg:cargo/serde@1.0.200", "pkg:cargo/skip@0.1.0"},
		"rust/crates/lib/Cargo.toml": {"complete/", "pkg:cargo/rand@0.8.5", "pkg:cargo/serde@1.0.200"},
	}
	if got := directs(g); !reflect.DeepEqual(got, want) {
		t.Errorf("roots = %v, want %v", got, want)
	}
}

func TestParseFSCargoMemberBounds(t *testing.T) {
	member := func(name string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("[package]\nname = \"" + name + "\"\n# padding padding padding\n")}
	}
	fsys := fstest.MapFS{
		"ws/Cargo.lock": {Data: []byte("version = 4\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n" +
			"[[package]]\nname = \"b\"\nversion = \"1.0.0\"\n")},
		"ws/Cargo.toml":   {Data: []byte("[workspace]\nmembers = [\"[\", \"*\"]\n")},
		"ws/a/Cargo.toml": member("a"),
		"ws/b/Cargo.toml": member("b"),
	}
	tests := []struct {
		name   string
		lim    Limits
		reason resolve.Reason
		want   []string
	}{
		{"every member", Limits{MaxBytes: 1 << 10, MaxNodes: 10, MaxEdges: 10}, "", []string{"ws/Cargo.toml", "ws/a/Cargo.toml", "ws/b/Cargo.toml"}},
		{"more members than MaxNodes", Limits{MaxBytes: 1 << 10, MaxNodes: 1, MaxEdges: 10}, resolve.ReasonTooLarge, []string{"ws/Cargo.toml"}},
		{"manifests over the byte budget", Limits{MaxBytes: 120, MaxNodes: 10, MaxEdges: 10}, resolve.ReasonTooLarge, []string{"ws/Cargo.toml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := ParseFS(fsys, "ws/Cargo.lock", tt.lim)
			if err != nil {
				t.Fatal(err)
			}
			checkGraph(t, Input{Path: "ws/Cargo.lock"}, tt.lim, g)
			var got []string
			for _, r := range g.Roots {
				got = append(got, r.Manifest)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("roots = %v, want %v", got, tt.want)
			}
			if r := g.Roots[0].Reason; r != tt.reason {
				t.Errorf("reason = %q, want %q", r, tt.reason)
			}
		})
	}
}

// FuzzCargoLock also fuzzes the root manifest and one member manifest, both
// through Parse and through ParseFS, which expands the member globs.
func FuzzCargoLock(f *testing.F) {
	for _, dir := range caseDirs(f, "cargo") {
		in := loadCase(f, dir)
		var member []byte
		if len(in.Members) > 0 {
			member = in.Members[slices.Sorted(maps.Keys(in.Members))[0]]
		}
		f.Add(in.Lockfile, in.Manifest, in.Manifest != nil, member)
	}
	f.Fuzz(func(t *testing.T, data, manifest []byte, hasManifest bool, member []byte) {
		in := Input{Path: "Cargo.lock", Lockfile: data, Members: map[string][]byte{"m/Cargo.toml": member}}
		fsys := fstest.MapFS{"Cargo.lock": {Data: data}, "m/Cargo.toml": {Data: member}}
		if hasManifest {
			in.Manifest = manifest
			fsys["Cargo.toml"] = &fstest.MapFile{Data: manifest}
		}
		parseChecked(t, in, fuzzLimits)
		g, err := ParseFS(fsys, "Cargo.lock", fuzzLimits)
		if err != nil {
			t.Fatal(err)
		}
		checkGraph(t, in, fuzzLimits, g)
	})
}
