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

package toolchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/graphtest"
)

var update = flag.Bool("update", false, "rewrite the graph.golden.json files")

func recorded(t *testing.T, dir string) runFunc {
	return func(name string, args ...string) output {
		read := func(file string) []byte {
			data, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		switch strings.Join(append([]string{name}, args...), " ") {
		case "go list -e -m -json all":
			return output{stdout: read("list.json")}
		case "go mod graph":
			if _, err := os.Stat(filepath.Join(dir, "stderr.txt")); err == nil {
				return failed("go mod graph", errors.New("exit status 1"), read("stderr.txt"))
			}
			return output{stdout: read("graph.txt")}
		}
		t.Fatalf("unexpected run of %s %q", name, args)
		return output{}
	}
}

func resolveRecorded(t *testing.T, dir string) resolve.Graph {
	lim := build.Limits{MaxNodes: DefaultLimits().MaxNodes, MaxEdges: DefaultLimits().MaxEdges}
	b := build.New("go.mod", resolve.EcosystemGolang, "go.mod", lim)
	resolveGo(b, b.Root(""), recorded(t, dir))
	return b.Graph()
}

func TestGoGolden(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "go", "*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			g := resolveRecorded(t, dir)
			lim := DefaultLimits()
			graphtest.Check(t, g, "go.mod", build.Limits{MaxNodes: lim.MaxNodes, MaxEdges: lim.MaxEdges})
			if again := resolveRecorded(t, dir); !reflect.DeepEqual(g, again) {
				t.Fatalf("not deterministic:\n%+v\n%+v", g, again)
			}
			compareGolden(t, g, filepath.Join(dir, "graph.golden.json"))
		})
	}
}

func compareGolden(t *testing.T, g resolve.Graph, golden string) {
	t.Helper()
	got, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
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
}

func TestGoListFailureIsUnknown(t *testing.T) {
	for _, tt := range []struct {
		name string
		out  output
		want resolve.Reason
	}{
		{"missing", output{reason: resolve.ReasonToolMissing, detail: "go: not found on PATH"}, resolve.ReasonToolMissing},
		{"failed", failed("go list", errors.New("exit status 1"), []byte("go: go.mod: no such file")), resolve.ReasonToolFailed},
		{"offline", failed("go list", errors.New("exit status 1"), []byte("dial tcp: connection refused")), resolve.ReasonToolFailed},
		{"malformed", output{stdout: []byte(`{"Path": "example.com/app", "Main": true}{`)}, resolve.ReasonMalformed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := build.New("go.mod", resolve.EcosystemGolang, "go.mod", build.Limits{MaxNodes: 10, MaxEdges: 10})
			resolveGo(b, b.Root(""), func(string, ...string) output { return tt.out })
			r := b.Graph().Roots[0]
			if r.Status != resolve.StatusUnknown || r.Reason != tt.want {
				t.Errorf("root is %s (%s), want unknown (%s): %s", r.Status, r.Reason, tt.want, r.Detail)
			}
		})
	}
}

func TestSupported(t *testing.T) {
	if !Supported("sub/go.mod") || Supported("go.sum") || Supported("pom.xml") {
		t.Error("Supported does not match the table")
	}
	if _, err := Resolve(t.Context(), t.TempDir(), "go.sum", Options{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Resolve(go.sum) = %v, want ErrUnsupported", err)
	}
}
