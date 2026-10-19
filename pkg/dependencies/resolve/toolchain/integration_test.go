//go:build integration

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
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/graphtest"
)

var goFixture = filepath.Join("testdata", "integration", "go")

func resolveFixture(t *testing.T, opts Options) resolve.Graph {
	t.Helper()
	g, err := Resolve(t.Context(), goFixture, "app/go.mod", opts)
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	graphtest.Check(t, g, "app/go.mod", build.Limits{MaxNodes: lim.MaxNodes, MaxEdges: lim.MaxEdges})
	return g
}

func TestGoIntegration(t *testing.T) {
	g := resolveFixture(t, Options{})
	compareGolden(t, g, filepath.Join(goFixture, "graph.golden.json"))
}

func TestGoIntegrationOffline(t *testing.T) {
	g := resolveFixture(t, Options{Env: []string{
		"GOPROXY=http://127.0.0.1:9",
		"GOFLAGS=-mod=readonly -modcacherw",
		"GOMODCACHE=" + t.TempDir(),
	}})
	r := g.Roots[0]
	if r.Status != resolve.StatusPartial || r.Reason != resolve.ReasonRegistryUnreachable {
		t.Fatalf("root is %s (%s), want partial (registry_unreachable): %s", r.Status, r.Reason, r.Detail)
	}
	var direct, indirect []resolve.NodeID
	for _, m := range r.Members {
		if m.Direct {
			direct = append(direct, m.ID)
		} else {
			indirect = append(indirect, m.ID)
		}
	}
	wantDirect := []resolve.NodeID{
		"pkg:golang/example.com/local",
		"pkg:golang/github.com/google/uuid@v1.6.0",
		"pkg:golang/github.com/stretchr/testify@v1.12.1",
	}
	wantIndirect := []resolve.NodeID{"pkg:golang/go.yaml.in/yaml/v3@v3.0.5"}
	if !slices.Equal(direct, wantDirect) || !slices.Equal(indirect, wantIndirect) {
		t.Errorf("members: direct %v, indirect %v; want %v and %v", direct, indirect, wantDirect, wantIndirect)
	}
}
