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

package aiusage

import (
	"path/filepath"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/fragbuild"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// reachability decides, from the call graph, whether a finding's function runs from an entry
// point of the scanned code.
type reachability struct {
	root   string
	graph  *callgraph.CallGraph
	tracer *callgraph.Tracer
	memo   map[string]verdict
}

type verdict struct {
	status string
	entry  *sbom.AIEntryPoint
}

func newReachability(root, ecosystem string, graph *callgraph.CallGraph) *reachability {
	tracer := callgraph.NewTracer(graph, fragbuild.ExportPackageSeparator(ecosystem))
	tracer.SetProjectRoot(root)
	return &reachability{root: root, graph: graph, tracer: tracer, memo: map[string]verdict{}}
}

// of returns the verdict for the function callerKey. The scanned code is the application, so a
// chain to a program or framework entry point makes a finding reachable; a chain that needs a
// name-only call, or a walk the depth limit cut, leaves it unknown; no chain makes it unreachable.
func (r *reachability) of(callerKey string) verdict {
	if v, ok := r.memo[callerKey]; ok {
		return v
	}
	v := r.trace(callerKey)
	r.memo[callerKey] = v
	return v
}

func (r *reachability) trace(callerKey string) verdict {
	fn := r.graph.Functions[callerKey]
	if fn == nil {
		return verdict{status: sbom.AIUnknown}
	}
	// Top-level code runs when its file is run or imported.
	if fn.ID.Name == moduleFunctionName {
		return verdict{status: sbom.AIReachable, entry: &sbom.AIEntryPoint{File: r.relative(fn.FilePath), Line: 1, Kind: "module"}}
	}
	if mark, ok := r.tracer.EntryPoint(fn, nil); ok {
		return verdict{status: sbom.AIReachable, entry: &sbom.AIEntryPoint{File: r.relative(fn.FilePath), Line: fn.StartLine, Kind: string(mark.Kind)}}
	}
	trace := r.tracer.TraceBackCondensed(fn.ID, nil, 0, 1)
	switch {
	case trace.UnresolvedDispatch:
		return verdict{status: sbom.AIUnknown}
	case len(trace.Chains) == 0 && trace.DepthLimited:
		return verdict{status: sbom.AIUnknown}
	case len(trace.Chains) == 0:
		return verdict{status: sbom.AIUnreachable}
	}
	chain := trace.Chains[0]
	if len(chain.Steps) == 0 {
		return verdict{status: sbom.AIUnknown}
	}
	switch chain.RootKind {
	case callgraph.RootKindMain, callgraph.RootKindFrameworkEntry:
	default:
		// The chain starts at code nothing calls and no catalog recognizes: dead code, or an
		// entry point the engine does not know.
		return verdict{status: sbom.AIUnknown}
	}
	head := chain.Steps[0]
	line := head.Line
	if decl := r.graph.Functions[head.Function.String()]; decl != nil && decl.StartLine > 0 {
		line = decl.StartLine
	}
	return verdict{status: sbom.AIReachable, entry: &sbom.AIEntryPoint{File: r.relative(head.FilePath), Line: line, Kind: string(chain.RootKind)}}
}

// moduleFunctionName is the function the call graph holds a file's top-level code in.
const moduleFunctionName = "<module>"

func (r *reachability) relative(path string) string {
	if rel, err := filepath.Rel(r.root, path); err == nil && filepath.IsAbs(path) {
		path = rel
	}
	return filepath.ToSlash(path)
}
