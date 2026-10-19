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

// Package toolchain builds a resolve.Graph by running an ecosystem's own
// tools on a manifest, such as the go command on go.mod or mvn on pom.xml,
// for projects whose lockfile does not record the whole graph.
//
// It runs build tooling on files the scanned repository controls, and some
// tools run the repository's own code, such as build scripts and plugins, so
// callers run it inside an isolated sandbox. It never needs credentials: the
// caller points the tools at a registry or mirror through Options.Env. Each
// tool run has a timeout, and Limits bounds what is read from it.
//
// A tool that is missing, fails, times out or prints too much makes its root
// unknown; one that cannot reach the registry makes it partial, with what the
// tool resolved without it. Resolve never fails because of a tool. A root's
// Manifest and Lockfile are both the manifest's path, since the tool, not a
// lockfile, resolved it. A Maven reactor has one root per module, each with
// the module's pom.xml as both.
package toolchain

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"time"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// Limits bounds the output read from a tool and the graph built from it. A
// Maven reactor's modules are resolved apart, so MaxNodes and MaxEdges bound
// each module's graph, not the merged one.
type Limits struct {
	MaxOutput int64 // stdout or stderr of one tool run, or a file it writes; more makes the root unknown (too_large)
	MaxNodes  int   // nodes kept; reaching it makes the roots partial (node_limit)
	MaxEdges  int   // edges kept; reaching it makes the roots partial (edge_limit)
}

// DefaultLimits returns limits that fit any real project: 64 MiB of output,
// 50,000 nodes and 500,000 edges.
func DefaultLimits() Limits {
	return Limits{MaxOutput: 64 << 20, MaxNodes: 50_000, MaxEdges: 500_000}
}

// DefaultTimeout bounds each tool run when Options.Timeout is zero.
const DefaultTimeout = 10 * time.Minute

// Options configures Resolve.
type Options struct {
	Timeout time.Duration // per tool run; zero means DefaultTimeout
	// Env is added to the process environment after each tool's defaults, so
	// its values win. It is where the caller sets the registry or mirror,
	// such as GOPROXY, and may override a default, such as GOFLAGS.
	Env    []string
	Limits Limits // zero means DefaultLimits
}

// ErrUnsupported is returned for a manifest whose base name has no tool.
var ErrUnsupported = errors.New("unsupported manifest")

type tool struct {
	env     []string
	resolve func(p project) resolve.Graph
}

// project is the manifest, its directory on disk and the tools run in it.
type project struct {
	manifest  string // slash path, as given to Resolve
	dir       string
	lim       build.Limits
	maxOutput int64
	run       runFunc
}

var tools = map[string]tool{
	"go.mod": {goEnv, func(p project) resolve.Graph {
		b := build.New(p.manifest, resolve.EcosystemGolang, "go.mod", p.lim)
		resolveGo(b, b.Root(""), p.run)
		return b.Graph()
	}},
	"pom.xml": {nil, resolveMaven},
}

// Supported reports whether manifest's base name is one this package
// resolves.
func Supported(manifest string) bool {
	_, ok := tools[path.Base(manifest)]
	return ok
}

// Resolve runs the ecosystem's tools on the manifest at manifest, a slash
// path relative to dir. The only error is ErrUnsupported; tool problems are
// reported on the roots. When ctx is cancelled it returns the graph built so
// far, with the roots it stopped short of reported as timed out.
func Resolve(ctx context.Context, dir, manifest string, opts Options) (resolve.Graph, error) {
	t, ok := tools[path.Base(manifest)]
	if !ok {
		return resolve.Graph{}, ErrUnsupported
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits()
	}
	r := runner{
		ctx:       ctx,
		dir:       filepath.Join(dir, filepath.FromSlash(path.Dir(manifest))),
		env:       slices.Concat(os.Environ(), t.env, opts.Env),
		timeout:   opts.Timeout,
		maxOutput: opts.Limits.MaxOutput,
	}
	return t.resolve(project{
		manifest:  manifest,
		dir:       r.dir,
		lim:       build.Limits{MaxNodes: opts.Limits.MaxNodes, MaxEdges: opts.Limits.MaxEdges},
		maxOutput: r.maxOutput,
		run:       r.run,
	}), nil
}
