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

// Package lockfile builds a resolve.Graph from a lockfile, without running any
// package manager or other process.
//
// Lockfiles are untrusted input. Parsing is bounded by Limits: a lockfile
// larger than MaxBytes is not parsed, and the graph stops growing at MaxNodes
// nodes or MaxEdges edges. A malformed or unsupported lockfile yields an
// unknown root with a reason; a lockfile that parses but cannot be fully
// resolved yields a partial root with a reason. Parse never fails on content.
//
// Each format names its roots after the manifest beside the lockfile, joined
// with the workspace directory for formats that record workspaces
// (package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml).
// Cargo.lock does not record where its workspace members live, so their
// roots come from the member manifests in Input.Members. A workspace, path or link package that
// something depends on is a local node, with its own dependencies as edges.
// Lockfile entries that no root reaches become non-direct members of the
// root beside the lockfile.
package lockfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// Limits bounds the work Parse does on one lockfile.
type Limits struct {
	MaxBytes int64 // largest lockfile, and largest total of its manifests, read and parsed
	MaxNodes int   // nodes kept; reaching it makes the roots partial (node_limit)
	MaxEdges int   // edges kept; reaching it makes the roots partial (edge_limit)
}

// DefaultLimits returns limits that fit any real lockfile: 32 MiB, 50,000
// nodes and 500,000 edges.
func DefaultLimits() Limits {
	return Limits{MaxBytes: 32 << 20, MaxNodes: 50_000, MaxEdges: 500_000}
}

// Input is one lockfile and, when its format reads one, its sibling manifest.
type Input struct {
	Path     string // slash path of the lockfile; names the roots, never opened
	Lockfile []byte
	Manifest []byte // the sibling manifest named by ManifestFor; nil when absent
	// Members holds workspace member manifests keyed by slash path relative
	// to the lockfile's directory, such as "crates/app/Cargo.toml". Only
	// Cargo.lock reads it.
	Members map[string][]byte
}

// ErrUnsupported is returned for a lockfile whose base name is not a
// supported format.
var ErrUnsupported = errors.New("unsupported lockfile")

type format struct {
	ecosystem resolve.Ecosystem
	manifest  string // the manifest each root stands for
	reads     bool   // parse reads the sibling manifest
	parse     func(b *builder, lockfile, manifest []byte, members map[string][]byte)
	// members, when set, finds and reads the member manifests the sibling
	// manifest names, within budget bytes in total.
	members func(fsys fs.FS, dir string, manifest []byte, budget int64, maxFiles int) map[string][]byte
}

var formats = map[string]format{
	"package-lock.json":   {resolve.EcosystemNPM, "package.json", false, parsePackageLock, nil},
	"npm-shrinkwrap.json": {resolve.EcosystemNPM, "package.json", false, parsePackageLock, nil},
	"yarn.lock":           {resolve.EcosystemNPM, "package.json", true, parseYarnLock, nil},
	"pnpm-lock.yaml":      {resolve.EcosystemNPM, "package.json", false, parsePnpmLock, nil},
	"Cargo.lock":          {resolve.EcosystemCargo, "Cargo.toml", true, parseCargoLock, cargoMembers},
	"Gemfile.lock":        {resolve.EcosystemGem, "Gemfile", true, parseGemfileLock, nil},
	"poetry.lock":         {resolve.EcosystemPyPI, "pyproject.toml", true, parsePoetryLock, nil},
	"composer.lock":       {resolve.EcosystemComposer, "composer.json", true, parseComposerLock, nil},
}

// Supported reports whether path's base name is a lockfile this package
// parses.
func Supported(path string) bool {
	_, ok := lookup(path)
	return ok
}

// ManifestFor returns the base name of the sibling manifest the format of
// path reads, if it reads one.
func ManifestFor(path string) (string, bool) {
	f, ok := lookup(path)
	if !ok || !f.reads {
		return "", false
	}
	return f.manifest, true
}

func lookup(p string) (format, bool) {
	f, ok := formats[path.Base(p)]
	return f, ok
}

// Parse builds the graph of one lockfile. The only error is ErrUnsupported;
// problems with the content are reported on the roots.
func Parse(in Input, lim Limits) (resolve.Graph, error) {
	f, ok := lookup(in.Path)
	if !ok {
		return resolve.Graph{}, ErrUnsupported
	}
	b := newBuilder(in.Path, f, lim)
	manifests := int64(len(in.Manifest))
	for _, m := range in.Members {
		manifests += int64(len(m))
	}
	switch {
	case int64(len(in.Lockfile)) > lim.MaxBytes:
		b.flag(resolve.ReasonTooLarge, fmt.Sprintf("lockfile exceeds %d bytes", lim.MaxBytes))
	case manifests > lim.MaxBytes:
		b.flag(resolve.ReasonTooLarge, fmt.Sprintf("manifests exceed %d bytes", lim.MaxBytes))
	case len(in.Members) > lim.MaxNodes:
		b.flag(resolve.ReasonTooLarge, fmt.Sprintf("more than %d member manifests", lim.MaxNodes))
	default:
		f.parse(b, in.Lockfile, in.Manifest, in.Members)
	}
	return b.graph(), nil
}

// ParseFS reads the lockfile at path in fsys, and the sibling manifest when
// its format reads one, then parses them. For Cargo.lock it also reads the
// manifest of each workspace member the sibling Cargo.toml lists; more than
// MaxNodes of them is too_large, like oversized bytes. The lockfile is read up to MaxBytes+1 bytes, and the
// manifests up to MaxBytes+1 bytes in total, so oversized input costs no more
// than that. A missing manifest is not an error; formats that need it report
// it on the root.
func ParseFS(fsys fs.FS, p string, lim Limits) (resolve.Graph, error) {
	f, ok := lookup(p)
	if !ok {
		return resolve.Graph{}, ErrUnsupported
	}
	in := Input{Path: p}
	var err error
	if in.Lockfile, err = readCapped(fsys, p, lim.MaxBytes); err != nil {
		return resolve.Graph{}, err
	}
	if f.reads {
		in.Manifest, err = readCapped(fsys, path.Join(path.Dir(p), f.manifest), lim.MaxBytes)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return resolve.Graph{}, err
		}
	}
	if f.members != nil && in.Manifest != nil {
		in.Members = f.members(fsys, path.Dir(p), in.Manifest, lim.MaxBytes-int64(len(in.Manifest)), lim.MaxNodes)
	}
	return Parse(in, lim)
}

func readCapped(fsys fs.FS, name string, maxBytes int64) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(io.LimitReader(file, maxBytes+1))
}
