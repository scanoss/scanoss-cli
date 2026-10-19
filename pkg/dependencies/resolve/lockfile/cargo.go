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
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

type cargoPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Dependencies []string `toml:"dependencies"`
}

type cargoManifest struct {
	Package struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Workspace struct {
		Members []string `toml:"members"`
		Exclude []string `toml:"exclude"`
	} `toml:"workspace"`
	cargoTables
	Target map[string]cargoTables `toml:"target"`
}

// cargoTables are the dependency tables of a manifest or of one of its
// [target.*] sections, keyed by the name the crate uses for each dependency.
type cargoTables struct {
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
}

// devOnly returns the packages the manifest needs only as dev dependencies.
// Build dependencies run when users build the crate, so they are runtime.
func (m cargoManifest) devOnly() map[string]bool {
	dev, runtime := map[string]bool{}, map[string]bool{}
	for _, t := range append([]cargoTables{m.cargoTables}, slices.Collect(maps.Values(m.Target))...) {
		for _, deps := range []map[string]any{t.Dependencies, t.BuildDependencies} {
			for name, spec := range deps {
				runtime[cargoPackageName(name, spec)] = true
			}
		}
		for name, spec := range t.DevDependencies {
			dev[cargoPackageName(name, spec)] = true
		}
	}
	for name := range runtime {
		delete(dev, name)
	}
	return dev
}

// cargoPackageName returns the package a dependency names, which differs
// from its key when it is renamed: foo = { package = "bar" }.
func cargoPackageName(name string, spec any) string {
	if t, ok := spec.(map[string]any); ok {
		if p, ok := t["package"].(string); ok {
			return p
		}
	}
	return name
}

// parseCargoLock reads Cargo.lock. Packages without a source are the
// workspace's own crates and path dependencies. Cargo.lock does not say where
// they live, so a local crate is the root at the manifest that names it: the
// sibling Cargo.toml or a member manifest. A local crate that another crate
// depends on is a local node. A local crate that no manifest names is folded
// into the root beside the lockfile when nothing depends on it, or when no
// other root reaches it, as in a cycle of crates that only depend on each
// other.
func parseCargoLock(b *builder, data, manifest []byte, members map[string][]byte) {
	var lock struct {
		Package []cargoPackage `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	pkgs := lock.Package
	dirs, devOnly := cargoDirs(b, manifest, members)
	idx := cargoIndex(pkgs)
	// deps[i][j] is the package that dependency j of package i names, or -1.
	deps := make([][]int, len(pkgs))
	depended := map[int]bool{}
	for i, p := range pkgs {
		for _, dep := range p.Dependencies {
			to := -1
			if match := cargoLookup(idx, pkgs, dep); len(match) == 1 {
				to = match[0]
				depended[to] = true
			}
			deps[i] = append(deps[i], to)
		}
	}

	isRoot := map[int]bool{}
	var queue []int
	for i, p := range pkgs {
		if _, named := dirs[p.Name]; p.Source == "" && (named || !depended[i]) {
			isRoot[i] = true
			queue = append(queue, i)
		}
	}
	reached := maps.Clone(isRoot)
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		for _, to := range deps[i] {
			if to >= 0 && pkgs[to].Source == "" && !reached[to] {
				reached[to] = true
				queue = append(queue, to)
			}
		}
	}

	ids := make([]resolve.NodeID, len(pkgs))
	for i, p := range pkgs {
		switch {
		case p.Source != "":
			ids[i], _ = b.node("", p.Name, p.Version)
		case depended[i]:
			ids[i], _ = b.local("", p.Name, p.Version)
		}
		if p.Source == "" && !reached[i] {
			isRoot[i] = true
		}
	}
	// A root's dev dependencies are known when every crate it stands for has
	// a manifest.
	known := map[*root]bool{}
	for i, p := range pkgs {
		var r *root
		if isRoot[i] {
			r = b.root(dirs[p.Name])
			_, ok := devOnly[p.Name]
			if k, seen := known[r]; !seen || k {
				known[r] = ok
			}
		}
		if r == nil && ids[i] == "" {
			continue
		}
		for j, to := range deps[i] {
			if to < 0 {
				if r != nil {
					r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %q", p.Name, p.Dependencies[j]))
				}
				if ids[i] != "" {
					b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %q", ids[i], p.Dependencies[j]))
				}
				continue
			}
			if ids[to] == "" {
				continue
			}
			dev := p.Source == "" && devOnly[p.Name][pkgs[to].Name]
			if r != nil {
				r.declare(ids[to], dev)
			}
			if !dev {
				b.edge(ids[i], ids[to])
			}
		}
	}
	for r, k := range known {
		r.devKnown = k
	}
}

// cargoDirs maps the crate each manifest declares to the manifest's
// directory, relative to the lockfile's, and to the packages it needs only as
// dev dependencies. A manifest that does not parse is reported on every root
// and left out.
func cargoDirs(b *builder, manifest []byte, members map[string][]byte) (map[string]string, map[string]map[string]bool) {
	dirs, devOnly := map[string]string{}, map[string]map[string]bool{}
	add := func(name string, data []byte) {
		var m cargoManifest
		if err := toml.Unmarshal(data, &m); err != nil {
			b.flag(resolve.ReasonManifestMalformed, fmt.Sprintf("%s: %v", path.Join(path.Dir(b.lockfile), name), err))
			return
		}
		if m.Package.Name != "" {
			dirs[m.Package.Name] = path.Dir(name)
			devOnly[m.Package.Name] = m.devOnly()
		}
	}
	if manifest != nil {
		add("Cargo.toml", manifest)
	}
	for _, name := range slices.Sorted(maps.Keys(members)) {
		add(name, members[name])
	}
	return dirs, devOnly
}

// cargoMembers reads the Cargo.toml of each workspace member that manifest
// lists, expanding its globs under dir and dropping excluded directories. It
// stops once it has read more than maxFiles manifests or more than budget
// bytes, so that Parse reports the excess. Invalid globs and members without a readable
// Cargo.toml are skipped.
func cargoMembers(fsys fs.FS, dir string, manifest []byte, budget int64, maxFiles int) map[string][]byte {
	var m cargoManifest
	if toml.Unmarshal(manifest, &m) != nil {
		return nil
	}
	excluded := func(rel string) bool {
		return slices.ContainsFunc(m.Workspace.Exclude, func(e string) bool {
			e = path.Clean(e)
			return rel == e || strings.HasPrefix(rel, e+"/")
		})
	}
	out := map[string][]byte{}
	for _, pattern := range m.Workspace.Members {
		matches, err := fs.Glob(fsys, path.Join(dir, pattern))
		if err != nil {
			continue
		}
		for _, match := range matches {
			rel, ok := match, true
			if dir != "." {
				rel, ok = strings.CutPrefix(match, dir+"/")
			}
			key := path.Join(rel, "Cargo.toml")
			if _, seen := out[key]; !ok || seen || rel == "." || excluded(rel) {
				continue
			}
			if len(out) > maxFiles || budget < 0 {
				return out
			}
			data, err := readCapped(fsys, path.Join(dir, key), budget)
			if err != nil {
				continue
			}
			out[key] = data
			budget -= int64(len(data))
		}
	}
	return out
}

// cargoLookup returns the packages a dependency string names. Cargo adds the
// source only to the registry or git copy when a path package shares its name
// and version, so a reference that also fits exactly one local package means
// that one.
func cargoLookup(idx map[string][]int, pkgs []cargoPackage, dep string) []int {
	match := idx[strings.Join(strings.Fields(dep), " ")]
	if len(match) < 2 {
		return match
	}
	var local []int
	for _, i := range match {
		if pkgs[i].Source == "" {
			local = append(local, i)
		}
	}
	if len(local) == 1 {
		return local
	}
	return match
}

// cargoIndex maps every way Cargo can name a package ("name", "name
// version", "name version (source)") to the packages it fits. Cargo adds
// detail only where the shorter form would be ambiguous.
func cargoIndex(pkgs []cargoPackage) map[string][]int {
	idx := map[string][]int{}
	for i, p := range pkgs {
		for _, k := range []string{p.Name, p.Name + " " + p.Version, p.Name + " " + p.Version + " (" + p.Source + ")"} {
			idx[k] = append(idx[k], i)
		}
	}
	return idx
}
