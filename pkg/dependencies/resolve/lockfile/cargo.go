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
}

// parseCargoLock reads Cargo.lock. Packages without a source are the
// workspace's own crates and path dependencies. Cargo.lock does not say where
// they live, so a local crate is the root at the manifest that names it: the
// sibling Cargo.toml or a member manifest. What it depends on from a registry
// or git is direct; its links to other local crates are dropped. Local crates
// that no manifest names are folded into the root beside the lockfile.
func parseCargoLock(b *builder, data, manifest []byte, members map[string][]byte) {
	var lock struct {
		Package []cargoPackage `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	dirs := cargoDirs(b, manifest, members)
	idx := cargoIndex(lock.Package)
	ids := make([]resolve.NodeID, len(lock.Package))
	for i, p := range lock.Package {
		if p.Source != "" {
			ids[i], _ = b.node("", p.Name, p.Version)
		}
	}
	for i, p := range lock.Package {
		local := p.Source == ""
		if !local && ids[i] == "" {
			continue
		}
		var r *root
		if local {
			r = b.root(dirs[p.Name])
		}
		for _, dep := range p.Dependencies {
			match := cargoLookup(idx, lock.Package, dep)
			ok := len(match) == 1
			switch {
			case !ok && local:
				r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %q", p.Name, dep))
			case !ok:
				b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %q", ids[i], dep))
			case ids[match[0]] == "":
			case local:
				r.declare(ids[match[0]])
			default:
				b.edge(ids[i], ids[match[0]])
			}
		}
	}
}

// cargoDirs maps the crate each manifest declares to the manifest's
// directory, relative to the lockfile's. A manifest that does not parse is
// reported on every root and left out.
func cargoDirs(b *builder, manifest []byte, members map[string][]byte) map[string]string {
	dirs := map[string]string{}
	add := func(name string, data []byte) {
		var m cargoManifest
		if err := toml.Unmarshal(data, &m); err != nil {
			b.flag(resolve.ReasonManifestMalformed, fmt.Sprintf("%s: %v", path.Join(path.Dir(b.lockfile), name), err))
			return
		}
		if m.Package.Name != "" {
			dirs[m.Package.Name] = path.Dir(name)
		}
	}
	if manifest != nil {
		add("Cargo.toml", manifest)
	}
	for _, name := range slices.Sorted(maps.Keys(members)) {
		add(name, members[name])
	}
	return dirs
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
