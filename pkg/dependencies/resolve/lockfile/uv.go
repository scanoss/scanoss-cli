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
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/pelletier/go-toml/v2"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// uvDep names a locked package. uv writes the version when the name is
// locked at several.
type uvDep struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type uvPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  struct {
		Editable  string `toml:"editable"`
		Virtual   string `toml:"virtual"`
		Directory string `toml:"directory"`
		Path      string `toml:"path"`
	} `toml:"source"`
	Dependencies         []uvDep            `toml:"dependencies"`
	OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
}

// project returns the directory of an editable or virtual package's
// pyproject.toml, relative to the lockfile's, or "" for any other source.
func (p uvPackage) project() string {
	return cmp.Or(p.Source.Editable, p.Source.Virtual)
}

func (p uvPackage) local() bool {
	return p.project() != "" || p.Source.Directory != "" || p.Source.Path != ""
}

// runtime returns the package's dependencies and those of every extra the
// lockfile resolved for it.
func (p uvPackage) runtime() []uvDep {
	deps := slices.Clone(p.Dependencies)
	for _, extra := range slices.Sorted(maps.Keys(p.OptionalDependencies)) {
		deps = append(deps, p.OptionalDependencies[extra]...)
	}
	return deps
}

// dev returns the dependencies of every dev group.
func (p uvPackage) dev() []uvDep {
	var deps []uvDep
	for _, g := range slices.Sorted(maps.Keys(p.DevDependencies)) {
		deps = append(deps, p.DevDependencies[g]...)
	}
	return deps
}

// parseUvLock reads uv.lock. The project and each workspace member is a root
// at its pyproject.toml, found from its editable or virtual source, and its
// dev-dependencies groups are its dev dependencies. Editable, virtual,
// directory and path packages are local, and become nodes only when another
// package depends on them. A dependency on a name locked at several versions
// names the version; one that does not has an edge to each.
func parseUvLock(b *build.Builder, data, _ []byte, _ map[string][]byte) {
	var lock struct {
		Version  int `toml:"version"`
		Manifest struct {
			Members []string `toml:"members"`
		} `toml:"manifest"`
		Package []uvPackage `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		b.Flag(resolve.ReasonMalformed, err.Error())
		return
	}
	if lock.Version != 1 {
		b.Flag(resolve.ReasonUnsupportedVersion, fmt.Sprintf("version %d", lock.Version))
		return
	}
	pkgs := lock.Package
	members := map[string]bool{}
	for _, m := range lock.Manifest.Members {
		members[pep503(m)] = true
	}
	byName := map[string][]int{}
	for i, p := range pkgs {
		byName[pep503(p.Name)] = append(byName[pep503(p.Name)], i)
	}
	targets := func(d uvDep) []int {
		return slices.DeleteFunc(slices.Clone(byName[pep503(d.Name)]), func(j int) bool {
			return d.Version != "" && pkgs[j].Version != d.Version
		})
	}

	isRoot := make([]bool, len(pkgs))
	depended := make([]bool, len(pkgs))
	for i, p := range pkgs {
		isRoot[i] = p.project() != "" && (members[pep503(p.Name)] || p.project() == ".")
		deps := p.runtime()
		if isRoot[i] {
			deps = append(deps, p.dev()...)
		}
		for _, d := range deps {
			for _, j := range targets(d) {
				depended[j] = depended[j] || j != i
			}
		}
	}
	ids := make([]resolve.NodeID, len(pkgs))
	for i, p := range pkgs {
		switch {
		case !p.local():
			ids[i], _ = b.Node("", pep503(p.Name), p.Version)
		case depended[i]:
			ids[i], _ = b.Local("", pep503(p.Name), p.Version)
		}
	}

	// link hands add the node of each package d names, other than package i
	// itself, and reports d to unresolved when it names none.
	link := func(i int, d uvDep, add func(resolve.NodeID), unresolved func(string)) {
		to := targets(d)
		if len(to) == 0 {
			unresolved(fmt.Sprintf("%s requires %s", pkgs[i].Name, d.Name))
		}
		for _, j := range to {
			if j != i && ids[j] != "" {
				add(ids[j])
			}
		}
	}
	for i, p := range pkgs {
		if ids[i] != "" {
			for _, d := range p.runtime() {
				link(i, d, func(to resolve.NodeID) { b.Edge(ids[i], to) },
					func(detail string) { b.FlagNode(ids[i], resolve.ReasonUnresolvedDependency, detail) })
			}
		}
		if !isRoot[i] {
			continue
		}
		r := b.Root(p.project())
		r.DevKnown = true
		unresolved := func(detail string) { r.Flag(resolve.ReasonUnresolvedDependency, detail) }
		for _, d := range p.runtime() {
			link(i, d, func(id resolve.NodeID) { r.Declare(id, false) }, unresolved)
		}
		for _, d := range p.dev() {
			link(i, d, func(id resolve.NodeID) { r.Declare(id, true) }, unresolved)
		}
	}
}
