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
	"maps"
	"path"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

type pnpmLock struct {
	LockfileVersion string                  `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	pnpmImporter    `yaml:",inline"`        // a single project's dependencies before v9
	Packages        map[string]pnpmPackage  `yaml:"packages"`
	Snapshots       map[string]pnpmPackage  `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmRef `yaml:"dependencies"`
	DevDependencies      map[string]pnpmRef `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmRef `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// pnpmRef is the version an importer resolved a dependency to: a plain
// string up to v5, a {specifier, version} map from v6.
type pnpmRef string

func (r *pnpmRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*r = pnpmRef(n.Value)
		return nil
	}
	var v struct {
		Version string `yaml:"version"`
	}
	err := n.Decode(&v)
	*r = pnpmRef(v.Version)
	return err
}

// pnpmStyle captures how a lockfile version spells package keys.
type pnpmStyle struct {
	// key returns the package key a dependency on name at version points to.
	key func(name, version string) string
	// split returns the name and version, without peer suffix, of a key.
	split func(key string) (name, version string)
}

var (
	pnpmV5 = pnpmStyle{
		key: func(name, version string) string { return "/" + name + "/" + version },
		split: func(key string) (string, string) {
			i := strings.LastIndex(key, "/")
			if i < 0 {
				return key, ""
			}
			version, _, _ := strings.Cut(key[i+1:], "_")
			return strings.TrimPrefix(key[:i], "/"), version
		},
	}
	pnpmV6 = pnpmStyle{
		key:   func(name, version string) string { return "/" + name + "@" + version },
		split: func(key string) (string, string) { return splitAt(strings.TrimPrefix(key, "/")) },
	}
	pnpmV9 = pnpmStyle{
		key:   func(name, version string) string { return name + "@" + version },
		split: splitAt,
	}
)

// splitAt splits "name@version(peer@1)" into name and version.
func splitAt(key string) (string, string) {
	key, _, _ = strings.Cut(key, "(")
	i := strings.LastIndex(key, "@")
	if i <= 0 {
		return key, ""
	}
	return key[:i], key[i+1:]
}

// parsePnpmLock reads pnpm-lock.yaml 5.x, 6.x and 9.x. Each importer (each
// workspace project) is a root. Packages that differ only by the peers they
// were installed with are one node.
func parsePnpmLock(b *builder, data, _ []byte) {
	var lock pnpmLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	var style pnpmStyle
	pkgs := lock.Packages
	switch v := lock.LockfileVersion; {
	case v == "5" || strings.HasPrefix(v, "5."):
		style = pnpmV5
	case strings.HasPrefix(v, "6."):
		style = pnpmV6
	case strings.HasPrefix(v, "9."):
		style, pkgs = pnpmV9, lock.Snapshots
	default:
		b.flag(resolve.ReasonUnsupportedVersion, fmt.Sprintf("lockfileVersion %q", v))
		return
	}

	// lookup returns the node a dependency points to. A version that is itself
	// a package key is an alias or a non-registry package.
	ids := map[string]resolve.NodeID{}
	lookup := func(name, version string) (resolve.NodeID, bool) {
		if id, ok := ids[version]; ok {
			return id, true
		}
		id, ok := ids[style.key(name, version)]
		return id, ok
	}

	importers := lock.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": lock.pnpmImporter}
	}
	// link returns the importer at rel, a "link:" path relative to the
	// importer dir that depends on it, as a local node. Its dependencies are resolved
	// once every package is a node.
	locals := map[string]resolve.NodeID{}
	var linked []string
	link := func(dir, name, rel string) (resolve.NodeID, bool) {
		to := path.Join(dir, rel)
		if id, ok := locals[to]; ok {
			return id, true
		}
		if _, ok := importers[to]; !ok {
			return "", false
		}
		ns, n := parsers.GetScopedPackage(name)
		id, ok := b.local(ns, n, "")
		if ok {
			locals[to] = id
			linked = append(linked, to)
		}
		return id, ok
	}
	// deps resolves the dependencies of the importer or package at dir. It
	// returns the nodes they point to and, as "name version", the required
	// ones that point nowhere; a link that is not an importer is neither.
	deps := func(dir string, optional map[string]string, groups ...map[string]string) (found []resolve.NodeID, missing []string) {
		for _, deps := range groups {
			for _, name := range slices.Sorted(maps.Keys(deps)) {
				version := deps[name]
				if rel, ok := strings.CutPrefix(version, "link:"); ok {
					if id, ok := link(dir, name, rel); ok {
						found = append(found, id)
					}
				} else if id, ok := lookup(name, version); ok {
					found = append(found, id)
				} else if _, ok := optional[name]; !ok {
					missing = append(missing, name+" "+version)
				}
			}
		}
		return found, missing
	}
	edges := func(from resolve.NodeID, what string, found []resolve.NodeID, missing []string) {
		for _, to := range found {
			b.edge(from, to)
		}
		for _, m := range missing {
			b.flagNode(from, resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s", what, m))
		}
	}

	keys := slices.Sorted(maps.Keys(pkgs))
	for _, key := range keys {
		name, version := style.split(key)
		ns, n := parsers.GetScopedPackage(name)
		if id, ok := b.node(ns, n, version); ok {
			ids[key] = id
		}
	}
	for _, key := range keys {
		if from, ok := ids[key]; ok {
			p := pkgs[key]
			found, missing := deps(".", p.OptionalDependencies, p.Dependencies, p.OptionalDependencies)
			edges(from, key, found, missing)
		}
	}
	for _, dir := range slices.Sorted(maps.Keys(importers)) {
		r, imp := b.root(dir), importers[dir]
		found, missing := deps(dir, refs(imp.OptionalDependencies), refs(imp.Dependencies), refs(imp.DevDependencies), refs(imp.OptionalDependencies))
		for _, id := range found {
			r.declare(id)
		}
		for _, m := range missing {
			r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("importer %q requires %s", dir, m))
		}
	}
	for i := 0; i < len(linked); i++ {
		imp := importers[linked[i]]
		found, missing := deps(linked[i], refs(imp.OptionalDependencies), refs(imp.Dependencies), refs(imp.OptionalDependencies))
		edges(locals[linked[i]], fmt.Sprintf("importer %q", linked[i]), found, missing)
	}
}

func refs(m map[string]pnpmRef) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}
