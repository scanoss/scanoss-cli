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

	keys := slices.Sorted(maps.Keys(pkgs))
	for _, key := range keys {
		name, version := style.split(key)
		ns, n := parsers.GetScopedPackage(name)
		if id, ok := b.node(ns, n, version); ok {
			ids[key] = id
		}
	}
	for _, key := range keys {
		from, ok := ids[key]
		if !ok {
			continue
		}
		p := pkgs[key]
		for _, deps := range []map[string]string{p.Dependencies, p.OptionalDependencies} {
			for _, name := range slices.Sorted(maps.Keys(deps)) {
				if strings.HasPrefix(deps[name], "link:") {
					continue
				}
				if to, ok := lookup(name, deps[name]); ok {
					b.edge(from, to)
				} else if _, optional := p.OptionalDependencies[name]; !optional {
					b.flagNode(from, resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s %s", key, name, deps[name]))
				}
			}
		}
	}

	importers := lock.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": lock.pnpmImporter}
	}
	for _, dir := range slices.Sorted(maps.Keys(importers)) {
		r, imp := b.root(dir), importers[dir]
		for _, deps := range []map[string]pnpmRef{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for _, name := range slices.Sorted(maps.Keys(deps)) {
				version := string(deps[name])
				if strings.HasPrefix(version, "link:") {
					continue
				}
				if id, ok := lookup(name, version); ok {
					r.declare(id)
				} else if _, optional := imp.OptionalDependencies[name]; !optional {
					r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("importer %q requires %s %s", dir, name, version))
				}
			}
		}
	}
}
