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

	"github.com/pelletier/go-toml/v2"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// parsePoetryLock reads poetry.lock, and pyproject.toml for the direct
// dependencies. Poetry may lock one name at several versions, each for
// different environment markers; a dependency on that name then has an edge
// to every one of them. A path dependency (source type "directory" or
// "file") is a local node.
func parsePoetryLock(b *builder, data, manifest []byte, _ map[string][]byte) {
	var lock struct {
		Package []struct {
			Name         string         `toml:"name"`
			Version      string         `toml:"version"`
			Dependencies map[string]any `toml:"dependencies"`
			Source       struct {
				Type string `toml:"type"`
			} `toml:"source"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	byName := map[string][]resolve.NodeID{}
	ids := make([]resolve.NodeID, len(lock.Package))
	for i, p := range lock.Package {
		name := pep503(p.Name)
		add := b.node
		if p.Source.Type == "directory" || p.Source.Type == "file" {
			add = b.local
		}
		if id, ok := add("", name, p.Version); ok {
			ids[i] = id
			byName[name] = append(byName[name], id)
		}
	}
	for i, p := range lock.Package {
		if ids[i] == "" {
			continue
		}
		for _, dep := range slices.Sorted(maps.Keys(p.Dependencies)) {
			to, ok := byName[pep503(dep)]
			if !ok && !poetryOptional(p.Dependencies[dep]) {
				b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s", p.Name, dep))
			}
			for _, id := range to {
				b.edge(ids[i], id)
			}
		}
	}
	pyprojectDirects(b.root(""), manifest, byName)
}

func pyprojectDirects(r *root, manifest []byte, byName map[string][]resolve.NodeID) {
	if manifest == nil {
		r.flag(resolve.ReasonManifestMissing, "pyproject.toml not found")
		return
	}
	var py struct {
		Tool struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
	}
	if err := toml.Unmarshal(manifest, &py); err != nil {
		r.flag(resolve.ReasonManifestMalformed, err.Error())
		return
	}
	declare := func(dep string, optional bool) {
		ids, ok := byName[pep503(dep)]
		if !ok && !optional {
			r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("pyproject.toml requires %s", dep))
		}
		for _, id := range ids {
			r.declare(id, false)
		}
	}
	poetry := py.Tool.Poetry
	tables := []map[string]any{poetry.Dependencies, poetry.DevDependencies}
	for _, g := range slices.Sorted(maps.Keys(poetry.Group)) {
		tables = append(tables, poetry.Group[g].Dependencies)
	}
	for _, deps := range tables {
		for _, dep := range slices.Sorted(maps.Keys(deps)) {
			if dep != "python" {
				declare(dep, poetryOptional(deps[dep]))
			}
		}
	}
	for _, dep := range py.Project.Dependencies {
		declare(dep, false)
	}
	for _, extra := range slices.Sorted(maps.Keys(py.Project.OptionalDependencies)) {
		for _, dep := range py.Project.OptionalDependencies[extra] {
			declare(dep, true)
		}
	}
}

// poetryOptional reports whether a dependency is only installed for an
// extra, so a lockfile without it is still complete. The value is a version
// string, a table, or an array of tables for different markers.
func poetryOptional(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		return v["optional"] == true
	case []any:
		for _, e := range v {
			if !poetryOptional(e) {
				return false
			}
		}
		return len(v) > 0
	}
	return false
}

// pep503 returns the normalised name a requirement such as
// "Foo_Bar[extra]>=1.0" is about: lower case, with runs of "-", "_" and "."
// as one "-", and without extras, version or markers.
func pep503(req string) string {
	var out strings.Builder
	sep := false
	for _, c := range strings.TrimSpace(req) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c == '-' || c == '_' || c == '.':
			sep = true
			continue
		default:
			return out.String()
		}
		if sep && out.Len() > 0 {
			out.WriteByte('-')
		}
		sep = false
		out.WriteRune(c)
	}
	return out.String()
}
