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
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// yarnEntry is one block of a yarn.lock: the descriptors ("name@range") that
// resolve to it, and what it resolves to.
type yarnEntry struct {
	descriptors []string
	name        string
	version     string
	deps        map[string]string
	optional    map[string]string
}

// parseYarnLock reads yarn.lock v1, whose direct dependencies are only in
// package.json, and yarn berry, which records each workspace as an entry.
func parseYarnLock(b *builder, data, manifest []byte) {
	if bytes.HasPrefix(data, []byte("__metadata:")) || bytes.Contains(data, []byte("\n__metadata:")) {
		parseYarnBerry(b, data)
		return
	}
	entries, err := parseYarnV1(data)
	if err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	index := map[string]resolve.NodeID{}
	ids := make([]resolve.NodeID, len(entries))
	for i, e := range entries {
		ns, n := parsers.GetScopedPackage(e.name)
		id, ok := b.node(ns, n, e.version)
		if !ok {
			continue
		}
		ids[i] = id
		for _, d := range e.descriptors {
			index[d] = id
		}
	}
	for i, e := range entries {
		if ids[i] == "" {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(e.deps)) {
			if to, ok := index[name+"@"+e.deps[name]]; ok {
				b.edge(ids[i], to)
			} else {
				b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s@%s", ids[i], name, e.deps[name]))
			}
		}
		for _, name := range slices.Sorted(maps.Keys(e.optional)) {
			if to, ok := index[name+"@"+e.optional[name]]; ok {
				b.edge(ids[i], to)
			}
		}
	}
	yarnDirects(b.root(""), manifest, index)
}

func yarnDirects(r *root, manifest []byte, index map[string]resolve.NodeID) {
	if manifest == nil {
		r.flag(resolve.ReasonManifestMissing, "package.json not found")
		return
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		Workspaces           json.RawMessage   `json:"workspaces"`
	}
	if err := json.Unmarshal(manifest, &pkg); err != nil {
		r.flag(resolve.ReasonManifestMalformed, err.Error())
		return
	}
	if len(pkg.Workspaces) > 0 && string(pkg.Workspaces) != "null" {
		r.flag(resolve.ReasonUnsupportedWorkspaces, "yarn.lock v1 does not record which workspace declares what")
	}
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for _, name := range slices.Sorted(maps.Keys(deps)) {
			if id, ok := index[name+"@"+deps[name]]; ok {
				r.declare(id)
			} else if _, optional := pkg.OptionalDependencies[name]; !optional {
				r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("package.json requires %s@%s", name, deps[name]))
			}
		}
	}
}

// parseYarnV1 reads the indented v1 format: an unindented header listing the
// entry's descriptors, then two-space fields, then four-space dependencies.
func parseYarnV1(data []byte) ([]yarnEntry, error) {
	var entries []yarnEntry
	var section map[string]string
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(trimmed)
		if indent > 0 && len(entries) == 0 {
			return nil, fmt.Errorf("line %d: field outside an entry", n+1)
		}
		switch indent {
		case 0:
			header, ok := strings.CutSuffix(trimmed, ":")
			if !ok {
				return nil, fmt.Errorf("line %d: entry header does not end with a colon", n+1)
			}
			e := yarnEntry{deps: map[string]string{}, optional: map[string]string{}}
			for _, d := range strings.Split(header, ",") {
				e.descriptors = append(e.descriptors, strings.Trim(strings.TrimSpace(d), `"`))
			}
			e.name = descriptorPackage(e.descriptors[0])
			entries = append(entries, e)
		case 2:
			e := &entries[len(entries)-1]
			section = nil
			switch key, value := yarnPair(trimmed); {
			case key == "version":
				e.version = value
			case trimmed == "dependencies:":
				section = e.deps
			case trimmed == "optionalDependencies:":
				section = e.optional
			}
		case 4:
			if section != nil {
				key, value := yarnPair(trimmed)
				section[key] = value
			}
		}
	}
	return entries, nil
}

// yarnPair splits `key "value"`, where either side may be quoted.
func yarnPair(s string) (key, value string) {
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			return s[1 : end+1], strings.Trim(strings.TrimSpace(s[end+2:]), `"`)
		}
	}
	key, value, _ = strings.Cut(s, " ")
	return key, strings.Trim(strings.TrimSpace(value), `"`)
}

// splitDescriptor splits "name@range"; a scoped name keeps its leading "@".
func splitDescriptor(d string) (name, rng string) {
	if i := strings.Index(d[min(1, len(d)):], "@"); i >= 0 {
		return d[:i+1], d[i+2:]
	}
	return d, ""
}

// descriptorPackage returns the package a descriptor installs, which differs
// from its name for an alias such as "foo@npm:bar@^1.0.0".
func descriptorPackage(d string) string {
	name, rng := splitDescriptor(d)
	if target, ok := strings.CutPrefix(rng, "npm:"); ok {
		if real, _ := splitDescriptor(target); real != target {
			return real
		}
	}
	return name
}

type berryEntry struct {
	Version      string            `yaml:"version"`
	Resolution   string            `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
	LinkType     string            `yaml:"linkType"`
}

// berryLocal is the placeholder version yarn gives workspaces and soft links.
const berryLocal = "0.0.0-use.local"

// parseYarnBerry reads the YAML lockfile of yarn 2 and later. Workspace
// entries ("name@workspace:path") are roots. A workspace or soft link
// (link:, portal:) that something depends on is also a local node.
func parseYarnBerry(b *builder, data []byte) {
	var lock map[string]berryEntry
	if err := yaml.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	delete(lock, "__metadata")
	keys := slices.Sorted(maps.Keys(lock))

	index := map[string]string{}
	for _, key := range keys {
		for _, d := range strings.Split(key, ",") {
			// Relative protocols (link:, portal:, file:) carry the locator of the
			// workspace that declared them, which dependency ranges omit.
			d, _, _ = strings.Cut(strings.TrimSpace(d), "::")
			index[d] = key
		}
	}
	// target returns the entry a dependency of key resolves to.
	target := func(key, name string) (string, string, bool) {
		rng := lock[key].Dependencies[name]
		if !strings.Contains(rng, ":") {
			rng = "npm:" + rng
		}
		t, ok := index[name+"@"+rng]
		return t, rng, ok
	}
	depended := map[string]bool{}
	for _, key := range keys {
		for name := range lock[key].Dependencies {
			if t, _, ok := target(key, name); ok {
				depended[t] = true
			}
		}
	}

	ids := map[string]resolve.NodeID{}
	roots := map[string]*root{}
	for _, key := range keys {
		e := lock[key]
		name, rng := splitDescriptor(e.Resolution)
		ns, n := parsers.GetScopedPackage(name)
		dir, workspace := strings.CutPrefix(rng, "workspace:")
		if workspace {
			roots[key] = b.root(dir)
		}
		if !workspace && e.LinkType != "soft" {
			if id, ok := b.node(ns, n, e.Version); ok {
				ids[key] = id
			}
		} else if depended[key] {
			version := e.Version
			if version == berryLocal {
				version = ""
			}
			if id, ok := b.local(ns, n, version); ok {
				ids[key] = id
			}
		}
	}

	for _, key := range keys {
		r, from := roots[key], ids[key]
		if r == nil && from == "" {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(lock[key].Dependencies)) {
			t, rng, found := target(key, name)
			if !found {
				detail := fmt.Sprintf("%s requires %s@%s", key, name, rng)
				if r != nil {
					r.flag(resolve.ReasonUnresolvedDependency, detail)
				} else {
					b.flagNode(from, resolve.ReasonUnresolvedDependency, detail)
				}
				continue
			}
			to, isNode := ids[t]
			if !isNode {
				continue
			}
			if r != nil {
				r.declare(to)
			}
			if from != "" {
				b.edge(from, to)
			}
		}
	}
}
