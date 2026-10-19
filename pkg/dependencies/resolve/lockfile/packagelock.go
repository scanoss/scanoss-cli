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
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

type npmLock struct {
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]npmEntry `json:"packages"`
}

type npmEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Link                 bool              `json:"link"`
	Resolved             string            `json:"resolved"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

const nodeModules = "node_modules/"

// parsePackageLock reads the "packages" map of lockfileVersion 2 and 3. Keys
// are install locations; a key outside node_modules is the project or one of
// its workspaces, and so a root.
func parsePackageLock(b *builder, data, _ []byte) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 {
		b.flag(resolve.ReasonUnsupportedVersion, fmt.Sprintf("lockfileVersion %d", lock.LockfileVersion))
		return
	}
	if lock.Packages == nil {
		b.flag(resolve.ReasonMalformed, "no packages")
		return
	}

	keys := slices.Sorted(maps.Keys(lock.Packages))
	ids := map[string]resolve.NodeID{}
	for _, key := range keys {
		e := lock.Packages[key]
		if !isInstalled(key) || e.Link {
			continue
		}
		name := e.Name
		if name == "" {
			name = key[strings.LastIndex(key, nodeModules)+len(nodeModules):]
		}
		ns, n := parsers.GetScopedPackage(name)
		if id, ok := b.node(ns, n, e.Version); ok {
			ids[key] = id
		}
	}

	// target returns the node at location at. A link points at a workspace
	// folder, which becomes a local node the first time something depends on
	// it; its dependencies are resolved after the other entries'.
	var folders []string
	target := func(at string) (resolve.NodeID, bool) {
		e := lock.Packages[at]
		if !e.Link {
			id, ok := ids[at]
			return id, ok
		}
		dir := e.Resolved
		if id, ok := ids[dir]; ok {
			return id, true
		}
		f, ok := lock.Packages[dir]
		if !ok || f.Link || isInstalled(dir) {
			return "", false
		}
		name := f.Name
		if name == "" {
			name = at[strings.LastIndex(at, nodeModules)+len(nodeModules):]
		}
		ns, n := parsers.GetScopedPackage(name)
		id, ok := b.local(ns, n, f.Version)
		if ok {
			ids[dir] = id
			folders = append(folders, dir)
		}
		return id, ok
	}
	edges := func(from resolve.NodeID, key string, e npmEntry) {
		found, missing := npmDeps(lock.Packages, target, key, e, false)
		for _, to := range found {
			b.edge(from, to)
		}
		for _, name := range missing {
			b.flagNode(from, resolve.ReasonUnresolvedDependency, fmt.Sprintf("%q requires %q", key, name))
		}
	}

	for _, key := range keys {
		e := lock.Packages[key]
		if e.Link {
			continue
		}
		if isInstalled(key) {
			if from, ok := ids[key]; ok {
				edges(from, key, e)
			}
			continue
		}
		r := b.root(key)
		found, missing := npmDeps(lock.Packages, target, key, e, true)
		for _, id := range found {
			r.declare(id)
		}
		for _, name := range missing {
			r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("%q requires %q", key, name))
		}
	}
	for i := 0; i < len(folders); i++ {
		edges(ids[folders[i]], folders[i], lock.Packages[folders[i]])
	}
}

// isInstalled reports whether key is a location under node_modules, rather
// than the project or a workspace folder.
func isInstalled(key string) bool {
	return strings.HasPrefix(key, nodeModules) || strings.Contains(key, "/"+nodeModules)
}

// npmDeps resolves the dependencies of the entry at key, and its dev
// dependencies when dev is set. A missing optional or peer dependency is
// expected, so only missing required ones are returned.
func npmDeps(pkgs map[string]npmEntry, target func(at string) (resolve.NodeID, bool), key string, e npmEntry, dev bool) (found []resolve.NodeID, missing []string) {
	type group struct {
		deps     map[string]string
		optional bool
	}
	groups := []group{{e.Dependencies, false}, {e.OptionalDependencies, true}, {e.PeerDependencies, true}}
	if dev {
		groups = append(groups, group{e.DevDependencies, false})
	}
	for _, g := range groups {
		for _, name := range slices.Sorted(maps.Keys(g.deps)) {
			at, ok := npmLookup(pkgs, key, name)
			if !ok {
				if !g.optional {
					missing = append(missing, name)
				}
				continue
			}
			if id, ok := target(at); ok {
				found = append(found, id)
			}
		}
	}
	return found, missing
}

// npmLookup finds where Node would load name from when required at loc: its
// own node_modules first, then each enclosing node_modules up to the top.
func npmLookup(pkgs map[string]npmEntry, loc, name string) (string, bool) {
	for {
		cand := nodeModules + name
		if loc != "" {
			cand = loc + "/" + cand
		}
		if _, ok := pkgs[cand]; ok {
			return cand, true
		}
		if loc == "" {
			return "", false
		}
		i := strings.LastIndex(loc, nodeModules)
		if i < 0 {
			loc = ""
			continue
		}
		loc = strings.TrimSuffix(loc[:i], "/")
	}
}
