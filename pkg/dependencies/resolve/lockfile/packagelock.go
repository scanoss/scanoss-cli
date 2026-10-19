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
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

const nodeModules = "node_modules/"

// parsePackageLock reads the "packages" map of lockfileVersion 2 and 3. Keys
// are install locations; a key outside node_modules is the project or one of
// its workspaces, and so a root.
func parsePackageLock(b *builder, data, _ []byte, _ map[string][]byte) {
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

	for _, key := range keys {
		e := lock.Packages[key]
		if e.Link {
			continue
		}
		found, missing := npmDeps(lock.Packages, ids, key, e)
		if !isInstalled(key) {
			r := b.root(key)
			for _, id := range found {
				r.declare(id)
			}
			for _, name := range missing {
				r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("%q requires %q", key, name))
			}
			continue
		}
		from, ok := ids[key]
		if !ok {
			continue
		}
		for _, to := range found {
			b.edge(from, to)
		}
		for _, name := range missing {
			b.flagNode(from, resolve.ReasonUnresolvedDependency, fmt.Sprintf("%q requires %q", key, name))
		}
	}
}

// isInstalled reports whether key is a location under node_modules, rather
// than the project or a workspace folder.
func isInstalled(key string) bool {
	return strings.HasPrefix(key, nodeModules) || strings.Contains(key, "/"+nodeModules)
}

// npmDeps resolves the dependencies of the entry at key. A missing optional or
// peer dependency is expected, so only missing required ones are returned.
// Dependencies that resolve to a link (a workspace) are neither.
func npmDeps(pkgs map[string]npmEntry, ids map[string]resolve.NodeID, key string, e npmEntry) (found []resolve.NodeID, missing []string) {
	type group struct {
		deps     map[string]string
		optional bool
	}
	groups := []group{{e.Dependencies, false}, {e.OptionalDependencies, true}, {e.PeerDependencies, true}}
	if !isInstalled(key) {
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
			if id, ok := ids[at]; ok {
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
