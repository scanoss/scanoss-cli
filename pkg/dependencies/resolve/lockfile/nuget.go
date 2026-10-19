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
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

type nugetEntry struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
}

// parseNuGetLock reads packages.lock.json, which locks each target framework
// (and runtime, as "net8.0/linux-x64") separately. Every package of every
// target is a node, and each dependency resolves to the version locked for
// it in the same target, or, for a runtime, in its framework. NuGet ids are
// case-insensitive, so a package keeps the casing it is first written with.
// Project entries are the solution's own projects, local nodes without a
// version. The lockfile does not say which packages are dev dependencies.
//
// The lockfile sits beside its project file, whose name varies, so the root
// is named after the one project file in members, or after the lockfile
// itself without one.
func parseNuGetLock(b *builder, data, _ []byte, members map[string][]byte) {
	if len(members) == 1 {
		b.manifest = slices.Collect(maps.Keys(members))[0]
	}
	var lock struct {
		Version      int                              `json:"version"`
		Dependencies map[string]map[string]nugetEntry `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	if lock.Version != 1 && lock.Version != 2 {
		b.flag(resolve.ReasonUnsupportedVersion, fmt.Sprintf("version %d", lock.Version))
		return
	}
	if lock.Dependencies == nil {
		b.flag(resolve.ReasonMalformed, "no dependencies")
		return
	}
	r := b.root("")

	targets := slices.Sorted(maps.Keys(lock.Dependencies))
	names := map[string]string{} // lower-case id to the casing first seen
	ids := map[string]map[string]resolve.NodeID{}
	for _, t := range targets {
		ids[t] = map[string]resolve.NodeID{}
		pkgs := lock.Dependencies[t]
		depended := map[string]bool{}
		for _, e := range pkgs {
			for dep := range e.Dependencies {
				depended[strings.ToLower(dep)] = true
			}
		}
		for _, id := range slices.Sorted(maps.Keys(pkgs)) {
			e, key := pkgs[id], strings.ToLower(id)
			if _, ok := names[key]; !ok {
				names[key] = id
			}
			add := b.node
			if e.Type == "Project" {
				add = b.local
			}
			node, ok := add("", names[key], e.Resolved)
			if !ok {
				continue
			}
			ids[t][key] = node
			// A project that nothing else references is one of the root's
			// own project references.
			if e.Type == "Direct" || (e.Type == "Project" && !depended[key]) {
				r.declare(node, false)
			}
		}
	}
	for _, t := range targets {
		framework, _, _ := strings.Cut(t, "/")
		pkgs := lock.Dependencies[t]
		for _, id := range slices.Sorted(maps.Keys(pkgs)) {
			from, ok := ids[t][strings.ToLower(id)]
			if !ok {
				continue
			}
			for _, dep := range slices.Sorted(maps.Keys(pkgs[id].Dependencies)) {
				to, ok := ids[t][strings.ToLower(dep)]
				if !ok {
					to, ok = ids[framework][strings.ToLower(dep)]
				}
				if !ok {
					b.flagNode(from, resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s in %s", id, dep, t))
					continue
				}
				b.edge(from, to)
			}
		}
	}
}

// nugetProject finds the project file beside packages.lock.json. Only its
// name is used, so it is not read. It returns nothing unless there is
// exactly one.
func nugetProject(fsys fs.FS, dir string, _ []byte, _ int64, _ int) map[string][]byte {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var found []string
	for _, e := range entries {
		switch path.Ext(e.Name()) {
		case ".csproj", ".fsproj", ".vbproj":
			if !e.IsDir() {
				found = append(found, e.Name())
			}
		}
	}
	if len(found) != 1 {
		return nil
	}
	return map[string][]byte{found[0]: nil}
}
