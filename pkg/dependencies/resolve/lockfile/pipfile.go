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

	"github.com/pelletier/go-toml/v2"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// parsePipfileLock reads Pipfile.lock, whose "default" and "develop" maps
// pin every package with no edges, and the Pipfile for the direct
// dependencies: [packages] are runtime and [dev-packages] dev. A develop
// package that the Pipfile does not name is a member that is not direct,
// and so not dev. A path package is a local node, except the project's own
// directory. A VCS package has no version and is left out.
func parsePipfileLock(b *builder, data, manifest []byte, _ map[string][]byte) {
	type entry struct {
		Version string `json:"version"`
		Path    string `json:"path"`
	}
	var lock struct {
		Default map[string]entry `json:"default"`
		Develop map[string]entry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	if lock.Default == nil && lock.Develop == nil {
		b.flag(resolve.ReasonMalformed, "no default or develop packages")
		return
	}
	b.flag(resolve.ReasonEdgesUnknown, "Pipfile.lock records no edges")
	byName := map[string][]resolve.NodeID{}
	for _, section := range []map[string]entry{lock.Default, lock.Develop} {
		for _, name := range slices.Sorted(maps.Keys(section)) {
			e := section[name]
			add := b.node
			switch {
			case e.Path == ".":
				continue
			case e.Path != "":
				add = b.local
			}
			if id, ok := add("", pep503(name), strings.TrimLeft(e.Version, "=")); ok && !slices.Contains(byName[pep503(name)], id) {
				byName[pep503(name)] = append(byName[pep503(name)], id)
			}
		}
	}

	r := b.root("")
	if manifest == nil {
		r.flag(resolve.ReasonManifestMissing, "Pipfile not found")
		return
	}
	var pipfile struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if err := toml.Unmarshal(manifest, &pipfile); err != nil {
		r.flag(resolve.ReasonManifestMalformed, err.Error())
		return
	}
	r.devKnown = true
	for _, t := range []struct {
		deps map[string]any
		dev  bool
	}{{pipfile.Packages, false}, {pipfile.DevPackages, true}} {
		for _, name := range slices.Sorted(maps.Keys(t.deps)) {
			ids, ok := byName[pep503(name)]
			if !ok {
				r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("Pipfile requires %s", name))
			}
			for _, id := range ids {
				r.declare(id, t.dev)
			}
		}
	}
}
