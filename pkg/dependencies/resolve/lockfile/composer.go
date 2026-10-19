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

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// composerLinks is a name-to-constraint map. PHP encodes an empty one as [].
type composerLinks map[string]string

func (l *composerLinks) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("[]")) {
		return nil
	}
	return json.Unmarshal(data, (*map[string]string)(l))
}

// names returns the package names in l, sorted, without platform
// requirements such as php or ext-json, which have no vendor.
func (l composerLinks) names() []string {
	var out []string
	for _, name := range slices.Sorted(maps.Keys(l)) {
		if strings.Contains(name, "/") {
			out = append(out, name)
		}
	}
	return out
}

type composerPackage struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Require composerLinks `json:"require"`
	Replace composerLinks `json:"replace"`
	Provide composerLinks `json:"provide"`
}

// parseComposerLock reads composer.lock, and composer.json for the direct
// dependencies. A requirement may be met by a package that replaces or
// provides the name, as laravel/framework does for illuminate/*. A name
// locked twice resolves to its first entry, so packages win over
// packages-dev.
func parseComposerLock(b *builder, data, manifest []byte) {
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	pkgs := slices.Concat(lock.Packages, lock.PackagesDev)
	byName := map[string]resolve.NodeID{}
	ids := make([]resolve.NodeID, len(pkgs))
	for i, p := range pkgs {
		vendor, name, _ := strings.Cut(strings.ToLower(p.Name), "/")
		if id, ok := b.node(vendor, name, p.Version); ok {
			ids[i] = id
			if _, seen := byName[strings.ToLower(p.Name)]; !seen {
				byName[strings.ToLower(p.Name)] = id
			}
		}
	}
	for i, p := range pkgs {
		for _, name := range slices.Concat(p.Replace.names(), p.Provide.names()) {
			if _, ok := byName[strings.ToLower(name)]; !ok && ids[i] != "" {
				byName[strings.ToLower(name)] = ids[i]
			}
		}
	}
	for i, p := range pkgs {
		if ids[i] == "" {
			continue
		}
		for _, name := range p.Require.names() {
			if to, ok := byName[strings.ToLower(name)]; ok {
				b.edge(ids[i], to)
			} else {
				b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s", p.Name, name))
			}
		}
	}

	r := b.root("")
	if manifest == nil {
		r.flag(resolve.ReasonManifestMissing, "composer.json not found")
		return
	}
	var cj struct {
		Require    composerLinks `json:"require"`
		RequireDev composerLinks `json:"require-dev"`
	}
	if err := json.Unmarshal(manifest, &cj); err != nil {
		r.flag(resolve.ReasonManifestMalformed, err.Error())
		return
	}
	for _, name := range slices.Concat(cj.Require.names(), cj.RequireDev.names()) {
		if id, ok := byName[strings.ToLower(name)]; ok {
			r.declare(id)
		} else {
			r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("composer.json requires %s", name))
		}
	}
}
