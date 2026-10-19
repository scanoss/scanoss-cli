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
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

type cargoPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Dependencies []string `toml:"dependencies"`
}

// parseCargoLock reads Cargo.lock. Packages without a source are the
// workspace's own crates and path dependencies; they are folded into the one
// root, so what they depend on from a registry or git is direct.
func parseCargoLock(b *builder, data, _ []byte) {
	var lock struct {
		Package []cargoPackage `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	r := b.root("")
	idx := cargoIndex(lock.Package)
	ids := make([]resolve.NodeID, len(lock.Package))
	for i, p := range lock.Package {
		if p.Source != "" {
			ids[i], _ = b.node("", p.Name, p.Version)
		}
	}
	for i, p := range lock.Package {
		local := p.Source == ""
		if !local && ids[i] == "" {
			continue
		}
		for _, dep := range p.Dependencies {
			match := idx[strings.Join(strings.Fields(dep), " ")]
			ok := len(match) == 1
			switch {
			case !ok && local:
				r.flag(resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %q", p.Name, dep))
			case !ok:
				b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %q", ids[i], dep))
			case ids[match[0]] == "":
			case local:
				r.declare(ids[match[0]])
			default:
				b.edge(ids[i], ids[match[0]])
			}
		}
	}
}

// cargoIndex maps every way Cargo can name a package ("name", "name
// version", "name version (source)") to the packages it fits. Cargo adds
// detail only where the shorter form would be ambiguous.
func cargoIndex(pkgs []cargoPackage) map[string][]int {
	idx := map[string][]int{}
	for i, p := range pkgs {
		for _, k := range []string{p.Name, p.Name + " " + p.Version, p.Name + " " + p.Version + " (" + p.Source + ")"} {
			idx[k] = append(idx[k], i)
		}
	}
	return idx
}
