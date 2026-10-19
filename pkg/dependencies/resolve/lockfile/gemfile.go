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
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

type gemSpec struct {
	name, version string
	local         bool // from a PATH section
	deps          []string
}

// parseGemfileLock reads the GEM, GIT and PATH specs and the DEPENDENCIES of
// a Gemfile.lock. PATH gems are the project's own: one that DEPENDENCIES or
// another gem names is a local node. Platform variants of a gem
// ("1.15.4-x86_64-linux") are one node. The Gemfile, when present, says
// which direct dependencies are dev.
func parseGemfileLock(b *builder, data, manifest []byte, _ map[string][]byte) {
	specs, directs, err := scanGemfileLock(string(data))
	if err != nil {
		b.flag(resolve.ReasonMalformed, err.Error())
		return
	}
	named := map[string]bool{}
	for _, name := range directs {
		named[name] = true
	}
	for _, s := range specs {
		for _, dep := range s.deps {
			named[dep] = true
		}
	}
	byName := map[string]resolve.NodeID{}
	ids := make([]resolve.NodeID, len(specs))
	for i, s := range specs {
		version, _, _ := strings.Cut(s.version, "-")
		var id resolve.NodeID
		var ok bool
		switch {
		case !s.local:
			id, ok = b.node("", s.name, version)
		case named[s.name]:
			id, ok = b.local("", s.name, version)
		}
		if ok {
			ids[i] = id
			if _, seen := byName[s.name]; !seen {
				byName[s.name] = id
			}
		}
	}

	for i, s := range specs {
		if ids[i] == "" {
			continue
		}
		for _, dep := range s.deps {
			// Bundler never locks itself, though gems depend on it.
			if dep == "bundler" {
				continue
			}
			if to, ok := byName[dep]; ok {
				b.edge(ids[i], to)
			} else {
				b.flagNode(ids[i], resolve.ReasonUnresolvedDependency, fmt.Sprintf("%s requires %s", s.name, dep))
			}
		}
	}
	// A dependency missing from the specs is one Bundler left out for the
	// locked platforms, such as tzinfo-data outside Windows.
	r := b.root("")
	var dev map[string]bool
	if manifest != nil {
		dev, r.devKnown = gemfileDev(string(manifest))
	}
	for _, name := range directs {
		if id, ok := byName[name]; ok {
			r.declare(id, dev[name])
		}
	}
}

var (
	gemfileGem    = regexp.MustCompile(`^gem\s*\(?\s*["']([^"']+)["']`)
	gemfileGroup  = regexp.MustCompile(`^group\b\s*\(?(.*?)\)?\s*do(\s*\|[^|]*\|)?$`)
	gemfileOption = regexp.MustCompile(`(?:\bgroups?:|:groups?\s*=>)\s*(\[[^\]]*\]|:\w+|"[^"]*"|'[^']*')`)
	gemfileName   = regexp.MustCompile(`^(?::(\w+)|"([^"]*)"|'([^']*)')$`)
	gemfileOpen   = regexp.MustCompile(`^(if|unless|case|begin|while|until|def|class|module)\b|\bdo(\s*\|[^|]*\|)?$`)
	gemfileEnd    = regexp.MustCompile(`^end\b`)
)

// gemfileDev reads a Gemfile line by line and returns, for each gem it
// declares, whether every declaration is only in the development or test
// group. It recognises gem lines, group blocks and group options, and keeps
// count of other blocks; anything else is ignored, so a gem declared in a
// form it does not recognise is runtime. ok is false when the blocks do not
// balance, as then the groups cannot be trusted.
func gemfileDev(gemfile string) (dev map[string]bool, ok bool) {
	dev = map[string]bool{}
	var stack [][]string
	for _, line := range strings.Split(gemfile, "\n") {
		line, _, _ = strings.Cut(strings.TrimSpace(line), " #")
		if strings.HasPrefix(line, "#") {
			continue
		}
		if gemfileEnd.MatchString(line) {
			if len(stack) == 0 {
				return nil, false
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if m := gemfileGroup.FindStringSubmatch(line); m != nil {
			stack = append(stack, gemfileNames(strings.Split(m[1], ",")))
			continue
		}
		if gemfileOpen.MatchString(line) {
			stack = append(stack, nil)
			continue
		}
		m := gemfileGem.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		groups := slices.Concat(stack...)
		if o := gemfileOption.FindStringSubmatch(line); o != nil {
			groups = append(groups, gemfileNames(strings.Split(strings.Trim(o[1], "[]"), ","))...)
		}
		only := len(groups) > 0 && !slices.ContainsFunc(groups, func(g string) bool { return g != "development" && g != "test" })
		if prev, seen := dev[m[1]]; seen {
			only = only && prev
		}
		dev[m[1]] = only
	}
	return dev, len(stack) == 0
}

// gemfileNames returns the group names among symbols and strings, skipping
// anything else, such as an "optional: true" option.
func gemfileNames(args []string) []string {
	var out []string
	for _, a := range args {
		if m := gemfileName.FindStringSubmatch(strings.TrimSpace(a)); m != nil {
			out = append(out, m[1]+m[2]+m[3])
		}
	}
	return out
}

// scanGemfileLock splits a Gemfile.lock into its specs (four-space
// "name (version)" lines, each followed by six-space dependency lines) and
// the names under DEPENDENCIES.
func scanGemfileLock(data string) (specs []gemSpec, directs []string, err error) {
	section, known := "", false
	current := -1
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			continue
		}
		if trimmed == line {
			section, current = line, -1
			known = known || section == "GEM" || section == "GIT" || section == "PATH" || section == "DEPENDENCIES"
			continue
		}
		name, version := gemLine(trimmed)
		switch indent := len(line) - len(trimmed); {
		case section == "DEPENDENCIES" && indent == 2:
			directs = append(directs, strings.TrimSuffix(name, "!"))
		case section != "GEM" && section != "GIT" && section != "PATH":
		case indent == 4:
			specs = append(specs, gemSpec{name: name, version: version, local: section == "PATH"})
			current = len(specs) - 1
		case indent == 6 && current >= 0:
			specs[current].deps = append(specs[current].deps, name)
		}
	}
	if !known {
		return nil, nil, errors.New("no GEM, GIT, PATH or DEPENDENCIES section")
	}
	return specs, directs, nil
}

// gemLine splits "name (version or constraints)".
func gemLine(s string) (name, version string) {
	name, rest, _ := strings.Cut(s, " ")
	return name, strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")")
}
