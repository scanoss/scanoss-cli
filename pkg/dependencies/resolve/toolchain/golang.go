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

package toolchain

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// goEnv keeps the go command from rewriting the scanned go.mod
// (-mod=readonly), from downloading a toolchain the go directive asks for
// (GOTOOLCHAIN=local) and from reading a go.work above the module.
var goEnv = []string{"GOWORK=off", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local"}

// goUnreachable is what the go command writes when it cannot reach the
// module proxy or a VCS host.
var goUnreachable = []string{
	"dial tcp",
	"no such host",
	"connection refused",
	"i/o timeout",
	"network is unreachable",
	"TLS handshake timeout",
	"proxyconnect",
	"lookup disabled by GOPROXY=off",
	"connection reset",
}

type goListModule struct {
	Path     string
	Version  string
	Main     bool
	Indirect bool
	Replace  *struct{ Path, Version string }
	Error    *struct{ Err string }
}

type goSelected struct {
	required string // the version as required, which go mod graph names, before any replace
	id       resolve.NodeID
	indirect bool
}

// "go mod graph" names every version any module requires, by its version
// before replacement; only the edges from a selected version are kept,
// pointed at the selected version of their target.
func resolveGo(b *build.Builder, r *build.Root, run runFunc) {
	list := run("go", "list", "-e", "-m", "-json", "all")
	if list.reason != "" {
		r.Flag(list.reason, list.detail)
		return
	}
	var mods []goListModule
	dec := json.NewDecoder(bytes.NewReader(list.stdout))
	for {
		var m goListModule
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			r.Flag(resolve.ReasonMalformed, "go list: "+err.Error())
			return
		}
		mods = append(mods, m)
	}

	main := ""
	selected := map[string]goSelected{}
	for _, m := range mods {
		if m.Main {
			main = m.Path
			continue
		}
		if m.Error != nil {
			reason := resolve.ReasonUnresolvedDependency
			if unreachable(m.Error.Err, goUnreachable) {
				reason = resolve.ReasonRegistryUnreachable
			}
			detail := m.Error.Err
			if !strings.Contains(detail, m.Path) {
				detail = m.Path + ": " + detail
			}
			r.Flag(reason, detail)
		}
		add, path, version := b.Node, m.Path, m.Version
		switch {
		case m.Replace != nil && m.Replace.Version == "":
			add, version = b.Local, ""
		case m.Replace != nil:
			path, version = m.Replace.Path, m.Replace.Version
		}
		i := strings.LastIndex(path, "/")
		if id, ok := add(path[:max(i, 0)], path[i+1:], version); ok {
			selected[m.Path] = goSelected{m.Version, id, m.Indirect}
		}
	}

	graph := run("go", "mod", "graph")
	if graph.reason != "" {
		reason := resolve.ReasonEdgesUnknown
		if graph.reason == resolve.ReasonToolFailed && unreachable(string(graph.stderr), goUnreachable) {
			reason = resolve.ReasonRegistryUnreachable
		}
		r.Flag(reason, graph.detail)
		for _, s := range selected {
			if !s.indirect {
				r.Declare(s.id, false)
			}
		}
		return
	}
	for line := range strings.Lines(string(graph.stdout)) {
		f := strings.Fields(line)
		if len(f) != 2 {
			if len(f) > 0 {
				r.Flag(resolve.ReasonInvalidEntry, "go mod graph: "+strings.TrimSpace(line))
			}
			continue
		}
		fromPath, fromVersion, _ := strings.Cut(f[0], "@")
		toPath, _, _ := strings.Cut(f[1], "@")
		to, ok := selected[toPath]
		if !ok {
			continue
		}
		if fromPath == main && fromVersion == "" {
			if !to.indirect {
				r.Declare(to.id, false)
			}
			continue
		}
		if from, ok := selected[fromPath]; ok && from.required == fromVersion {
			b.Edge(from.id, to.id)
		}
	}
}
