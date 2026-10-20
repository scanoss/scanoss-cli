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
	"cmp"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// mavenTreePlugin is pinned because only the text output of its verbose tree
// keeps the edges to the nodes Maven omits; its JSON output ignores verbose.
const mavenTreePlugin = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1"

// mavenUnreachable is what mvn logs when it cannot reach a repository, and
// mavenAnswered a repository that answered, which is not a network problem.
var (
	mavenUnreachable = regexp.MustCompile(`Connection refused|Connect to |connect timed out|Read timed out|` +
		`UnknownHostException|Unknown host|Network is unreachable|No route to host|` +
		`Cannot access .* in offline mode|transfer failed for`)
	mavenAnswered = regexp.MustCompile(`status code: 40[134]\b|\b40[134] (?:Unauthorized|Forbidden|Not Found)\b`)
)

var (
	mavenFailedError    = regexp.MustCompile(`^Failed to execute goal (?:\S+ (?:\(\S+\) )?)?on project ([^\s:]+): `)
	mavenHelp           = regexp.MustCompile(`\s*-> \[Help \d+\]$`)
	mavenSkippedLine    = regexp.MustCompile(`^\[INFO\] (.+?) \.{2,} SKIPPED\b`)
	mavenMissingPOMLine = regexp.MustCompile(`^\[WARNING\] The POM for (\S+) is missing, no dependency information available`)
)

type mavenModule struct {
	dir        string // slash, relative to the top pom's directory
	artifactID string
	name       string // as in the reactor summary
	optional   bool   // declared only in a profile, so maybe not built
}

type mavenPOM struct {
	ArtifactID string   `xml:"artifactId"`
	Name       string   `xml:"name"`
	Modules    []string `xml:"modules>module"`
	Profiles   []struct {
		Modules []string `xml:"modules>module"`
	} `xml:"profiles>profile"`
}

// resolveMaven runs the dependency plugin's tree goal on the reactor of the
// pom, which writes one tree per module into the module's directory under a
// hidden name made for this call. It reads them all and removes them, also
// when mvn fails or times out. A module that wrote no tree gets the error the
// log gives for it. mvn from PATH is used, never the repository's mvnw.
//
// Maven mediates versions per module, so each module gets its own builder:
// one module's edges never lead another's root to versions it did not pick.
func resolveMaven(p project) resolve.Graph {
	mods := mavenModules(p.dir, p.maxOutput)
	name := ".dependency-tree-" + rand.Text() + ".txt"
	out := p.run("mvn", "-B", "-ntp", "-fae", "-Dstyle.color=never", mavenTreePlugin+":tree",
		"-Dverbose=true", "-DoutputType=text", "-DoutputFile="+name)
	trees := takeMavenTrees(p.dir, name, mods, p.maxOutput)
	log := parseMavenLog(out)

	reactor := map[string]bool{}
	for _, t := range trees {
		first, _, _ := strings.Cut(string(t.data), "\n")
		if f := strings.Split(strings.TrimSpace(first), ":"); len(f) >= 4 {
			reactor[f[0]+":"+f[1]+":"+f[len(f)-1]] = true
		}
	}
	module := func(dir string) *build.Builder {
		return build.New(path.Join(path.Dir(p.manifest), dir, "pom.xml"), resolve.EcosystemMaven, "pom.xml", p.lim)
	}
	var graphs []resolve.Graph
	for _, dir := range slices.Sorted(maps.Keys(trees)) {
		b := module(dir)
		r := b.Root("")
		r.DevKnown = true
		if trees[dir].tooLarge {
			r.Flag(resolve.ReasonTooLarge, fmt.Sprintf("%s: dependency tree exceeds %d bytes", b.Lockfile(), p.maxOutput))
		} else {
			ids := parseMavenTree(b, r, trees[dir].data, reactor)
			for _, m := range log.missingPOMs {
				if id, ok := ids[m.gav]; ok {
					b.FlagNode(id, resolve.ReasonUnresolvedDependency, m.line)
				}
			}
		}
		graphs = append(graphs, b.Graph())
	}
	for _, m := range mods {
		if _, ok := trees[m.dir]; ok {
			continue
		}
		if reason, detail := log.failure(m, out); reason != "" {
			b := module(m.dir)
			b.Root("").Flag(reason, detail)
			graphs = append(graphs, b.Graph())
		}
	}
	return build.Merge(graphs...)
}

// mavenModules lists the pom's directory and its modules, recursively. An
// entry of <modules> names a directory or a pom file in one.
func mavenModules(top string, maxSize int64) []mavenModule {
	var mods []mavenModule
	seen := map[string]int{}
	var walk func(dir, file string, optional bool)
	walk = func(dir, file string, optional bool) {
		i, ok := seen[dir]
		if ok && (optional || !mods[i].optional) {
			return
		}
		var pom mavenPOM
		data, tooLarge, err := readCapped(filepath.Join(top, filepath.FromSlash(dir), file), maxSize)
		if err == nil && !tooLarge {
			err = xml.Unmarshal(data, &pom)
		}
		if (err != nil || tooLarge) && dir != "." {
			return // mvn fails the build on it, which the top pom's root reports
		}
		if ok {
			mods[i].optional = false
		} else {
			seen[dir] = len(mods)
			mods = append(mods, mavenModule{dir, pom.ArtifactID, cmp.Or(pom.Name, pom.ArtifactID), optional})
		}
		child := func(entry string, optional bool) {
			entry = path.Join(dir, filepath.ToSlash(strings.TrimSpace(entry)))
			if info, err := os.Stat(filepath.Join(top, filepath.FromSlash(entry))); err == nil && !info.IsDir() {
				walk(path.Dir(entry), path.Base(entry), optional)
				return
			}
			walk(entry, "pom.xml", optional)
		}
		for _, e := range pom.Modules {
			child(e, optional)
		}
		for _, p := range pom.Profiles {
			for _, e := range p.Modules {
				child(e, true)
			}
		}
	}
	walk(".", "pom.xml", false)
	return mods
}

type mavenTree struct {
	data     []byte
	tooLarge bool
}

// takeMavenTrees reads and removes the trees named name, in the module
// directories and wherever else under top mvn wrote one, keyed by slash
// directory relative to top.
func takeMavenTrees(top, name string, mods []mavenModule, maxSize int64) map[string]mavenTree {
	dirs := map[string]bool{}
	for _, m := range mods {
		dirs[m.dir] = true
	}
	_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == name {
			if rel, err := filepath.Rel(top, filepath.Dir(p)); err == nil {
				dirs[filepath.ToSlash(rel)] = true
			}
		}
		return nil
	})
	trees := map[string]mavenTree{}
	for dir := range dirs {
		file := filepath.Join(top, filepath.FromSlash(dir), name)
		data, tooLarge, err := readCapped(file, maxSize)
		_ = os.Remove(file)
		if err == nil {
			trees[dir] = mavenTree{data, tooLarge}
		}
	}
	return trees
}

func readCapped(file string, maxSize int64) (data []byte, tooLarge bool, err error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	data, err = io.ReadAll(io.LimitReader(f, maxSize+1))
	if int64(len(data)) > maxSize {
		return nil, true, err
	}
	return data, false, err
}

// parseMavenTree adds one module's verbose tree. Its first line is the module
// itself; each other line is a prefix of three-character groups, one per
// level, then g:a:type[:classifier]:version:scope. A line in parentheses is a
// node Maven omitted, which has no children: the edge goes to that node, or
// for a conflict to the version that won. It returns the nodes it added by
// g:a:version.
func parseMavenTree(b *build.Builder, r *build.Root, data []byte, reactor map[string]bool) map[string]resolve.NodeID {
	ids := map[string]resolve.NodeID{}
	var parents []resolve.NodeID // the node at each level above the line; "" when dropped
	first := true
	for line := range strings.Lines(string(data)) {
		line = strings.TrimRight(line, "\r\n")
		if first || strings.TrimSpace(line) == "" {
			first = false
			continue
		}
		depth, rest := mavenDepth(line)
		if depth == 0 || depth > len(parents)+1 {
			r.Flag(resolve.ReasonInvalidEntry, "dependency tree line "+line)
			continue
		}
		parents = parents[:depth-1]
		if depth > 1 && parents[depth-2] == "" {
			parents = append(parents, "")
			continue
		}
		e, ok := parseMavenEntry(rest)
		if !ok {
			r.Flag(resolve.ReasonInvalidEntry, "dependency tree line "+line)
			parents = append(parents, "")
			continue
		}
		key := e.group + ":" + e.artifact + ":" + e.version
		add := b.Node
		if reactor[key] {
			add = b.Local
		}
		id, ok := add(e.group, e.artifact, e.version)
		if !ok {
			parents = append(parents, "")
			continue
		}
		ids[key] = id
		if depth == 1 {
			r.Declare(id, e.scope == "test")
		} else {
			b.Edge(parents[depth-2], id)
		}
		if e.omitted {
			id = ""
		}
		parents = append(parents, id)
	}
	return ids
}

func mavenDepth(line string) (int, string) {
	depth := 0
	for len(line) >= 3 {
		switch line[:3] {
		case "+- ", `\- `:
			return depth + 1, line[3:]
		case "|  ", "   ":
			depth++
			line = line[3:]
		default:
			return 0, line
		}
	}
	return 0, line
}

type mavenEntry struct {
	group, artifact, version, scope string
	omitted                         bool
}

func parseMavenEntry(s string) (mavenEntry, bool) {
	var e mavenEntry
	coords, note := s, ""
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		var ok bool
		if coords, note, ok = strings.Cut(s[1:len(s)-1], " - "); !ok || !strings.Contains(note, "omitted for ") {
			return e, false
		}
		e.omitted = true
	} else if c, annotation, ok := strings.Cut(s, " "); ok {
		if !strings.HasPrefix(annotation, "(") || !strings.HasSuffix(annotation, ")") {
			return e, false
		}
		coords = c
	}
	f := strings.Split(coords, ":")
	if (len(f) != 5 && len(f) != 6) || slices.Contains(f, "") {
		return e, false
	}
	e.group, e.artifact, e.version, e.scope = f[0], f[1], f[len(f)-2], f[len(f)-1]
	if _, winner, ok := strings.Cut(note, "omitted for conflict with "); ok {
		if v := strings.Fields(strings.TrimRight(winner, ";)")); len(v) > 0 {
			e.version = strings.TrimRight(v[0], ";")
		}
	}
	return e, true
}

type mavenMissingPOM struct {
	gav, line string
}

// mavenLog is what the build log says about the modules.
type mavenLog struct {
	failures    map[string]string // artifactId to its error
	firstFailed string            // artifactId
	skipped     []string          // reactor summary names
	plugin      string            // the error that the tree plugin could not be resolved
	firstError  string
	missingPOMs []mavenMissingPOM
}

func parseMavenLog(out output) mavenLog {
	l := mavenLog{failures: map[string]string{}}
	var lines []string
	for line := range strings.Lines(string(out.stdout) + "\n" + string(out.stderr)) {
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if m := mavenSkippedLine.FindStringSubmatch(line); m != nil {
			l.skipped = append(l.skipped, m[1])
		}
		if m := mavenMissingPOMLine.FindStringSubmatch(line); m != nil {
			if f := strings.Split(m[1], ":"); len(f) >= 4 {
				l.missingPOMs = append(l.missingPOMs, mavenMissingPOM{f[0] + ":" + f[1] + ":" + f[len(f)-1], strings.TrimPrefix(line, "[WARNING] ")})
			}
		}
	}
	for _, e := range mavenErrors(lines) {
		if m := mavenFailedError.FindStringSubmatch(e); m != nil {
			if _, ok := l.failures[m[1]]; !ok {
				l.failures[m[1]] = e
			}
			l.firstFailed = cmp.Or(l.firstFailed, m[1])
		}
		if strings.HasPrefix(e, "Plugin "+mavenTreePlugin) && strings.Contains(e, "could not be resolved") {
			l.plugin = cmp.Or(l.plugin, e)
		}
		l.firstError = cmp.Or(l.firstError, e)
	}
	return l
}

// mavenErrors joins the [ERROR] lines of each error. Maven 3.8 puts an error
// on one line ending in "-> [Help 1]"; 3.9 puts its causes on the lines
// after it and "-> [Help 1]" on a line of its own.
func mavenErrors(lines []string) []string {
	var errs []string
	open := false
	for _, line := range lines {
		text, ok := strings.CutPrefix(line, "[ERROR] ")
		text = strings.TrimSpace(text)
		if !ok || text == "" {
			open = false
			continue
		}
		end := mavenHelp.MatchString(text)
		text = mavenHelp.ReplaceAllString(text, "")
		switch {
		case open && text != "" && !mavenFailedError.MatchString(text):
			errs[len(errs)-1] += " " + text
		case text != "":
			errs = append(errs, text)
		}
		open = !end
	}
	return errs
}

// failure is the reason and detail of a module that wrote no tree: its own
// error, or the error of the module whose failure made Maven skip it, or the
// run's. A module only a profile declares and the log does not name was not
// in the build, and gets no root.
func (l mavenLog) failure(m mavenModule, out output) (resolve.Reason, string) {
	if text, ok := l.failures[m.artifactID]; ok && m.artifactID != "" {
		return mavenReason(text), text
	}
	if l.firstFailed != "" && l.wasSkipped(m) {
		return mavenReason(l.failures[l.firstFailed]), "skipped after " + l.firstFailed + " failed"
	}
	switch {
	case m.optional && !l.wasSkipped(m):
		return "", ""
	case out.reason != "" && out.reason != resolve.ReasonToolFailed:
		return out.reason, out.detail
	case l.plugin != "":
		return mavenReason(l.plugin), l.plugin
	case out.reason != "":
		text := cmp.Or(l.firstError, out.detail)
		return mavenReason(text), text
	}
	return resolve.ReasonToolFailed, fmt.Sprintf("mvn wrote no dependency tree for %s", path.Join(m.dir, "pom.xml"))
}

func (l mavenLog) wasSkipped(m mavenModule) bool {
	for _, s := range l.skipped {
		for _, n := range []string{m.name, m.artifactID} {
			if n != "" && (s == n || strings.HasPrefix(s, n+" ")) {
				return true
			}
		}
	}
	return false
}

func mavenReason(text string) resolve.Reason {
	if mavenUnreachable.MatchString(text) && !mavenAnswered.MatchString(text) {
		return resolve.ReasonRegistryUnreachable
	}
	return resolve.ReasonToolFailed
}
