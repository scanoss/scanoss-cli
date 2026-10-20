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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/graphtest"
)

// recordedMaven copies a case under testdata/maven to a new directory and
// serves its recorded mvn run: each module's tree.txt is written where mvn
// writes the tree, and stdout.txt and stderr.txt are the log, a failed run
// when it says BUILD FAILURE.
func recordedMaven(t *testing.T, caseDir string) (string, runFunc) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(caseDir)); err != nil {
		t.Fatal(err)
	}
	return dir, func(name string, args ...string) output {
		var file string
		for _, a := range args {
			if v, ok := strings.CutPrefix(a, "-DoutputFile="); ok {
				file = v
			}
		}
		if name != "mvn" || file == "" || strings.ContainsRune(file, filepath.Separator) {
			t.Fatalf("unexpected run of %s %q", name, args)
		}
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.Name() != "tree.txt" {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(filepath.Dir(p), file), data, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := os.ReadFile(filepath.Join(dir, "stdout.txt"))
		if err != nil {
			t.Fatal(err)
		}
		stderr, _ := os.ReadFile(filepath.Join(dir, "stderr.txt"))
		if !bytes.Contains(stdout, []byte("BUILD FAILURE")) {
			return output{stdout: stdout, stderr: stderr}
		}
		out := failed("mvn", errors.New("exit status 1"), stderr)
		out.stdout = stdout
		return out
	}
}

func resolveMavenRecorded(t *testing.T, caseDir string) resolve.Graph {
	t.Helper()
	dir, run := recordedMaven(t, caseDir)
	lim := DefaultLimits()
	g := resolveMaven(project{
		manifest:  "pom.xml",
		dir:       dir,
		lim:       build.Limits{MaxNodes: lim.MaxNodes, MaxEdges: lim.MaxEdges},
		maxOutput: lim.MaxOutput,
		run:       run,
	})
	checkNoTrees(t, dir)
	checkMavenGraph(t, g)
	return g
}

// checkMavenGraph checks each root as the graph of its module's pom, which it
// was built as, and that the merge kept the nodes and roots sorted and unique
// and every node in a root.
func checkMavenGraph(t *testing.T, g resolve.Graph) {
	t.Helper()
	lim := DefaultLimits()
	nodes := map[resolve.NodeID]resolve.Node{}
	for i, n := range g.Nodes {
		if i > 0 && g.Nodes[i-1].ID >= n.ID {
			t.Errorf("nodes not sorted and unique at %q", n.ID)
		}
		nodes[n.ID] = n
	}
	inRoot := map[resolve.NodeID]bool{}
	for i, r := range g.Roots {
		if i > 0 && g.Roots[i-1].Manifest >= r.Manifest {
			t.Errorf("roots not sorted and unique at %q", r.Manifest)
		}
		module := resolve.Graph{Nodes: []resolve.Node{}, Roots: []resolve.Root{r}}
		for _, m := range r.Members {
			module.Nodes = append(module.Nodes, nodes[m.ID])
			inRoot[m.ID] = true
		}
		graphtest.Check(t, module, r.Manifest, build.Limits{MaxNodes: lim.MaxNodes, MaxEdges: lim.MaxEdges})
	}
	for id := range nodes {
		if !inRoot[id] {
			t.Errorf("node %q is in no root", id)
		}
	}
}

// checkNoTrees fails when a tree mvn wrote is left in dir.
func checkNoTrees(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), ".dependency-tree-") {
			t.Errorf("%s was left behind", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestMavenGolden resolves every case under testdata/maven from its recorded
// output and compares the graph with the case's graph.golden.json.
func TestMavenGolden(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("testdata", "maven", "*"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			g := resolveMavenRecorded(t, dir)
			if again := resolveMavenRecorded(t, dir); !reflect.DeepEqual(g, again) {
				t.Fatalf("not deterministic:\n%+v\n%+v", g, again)
			}
			compareGolden(t, g, filepath.Join(dir, "graph.golden.json"))
		})
	}
}

func mavenRoot(t *testing.T, g resolve.Graph, manifest string) resolve.Root {
	t.Helper()
	for _, r := range g.Roots {
		if r.Manifest == manifest {
			return r
		}
	}
	t.Fatalf("no root for %s in %+v", manifest, g.Roots)
	return resolve.Root{}
}

func member(r resolve.Root, id resolve.NodeID) (resolve.Member, bool) {
	i := slices.IndexFunc(r.Members, func(m resolve.Member) bool { return m.ID == id })
	if i < 0 {
		return resolve.Member{}, false
	}
	return r.Members[i], true
}

func hasEdge(r resolve.Root, from, to resolve.NodeID) bool {
	return slices.Contains(r.Edges, resolve.Edge{From: from, To: to})
}

func TestMavenStatuses(t *testing.T) {
	type status struct {
		status resolve.Status
		reason resolve.Reason
		detail string // a part of the detail
	}
	complete := status{status: resolve.StatusComplete}
	for _, tt := range []struct {
		name  string
		roots map[string]status
	}{
		{"reactor", map[string]status{"pom.xml": complete, "core/pom.xml": complete, "app/pom.xml": complete}},
		{"missing-pom", map[string]status{"pom.xml": {resolve.StatusPartial, resolve.ReasonUnresolvedDependency, "com.example.absent:absent:jar:1.0.0"}}},
		{"network", map[string]status{
			"pom.xml":      complete,
			"core/pom.xml": {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "on project core"},
			"app/pom.xml":  {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "skipped after core failed"},
		}},
		{"network-maven39", map[string]status{
			"pom.xml":      complete,
			"core/pom.xml": {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "on project core"},
			"app/pom.xml":  {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "skipped after core failed"},
		}},
		{"plugin-maven39", map[string]status{
			"pom.xml":      {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "maven-dependency-plugin:3.8.1"},
			"core/pom.xml": {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "maven-dependency-plugin:3.8.1"},
			"app/pom.xml":  {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "maven-dependency-plugin:3.8.1"},
		}},
		{"tool-failed", map[string]status{"pom.xml": {resolve.StatusUnknown, resolve.ReasonToolFailed, "No versions available"}}},
		{"plugin", map[string]status{
			"pom.xml":      {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "maven-dependency-plugin:3.8.1"},
			"core/pom.xml": {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "maven-dependency-plugin:3.8.1"},
			"app/pom.xml":  {resolve.StatusPartial, resolve.ReasonRegistryUnreachable, "maven-dependency-plugin:3.8.1"},
		}},
		{"invalid-entry", map[string]status{"pom.xml": {resolve.StatusPartial, resolve.ReasonInvalidEntry, "commons-codec:commons-codec:1.16.0"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := resolveMavenRecorded(t, filepath.Join("testdata", "maven", tt.name))
			if len(g.Roots) != len(tt.roots) {
				t.Errorf("%d roots, want %d", len(g.Roots), len(tt.roots))
			}
			for manifest, want := range tt.roots {
				r := mavenRoot(t, g, manifest)
				if r.Status != want.status || r.Reason != want.reason || !strings.Contains(r.Detail, want.detail) {
					t.Errorf("%s is %s (%s): %q, want %s (%s) with %q", manifest, r.Status, r.Reason, r.Detail, want.status, want.reason, want.detail)
				}
				if (r.Status == resolve.StatusUnknown || r.Reason == resolve.ReasonRegistryUnreachable) && len(r.Members) != 0 {
					t.Errorf("%s has members %v", manifest, r.Members)
				}
			}
		})
	}
}

func TestMavenReactor(t *testing.T) {
	g := resolveMavenRecorded(t, filepath.Join("testdata", "maven", "reactor"))
	core := resolve.NodeID("pkg:maven/com.example/core@1.0.0")
	if i := slices.IndexFunc(g.Nodes, func(n resolve.Node) bool { return n.ID == core }); i < 0 || !g.Nodes[i].Local {
		t.Errorf("the sibling module %s is not a local node", core)
	}
	app := mavenRoot(t, g, "app/pom.xml")
	if m, ok := member(app, core); !ok || !m.Direct || m.Dev {
		t.Errorf("app: core is %+v, want a direct runtime member", m)
	}
	if !hasEdge(app, "pkg:maven/com.google.guava/guava@33.0.0-jre", "pkg:maven/org.checkerframework/checker-qual@3.41.0") {
		t.Error("app: no edge to the node omitted for duplicate")
	}
	if m, ok := member(app, "pkg:maven/org.checkerframework/checker-qual@3.41.0"); !ok || !m.Direct || m.Dev {
		t.Errorf("app: the provided dependency is %+v, want a direct runtime member", m)
	}
	coreRoot := mavenRoot(t, g, "core/pom.xml")
	for id, dev := range map[resolve.NodeID]bool{
		"pkg:maven/junit/junit@4.13.2":                true,
		"pkg:maven/org.hamcrest/hamcrest-core@1.3":    true,
		"pkg:maven/com.google.guava/guava@33.0.0-jre": false,
	} {
		if m, ok := member(coreRoot, id); !ok || m.Dev != dev || !coreRoot.DevKnown {
			t.Errorf("core: %s is %+v, want dev %v", id, m, dev)
		}
	}
	if len(mavenRoot(t, g, "pom.xml").Members) != 0 {
		t.Error("the parent pom has members")
	}
}

// TestMavenVersionsPerModule resolves two modules that pick different
// versions of y under the same x: a takes y 2 and omits y 1 for the
// conflict, b takes y 1. Neither root may reach the other's y.
func TestMavenVersionsPerModule(t *testing.T) {
	g := resolveMavenRecorded(t, filepath.Join("testdata", "maven", "module-versions"))
	x := resolve.NodeID("pkg:maven/org.example/x@1.0")
	for _, tt := range []struct {
		manifest      string
		want, notWant []resolve.NodeID
	}{
		{"a/pom.xml", []resolve.NodeID{"pkg:maven/org.example/y@2", "pkg:maven/org.example/y2-only@1.0"}, []resolve.NodeID{"pkg:maven/org.example/y@1", "pkg:maven/org.example/y1-only@1.0"}},
		{"b/pom.xml", []resolve.NodeID{"pkg:maven/org.example/y@1", "pkg:maven/org.example/y1-only@1.0"}, []resolve.NodeID{"pkg:maven/org.example/y@2", "pkg:maven/org.example/y2-only@1.0"}},
	} {
		r := mavenRoot(t, g, tt.manifest)
		if r.Lockfile != tt.manifest {
			t.Errorf("%s: lockfile %s, want the module's own pom", tt.manifest, r.Lockfile)
		}
		if !hasEdge(r, x, tt.want[0]) {
			t.Errorf("%s: no edge from x to %s", tt.manifest, tt.want[0])
		}
		for _, id := range tt.want {
			if _, ok := member(r, id); !ok {
				t.Errorf("%s: %s is not a member", tt.manifest, id)
			}
		}
		for _, id := range tt.notWant {
			if _, ok := member(r, id); ok {
				t.Errorf("%s reaches %s, which only the other module picked", tt.manifest, id)
			}
		}
	}
}

func TestMavenOmittedEdges(t *testing.T) {
	g := resolveMavenRecorded(t, filepath.Join("testdata", "maven", "omitted"))
	r := mavenRoot(t, g, "pom.xml")
	httpclient := resolve.NodeID("pkg:maven/org.apache.httpcomponents/httpclient@4.5.14")
	for _, to := range []resolve.NodeID{"pkg:maven/commons-codec/commons-codec@1.16.0", "pkg:maven/commons-logging/commons-logging@1.2"} {
		if !hasEdge(r, httpclient, to) {
			t.Errorf("no edge %s -> %s", httpclient, to)
		}
	}
	if _, ok := member(r, "pkg:maven/commons-codec/commons-codec@1.11"); ok {
		t.Error("the version that lost the conflict is a member")
	}

	g = resolveMavenRecorded(t, filepath.Join("testdata", "maven", "cycle"))
	if !hasEdge(mavenRoot(t, g, "pom.xml"), "pkg:maven/org.example/b@1.0", "pkg:maven/org.example/a@1.0") {
		t.Error("no edge to the node omitted for cycle")
	}

	g = resolveMavenRecorded(t, filepath.Join("testdata", "maven", "classifier"))
	if _, ok := member(mavenRoot(t, g, "pom.xml"), "pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final"); !ok {
		t.Error("the dependency with a classifier is not a member")
	}

	g = resolveMavenRecorded(t, filepath.Join("testdata", "maven", "invalid-entry"))
	if _, ok := member(mavenRoot(t, g, "pom.xml"), "pkg:maven/org.example/orphan@1.0"); ok {
		t.Error("the child of an unparseable line is a member")
	}
}

func TestMavenFailureReason(t *testing.T) {
	for text, want := range map[string]resolve.Reason{
		"Could not transfer artifact a:b:pom:1 from/to central (http://127.0.0.1:9/maven2): transfer failed for http://127.0.0.1:9/a.pom: Connect to 127.0.0.1:9 failed: Connection refused": resolve.ReasonRegistryUnreachable,
		"Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the artifact a:b:jar:1 has not been downloaded from it before":                                     resolve.ReasonRegistryUnreachable,
		"Could not transfer artifact a:b:pom:1 from/to private (https://repo.example.com): status code: 401, reason phrase: Unauthorized (401)":                                              resolve.ReasonToolFailed,
		"Could not transfer artifact a:b:pom:1 from/to private (https://repo.example.com): transfer failed for https://repo.example.com/a.pom, status code: 403":                             resolve.ReasonToolFailed,
		"No versions available for a:b:jar:[99.0,100.0) within specified range":                                                                                                              resolve.ReasonToolFailed,
	} {
		if got := mavenReason(text); got != want {
			t.Errorf("mavenReason(%q) = %s, want %s", text, got, want)
		}
	}
}

func TestMavenModules(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("pom.xml", `<project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>top</artifactId>
		<modules><module>a</module><module>b/b-pom.xml</module><module>${gone}</module></modules>
		<profiles><profile><modules><module>extra</module><module>a</module></modules></profile></profiles></project>`)
	write("a/pom.xml", `<project><parent><artifactId>top</artifactId></parent><artifactId>a</artifactId><name>Module A</name>
		<modules><module>nested</module></modules></project>`)
	write("a/nested/pom.xml", `<project><artifactId>nested</artifactId></project>`)
	write("b/b-pom.xml", `<project><artifactId>b</artifactId></project>`)
	write("extra/pom.xml", `<project><artifactId>extra</artifactId><modules><module>../a</module></modules></project>`)

	want := []mavenModule{
		{dir: ".", artifactID: "top", name: "top"},
		{dir: "a", artifactID: "a", name: "Module A"},
		{dir: "a/nested", artifactID: "nested", name: "nested"},
		{dir: "b", artifactID: "b", name: "b"},
		{dir: "extra", artifactID: "extra", name: "extra", optional: true},
	}
	if got := mavenModules(dir, 1<<20); !reflect.DeepEqual(got, want) {
		t.Errorf("mavenModules:\n got %+v\nwant %+v", got, want)
	}
}
