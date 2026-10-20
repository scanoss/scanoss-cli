//go:build integration

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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

// These tests run the real mvn, which needs the network to reach Maven
// Central.

var mavenFixture = filepath.Join("testdata", "integration", "maven")

func resolveMavenFixture(t *testing.T, opts Options) resolve.Graph {
	t.Helper()
	g, err := Resolve(t.Context(), mavenFixture, "reactor/pom.xml", opts)
	if err != nil {
		t.Fatal(err)
	}
	checkNoTrees(t, mavenFixture)
	checkMavenGraph(t, g)
	return g
}

func TestMavenIntegration(t *testing.T) {
	g := resolveMavenFixture(t, Options{})
	compareGolden(t, g, filepath.Join(mavenFixture, "graph.golden.json"))
}

func TestMavenIntegrationOffline(t *testing.T) {
	repo := t.TempDir()
	settings := `<settings><localRepository>` + repo + `</localRepository><mirrors><mirror>` +
		`<id>central</id><mirrorOf>*</mirrorOf><url>http://127.0.0.1:9/maven2</url>` +
		`</mirror></mirrors></settings>`
	var env []string
	if mavenAtLeast(t, 3, 9) {
		file := filepath.Join(t.TempDir(), "settings.xml")
		if err := os.WriteFile(file, []byte(settings), 0o644); err != nil {
			t.Fatal(err)
		}
		env = []string{"MAVEN_ARGS=-s " + file + " -Dmaven.repo.local=" + repo}
	} else {
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, ".m2"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".m2", "settings.xml"), []byte(settings), 0o644); err != nil {
			t.Fatal(err)
		}
		// The JVM takes user.home from the password database, not HOME.
		env = []string{"MAVEN_OPTS=-Duser.home=" + home}
	}
	g := resolveMavenFixture(t, Options{Env: env})
	if len(g.Roots) != 3 {
		t.Fatalf("%d roots, want 3: %+v", len(g.Roots), g.Roots)
	}
	for _, r := range g.Roots {
		if r.Status != resolve.StatusPartial || r.Reason != resolve.ReasonRegistryUnreachable {
			t.Errorf("%s is %s (%s): %s, want partial (registry_unreachable)", r.Manifest, r.Status, r.Reason, r.Detail)
		}
	}
}

// mavenAtLeast reports whether mvn on PATH is at least major.minor, the
// first to read MAVEN_ARGS being 3.9.
func mavenAtLeast(t *testing.T, major, minor int) bool {
	t.Helper()
	out, err := exec.Command("mvn", "-v").Output()
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`Apache Maven (\d+)\.(\d+)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("no version in mvn -v: %s", out)
	}
	gotMajor, _ := strconv.Atoi(string(m[1]))
	gotMinor, _ := strconv.Atoi(string(m[2]))
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}
