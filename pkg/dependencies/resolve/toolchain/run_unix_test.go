//go:build unix

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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
)

func fakeTool(t *testing.T, name, body string, cmds ...string) {
	t.Helper()
	for _, c := range cmds {
		p, err := exec.LookPath(c)
		if err != nil {
			t.Skipf("%s not found: %v", c, err)
		}
		body = strings.ReplaceAll(body, "{"+c+"}", p)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func resolveRoot(t *testing.T, ctx context.Context, opts Options) resolve.Root {
	t.Helper()
	g, err := Resolve(ctx, t.TempDir(), "go.mod", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Roots) != 1 || len(g.Nodes) != 0 {
		t.Fatalf("want one root and no nodes, got %+v", g)
	}
	return g.Roots[0]
}

func TestRunTimeoutKillsTheProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	fakeTool(t, "go", fmt.Sprintf("{sleep} 30 &\necho $! > %s\nwait", pidFile), "sleep")

	start := time.Now()
	r := resolveRoot(t, t.Context(), Options{Timeout: 200 * time.Millisecond})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Resolve took %s after a 200ms timeout", elapsed)
	}
	if r.Status != resolve.StatusUnknown || r.Reason != resolve.ReasonTimeout {
		t.Errorf("root is %s (%s), want unknown (timeout): %s", r.Status, r.Reason, r.Detail)
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the tool's child %d outlived the timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunCancelled(t *testing.T) {
	fakeTool(t, "go", "{sleep} 30", "sleep")
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	r := resolveRoot(t, ctx, Options{})
	if r.Status != resolve.StatusUnknown || r.Reason != resolve.ReasonTimeout || !strings.Contains(r.Detail, "cancelled") {
		t.Errorf("root is %s (%s): %s, want unknown (timeout) for a cancellation", r.Status, r.Reason, r.Detail)
	}
}

func TestRunToolFailed(t *testing.T) {
	fakeTool(t, "go", "echo 'go: errors parsing go.mod' >&2\nexit 1")
	r := resolveRoot(t, t.Context(), Options{})
	if r.Status != resolve.StatusUnknown || r.Reason != resolve.ReasonToolFailed {
		t.Errorf("root is %s (%s), want unknown (tool_failed)", r.Status, r.Reason)
	}
	if !strings.Contains(r.Detail, "go: errors parsing go.mod") {
		t.Errorf("detail %q does not quote stderr", r.Detail)
	}
}

func TestRunStderrTailInDetail(t *testing.T) {
	fakeTool(t, "go", "i=0\nwhile [ $i -lt 500 ]; do echo 'noise noise noise' >&2; i=$((i+1)); done\necho 'go: the real error' >&2\nexit 1")
	r := resolveRoot(t, t.Context(), Options{})
	if r.Reason != resolve.ReasonToolFailed || !strings.HasSuffix(r.Detail, "go: the real error") {
		t.Errorf("root is %s: %q, want tool_failed ending with the last stderr line", r.Reason, r.Detail)
	}
}

func TestRunToolMissing(t *testing.T) {
	t.Setenv("PATH", "")
	r := resolveRoot(t, t.Context(), Options{})
	if r.Status != resolve.StatusUnknown || r.Reason != resolve.ReasonToolMissing {
		t.Errorf("root is %s (%s), want unknown (tool_missing): %s", r.Status, r.Reason, r.Detail)
	}
}

func TestRunOutputTooLarge(t *testing.T) {
	for stream, redirect := range map[string]string{"stdout": "", "stderr": " >&2"} {
		t.Run(stream, func(t *testing.T) {
			fakeTool(t, "go", "while :; do echo '{\"Path\": \"example.com/app\", \"Main\": true}'"+redirect+"; done")
			lim := DefaultLimits()
			lim.MaxOutput = 1 << 10
			r := resolveRoot(t, t.Context(), Options{Limits: lim})
			if r.Status != resolve.StatusUnknown || r.Reason != resolve.ReasonTooLarge {
				t.Errorf("root is %s (%s), want unknown (too_large): %s", r.Status, r.Reason, r.Detail)
			}
		})
	}
}

func TestRunEnvCallerWins(t *testing.T) {
	fakeTool(t, "go", `echo "$GOFLAGS|$GOTOOLCHAIN" >&2; exit 1`)
	r := resolveRoot(t, t.Context(), Options{Env: []string{"GOFLAGS=-mod=mod"}})
	if !strings.HasSuffix(r.Detail, "-mod=mod|local") {
		t.Errorf("detail %q: want the caller's GOFLAGS and the default GOTOOLCHAIN", r.Detail)
	}
}

func TestMavenTimeoutKeepsFinishedModules(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("testdata", "maven", "reactor"))); err != nil {
		t.Fatal(err)
	}
	fakeTool(t, "mvn", `for a in "$@"; do case "$a" in -DoutputFile=*) f="${a#-DoutputFile=}";; esac; done
echo 'com.example:parent:pom:1.0.0' > "$f"
echo 'com.example:core:jar:1.0.0' > "core/$f"
echo '+- junit:junit:jar:4.13.2:test' >> "core/$f"
echo '[INFO] Building app 1.0.0'
{sleep} 30`, "sleep")

	g, err := Resolve(t.Context(), dir, "pom.xml", Options{Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	checkNoTrees(t, dir)
	if r := mavenRoot(t, g, "core/pom.xml"); r.Status != resolve.StatusComplete || len(r.Members) != 1 || !r.Members[0].Dev {
		t.Errorf("core is %s (%s) with %+v, want complete with junit as dev", r.Status, r.Reason, r.Members)
	}
	if r := mavenRoot(t, g, "pom.xml"); r.Status != resolve.StatusComplete {
		t.Errorf("the parent is %s (%s), want complete", r.Status, r.Reason)
	}
	if r := mavenRoot(t, g, "app/pom.xml"); r.Status != resolve.StatusUnknown || r.Reason != resolve.ReasonTimeout {
		t.Errorf("app is %s (%s): %s, want unknown (timeout)", r.Status, r.Reason, r.Detail)
	}
}
