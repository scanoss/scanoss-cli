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

package wfp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/wfp/wfp2"
)

// A source long enough to yield both wfp1 and wfp2 minutiae, so the two blocks can be
// compared.
const wfp2Source = `int add(int a, int b) {
    int result = a + b;
    return result;
}
int mul(int a, int b) {
    int acc = 0;
    for (int i = 0; i < b; i++) {
        acc = acc + a;
    }
    return acc;
}
long combine(int x, int y, int z) {
    long total = add(x, y);
    total = total + mul(total, z);
    return total;
}
`

// The wfp2 block is additive: with it off the WFP is exactly today's; with it on the same
// bytes are followed by a "wfp2=" marker and the token-aware minutiae, which match the
// pkg/wfp/wfp2 port exactly.
func TestGenerateFingerprintWFP2Block(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.c")
	if err := os.WriteFile(path, []byte(wfp2Source), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	off, err := generateFingerprint(path, dir, options{keepHeaders: true})
	if err != nil {
		t.Fatalf("generateFingerprint (off): %v", err)
	}
	on, err := generateFingerprint(path, dir, options{keepHeaders: true, wfp2: true})
	if err != nil {
		t.Fatalf("generateFingerprint (on): %v", err)
	}

	// Off: the classic WFP, with no wfp2 marker anywhere.
	if strings.Contains(off.Fingerprint, "wfp2=") {
		t.Errorf("wfp2 off, yet a wfp2= marker appeared:\n%s", off.Fingerprint)
	}

	// On: the classic bytes are a prefix — the wfp1 half is untouched — followed by the
	// marker line and the wfp2 minutiae.
	if !strings.HasPrefix(on.Fingerprint, off.Fingerprint) {
		t.Fatalf("wfp2 on changed the classic bytes.\n--- off ---\n%s\n--- on ---\n%s", off.Fingerprint, on.Fingerprint)
	}
	tail := strings.TrimPrefix(on.Fingerprint, off.Fingerprint)
	if !strings.HasPrefix(tail, "wfp2=\n") {
		t.Fatalf("wfp2 block does not start with the marker line; tail = %q", tail)
	}

	// The minutiae after the marker are exactly what the port produces for this file.
	wantMinutiae := formatWFP2(wfp2.Minutiae([]byte(wfp2Source)))
	gotMinutiae := strings.TrimSuffix(strings.TrimPrefix(tail, "wfp2=\n"), "\n")
	if gotMinutiae != wantMinutiae {
		t.Errorf("wfp2 minutiae mismatch\n got: %q\nwant: %q", gotMinutiae, wantMinutiae)
	}
	if wantMinutiae == "" {
		t.Fatal("fixture produced no wfp2 minutiae; choose a longer source")
	}
}

// A source too short to yield any wfp2 minutiae must not emit a bare "wfp2=" marker: the
// block is written only when there is something to put in it.
func TestGenerateFingerprintWFP2NoEmptyMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.c")
	if err := os.WriteFile(path, []byte("int x;\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fp, err := generateFingerprint(path, dir, options{keepHeaders: true, wfp2: true})
	if err != nil {
		t.Fatalf("generateFingerprint: %v", err)
	}
	if len(wfp2.Minutiae([]byte("int x;\n"))) != 0 {
		t.Skip("fixture unexpectedly produced wfp2 minutiae")
	}
	if strings.Contains(fp.Fingerprint, "wfp2=") {
		t.Errorf("empty wfp2 block emitted a bare marker:\n%s", fp.Fingerprint)
	}
}

// WithWFP2 reaches generateFingerprint through the public Files entry point, the way the
// scan and wfp commands drive it.
func TestFilesWithWFP2Option(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.c")
	if err := os.WriteFile(path, []byte(wfp2Source), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	plain := Files([]string{path}, 1, dir, nil)
	withWFP2 := Files([]string{path}, 1, dir, nil, WithWFP2())

	if strings.Contains(string(plain.WFP), "wfp2=") {
		t.Errorf("no option, yet wfp2= appeared:\n%s", plain.WFP)
	}
	if !strings.Contains(string(withWFP2.WFP), "\nwfp2=\n") {
		t.Errorf("WithWFP2 did not add a wfp2= block:\n%s", withWFP2.WFP)
	}
}

// formatWFP2 renders a minutiae map as the WFP's "line=hex,..." lines, sorted by line.
func formatWFP2(m map[int][]uint32) string {
	var lines []string
	for _, k := range wfp2.SortedLines(m) {
		parts := make([]string, len(m[k]))
		for i, h := range m[k] {
			parts[i] = fmt.Sprintf("%08x", h)
		}
		lines = append(lines, strconv.Itoa(k)+"="+strings.Join(parts, ","))
	}
	return strings.Join(lines, "\n")
}
