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

package wfp2

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Normalizex is the heart of the format: a change to a byte code or to the type-run /
// identifier / punctuation handling silently re-keys every fingerprint. These cases pin
// the behaviour the reference and the engine depend on.
func TestNormalizex(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []byte
	}{
		{
			// "int" is a type (0x00 starts the run), space drops, "x" is an identifier
			// (0xff), "=" is punctuation (213), then another type-run and identifier.
			name: "type identifier punctuation",
			in:   "int x = int y",
			want: []byte{0x00, 0xff, 213, 0x00, 0xff},
		},
		{
			// Each type keyword emits 0x00. The lastWasType guard only suppresses a repeat
			// for immediately-adjacent types; the spaces between these reset it, so three
			// types give three 0x00 (verified against the reference). What's dropped is the
			// identity of the type, not its count.
			name: "space-separated types each emit 0x00",
			in:   "unsigned long int x",
			want: []byte{0x00, 0x00, 0x00, 0xff},
		},
		{
			// A reserved word takes its element code; "return" is 146.
			name: "reserved word",
			in:   "return x",
			want: []byte{146, 0xff},
		},
		{
			// "true" is in both tables; elementsMap is consulted first, so its code (169)
			// wins over the type-run 0x00.
			name: "element beats type",
			in:   "true",
			want: []byte{169},
		},
		{
			// Characters with no element code (here, the space) are dropped entirely.
			name: "unmapped chars dropped",
			in:   "a b",
			want: []byte{0xff, 0xff},
		},
		{
			// Newlines are preserved between lines so winnowing can number them.
			name: "newline preserved",
			in:   "a\nb",
			want: []byte{0xff, '\n', 0xff},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := []byte(Normalizex(tc.in))
			if string(got) != string(tc.want) {
				t.Errorf("Normalizex(%q) = % x, want % x", tc.in, got, tc.want)
			}
		})
	}
}

// DetectLanguage must be deterministic on ties — the one behaviour that differs from the
// reference scanoss-go implementation. The fixed order is python, java, go, c, cpp,
// javascript, ruby, php, resolved by strict max (first wins). This mirrors the engine.
func TestDetectLanguageDeterministic(t *testing.T) {
	// Clear-majority inputs must pick the obvious language.
	clear := map[string]string{
		"def foo():\n    return None\n":    "python",
		"package main\nfunc main() {}\n":   "go",
		"public class A { void m() {} }\n": "java",
	}
	for src, want := range clear {
		if got := DetectLanguage(src); got != want {
			t.Errorf("DetectLanguage(%q) = %q, want %q", src, got, want)
		}
	}

	// Whatever a given input resolves to, it must resolve there every time: ranging a Go
	// map (as the reference does) would flip ties run to run.
	const tie = "class require def end import package func"
	first := DetectLanguage(tie)
	for i := 0; i < 200; i++ {
		if got := DetectLanguage(tie); got != first {
			t.Fatalf("DetectLanguage is not deterministic: run %d gave %q, first gave %q", i, got, first)
		}
	}

	// No keyword hit → no language (leaves the source un-stripped downstream).
	if got := DetectLanguage("1 2 3 + 4 5\n"); got != "" {
		t.Errorf("DetectLanguage(no keywords) = %q, want \"\"", got)
	}
}

// TestDetectLanguageTieOrder pins the tie-break to the engine's fixed order: on an equal
// score the lower-indexed language wins. The lone token "def" scores 1 for python (index
// 0) and 1 for ruby (index 6); python's lower index must decide it.
func TestDetectLanguageTieOrder(t *testing.T) {
	if languageOrder[0] != "python" {
		t.Fatalf("languageOrder[0] = %q, want python (the engine's first language)", languageOrder[0])
	}
	if got := DetectLanguage("def"); got != "python" {
		t.Errorf("DetectLanguage(%q) = %q, want python (lowest index on tie)", "def", got)
	}
}

// Minutiae runs the whole pipeline; these golden values were produced by the reference
// (scanoss-go pkg/fingerprint/wfp2, hash-len 8), which the engine port mirrors. A drift
// here means the client would stop matching the mined KB.
func TestMinutiaeGolden(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // sorted "line=hex,hex" lines joined by \n
	}{
		{
			name: "c",
			src: "int add(int a, int b) {\n" +
				"    int result = a + b;\n" +
				"    return result;\n" +
				"}\n" +
				"int mul(int a, int b) {\n" +
				"    int acc = 0;\n" +
				"    for (int i = 0; i < b; i++) {\n" +
				"        acc = acc + a;\n" +
				"    }\n" +
				"    return acc;\n" +
				"}\n",
			want: "9=33cd85f3",
		},
		{
			name: "python",
			src: "import sys\n" +
				"\n" +
				"# A simple accumulator class\n" +
				"class Accumulator:\n" +
				"    \"\"\"Holds a running total.\"\"\"\n" +
				"    def __init__(self):\n" +
				"        self.total = 0\n" +
				"\n" +
				"    def add(self, value):\n" +
				"        self.total += value\n" +
				"        return self.total\n" +
				"\n" +
				"def main():\n" +
				"    acc = Accumulator()\n" +
				"    for i in range(10):\n" +
				"        acc.add(i * i)\n" +
				"    print(\"sum of squares:\", acc.total)\n" +
				"\n" +
				"if __name__ == \"__main__\":\n" +
				"    main()\n",
			want: "16=9fb18eb0\n19=d97a8f6d,2dc8c9ec",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatMinutiae(Minutiae([]byte(tc.src))); got != tc.want {
				t.Errorf("Minutiae mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// Minutiae must be stable across runs: the CLI saves and re-scans WFPs, so the same bytes
// in must give the same bytes out every time.
func TestMinutiaeDeterministic(t *testing.T) {
	src := []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n" +
		strings.Repeat("var x = someValue + otherValue\n", 40))
	first := formatMinutiae(Minutiae(src))
	for i := 0; i < 50; i++ {
		if got := formatMinutiae(Minutiae(src)); got != first {
			t.Fatalf("Minutiae not deterministic at run %d", i)
		}
	}
}

// RemoveCommentsFromSource preserves the line count so fingerprint line numbers stay
// aligned with the source, and leaves an unknown language untouched.
func TestRemoveCommentsFromSource(t *testing.T) {
	src := "int a; // trailing\n/* block */\nint b;\n"
	got := RemoveCommentsFromSource(src, "c")
	if lines := strings.Count(got, "\n"); lines != strings.Count(src, "\n") {
		t.Errorf("line count changed: got %d, want %d", lines, strings.Count(src, "\n"))
	}
	if strings.Contains(got, "trailing") || strings.Contains(got, "block") {
		t.Errorf("comment text survived: %q", got)
	}
	// Unknown language: returned unchanged.
	if out := RemoveCommentsFromSource(src, "cobol"); out != src {
		t.Errorf("unknown language should be unchanged, got %q", out)
	}
}

// formatMinutiae renders a minutiae map the way the WFP does: sorted lines, each
// "line=hex,hex,...", joined by newlines.
func formatMinutiae(m map[int][]uint32) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var lines []string
	for _, k := range keys {
		parts := make([]string, len(m[k]))
		for i, h := range m[k] {
			parts[i] = fmt.Sprintf("%08x", h)
		}
		lines = append(lines, fmt.Sprintf("%d=%s", k, strings.Join(parts, ",")))
	}
	return strings.Join(lines, "\n")
}
