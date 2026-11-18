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
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/wfp/wfp2"
)

// WFP1 algorithm parameters: the n-gram length hashed per window, and the number of
// hashes a window spans. They define the fingerprint format, so changing either makes
// the output incomparable with every WFP the server already holds.
const (
	gramWFP1   = 30
	windowWFP1 = 64
)

// CRC tables are built once at package init (they were previously rebuilt on
// every generateFingerprint call).
var (
	crc64ECMA       = crc64.MakeTable(crc64.ECMA)
	crc32Castagnoli = crc32.MakeTable(0x82f63b78)
)

const hexDigits = "0123456789abcdef"

// appendHex8 appends v as 8 lowercase, zero-padded hex digits — byte-identical to
// fmt "%0.8x" for a uint32, without the per-emission allocation of fmt.Sprintf.
func appendHex8(dst []byte, v uint32) []byte {
	return append(dst,
		hexDigits[(v>>28)&0xf], hexDigits[(v>>24)&0xf],
		hexDigits[(v>>20)&0xf], hexDigits[(v>>16)&0xf],
		hexDigits[(v>>12)&0xf], hexDigits[(v>>8)&0xf],
		hexDigits[(v>>4)&0xf], hexDigits[v&0xf])
}

// normalize normalizes a byte according to winnowing rules
func normalize(b byte) byte {
	if b < '0' {
		return 0
	}
	if b > 'z' {
		return 0
	}
	if b <= '9' {
		return b
	}
	if b >= 'a' {
		return b
	}
	if (b >= 'A') && (b <= 'Z') {
		return b + 32
	}
	return 0
}

// minHash finds the minimum hash in a slice
func minHash(hashes []uint32) uint32 {
	indexMin := 0
	for r := range hashes {
		if hashes[r] <= hashes[indexMin] {
			indexMin = r
		}
	}
	return hashes[indexMin]
}

// generateFingerprint generates the WFP fingerprint of a file. The file is read from
// filePath; root, when non-empty, makes the WFP "file=" label relative to it (so the
// scan result reports paths relative to the scanned folder, not absolute local paths).
func generateFingerprint(filePath string, root string, opts options) (*FileFingerprint, error) {
	// No filtering here: which files are worth fingerprinting is decided once,
	// during collection (pkg/filter), which is the only stage that reports what
	// it skipped. Deciding again at this depth would drop files the caller has
	// already counted as collected.
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	// The "file=" line uses the path relative to the scan root when one is given.
	label := filePath
	if root != "" {
		if rel, relErr := filepath.Rel(root, filePath); relErr == nil {
			label = filepath.ToSlash(rel)
		}
	}

	// Whole-file hash: CRC64 (ECMA), 16 hex digits. It covers the whole file even when the
	// header lines below are dropped from the snippet minutiae: the file= line states what was
	// read, not what was fingerprinted.
	hashHex := fmt.Sprintf("%016x", crc64.Checksum(f, crc64ECMA))

	// How many leading lines are preamble rather than code. The filter is on unless the caller
	// passed WithoutSkipHeaders, and it drops nothing from a file whose language it does not know.
	headerLines := 0
	if !opts.keepHeaders {
		headerLines = headerOffset(filePath, string(f), opts.skipHeadersLimit)
	}

	// Assemble the WFP into a builder. This was previously a `result += ...` string
	// concat, which is O(n²) in the output size on large files.
	var sb strings.Builder
	sb.Grow(len(f)/8 + 64)
	fmt.Fprintf(&sb, "file=%s,%d,%s\n", hashHex, len(f), label)

	// Generate winnowing fingerprint
	lines := 1
	var window []byte
	var hashes []uint32
	var last uint32
	var minBuf [4]byte // reused per minutia; stays on the stack (no per-emission alloc)
	wfp := make(map[int][]uint32)

	for i := 0; i < len(f); i++ {
		if f[i] == '\n' {
			lines++
		}
		newByte := normalize(f[i])
		if newByte == 0 {
			continue
		}

		window = append(window, newByte)
		if len(window) >= gramWFP1 {
			hashes = append(hashes, crc32.Checksum(window, crc32Castagnoli))
			if len(hashes) >= windowWFP1 {
				a := minHash(hashes)
				if a != last {
					last = a
					binary.LittleEndian.PutUint32(minBuf[:], a)
					wfp[lines] = append(wfp[lines], crc32.Checksum(minBuf[:], crc32Castagnoli))
				}
				hashes = hashes[1:windowWFP1]
			}
			window = window[1:gramWFP1]
		}
	}

	// Build final result: sorted line numbers, each with its comma-joined hex minutiae.
	keys := make([]int, 0, len(wfp))
	for k := range wfp {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	hexBuf := make([]byte, 0, 8)
	startLineWritten := false
	for _, k := range keys {
		// Minutiae from the header lines are dropped, and the first surviving line is preceded
		// by a start_line marker naming the offset — the shape scanoss.py emits, so a WFP from
		// either client reads the same.
		if k <= headerLines {
			continue
		}
		if headerLines > 0 && !startLineWritten {
			sb.WriteString("start_line=")
			sb.WriteString(strconv.Itoa(headerLines))
			sb.WriteByte('\n')
			startLineWritten = true
		}
		sb.WriteString(strconv.Itoa(k))
		sb.WriteByte('=')
		v := wfp[k]
		for w := 0; w < len(v); w++ {
			hexBuf = appendHex8(hexBuf[:0], v[w])
			sb.Write(hexBuf)
			if w < len(v)-1 {
				sb.WriteByte(',')
			} else {
				sb.WriteByte('\n')
			}
		}
	}

	// The token-aware wfp2 block, when asked for: the same file= line serves it, so it is
	// simply appended after the wfp1 minutiae, introduced by a "wfp2=" marker line. Off by
	// default — without it, nothing below runs and the WFP is unchanged.
	if opts.wfp2 {
		appendWFP2Block(&sb, f, hexBuf)
	}

	return &FileFingerprint{
		Path:        label,
		Hash:        hashHex,
		Size:        len(f),
		Fingerprint: sb.String(),
	}, nil
}

// appendWFP2Block appends the token-aware wfp2 minutiae of src to sb, preceded by the
// "wfp2=" marker line the engine and API split on. hexBuf is a scratch buffer reused for
// hex formatting (its contents are discarded). The minutiae use the same "line=hex,..."
// format as the wfp1 block, sorted by line, with no header-line skipping — wfp2 has no
// notion of it, and the miner the KB was built with applied none.
//
// Nothing is written when there are no minutiae (a very short or non-source file), so the
// WFP never carries an empty "wfp2=" marker.
func appendWFP2Block(sb *strings.Builder, src []byte, hexBuf []byte) {
	minutiae := wfp2.Minutiae(src)
	if len(minutiae) == 0 {
		return
	}
	sb.WriteString("wfp2=\n")
	for _, k := range wfp2.SortedLines(minutiae) {
		sb.WriteString(strconv.Itoa(k))
		sb.WriteByte('=')
		v := minutiae[k]
		for w := 0; w < len(v); w++ {
			hexBuf = appendHex8(hexBuf[:0], v[w])
			sb.Write(hexBuf)
			if w < len(v)-1 {
				sb.WriteByte(',')
			} else {
				sb.WriteByte('\n')
			}
		}
	}
}
