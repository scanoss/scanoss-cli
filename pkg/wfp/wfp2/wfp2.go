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

// Package wfp2 generates WFP2 (token-aware) fingerprint minutiae: a language-aware
// winnowing that detects the source language, strips comments and normalizes the source
// to a byte stream (identifiers, type-runs, reserved words and punctuation each mapped to
// fixed codes) before winnowing it. Cosmetic edits — renamed identifiers, reformatting,
// changed comments — leave the fingerprint unchanged, which is what lets wfp2 match
// snippets wfp1 would miss.
//
// This is a faithful port of the reference implementation (scanoss-go
// pkg/fingerprint/wfp2), which the engine mirrors byte-for-byte in C (engine src/wfp2.c)
// and which the mined KB was generated with. The output MUST stay byte-identical to both,
// so the algorithm here — the normalization tables, GRAM/WINDOW, the CRC32C winnowing and
// the little-endian min-hash re-hash — is reproduced verbatim and must not be "improved".
// The sole deliberate departure is a deterministic language tie-break; see DetectLanguage.
package wfp2

import (
	"encoding/binary"
	"hash/crc32"
	"sort"
	"strings"
)

// GRAM and WINDOW are the wfp2 winnowing parameters: the n-gram length hashed and the
// number of gram-hashes a window spans. They differ from wfp1's and, like wfp1's, are
// part of the on-the-wire format — changing either makes the output incomparable with the
// mined KB.
const (
	gramWFP2   = 20
	windowWFP2 = 40
)

// maxLines caps the line number winnowing will record; the reference stops accumulating
// once a source reaches this many normalized lines.
const maxLines = 0xffff

// crc32Castagnoli is the CRC-32C (Castagnoli, polynomial 0x82f63b78) table, built once.
// wfp2 uses it both for each gram-hash and for the final per-minutia hash — the same
// polynomial the engine's winnowing uses.
var crc32Castagnoli = crc32.MakeTable(crc32.Castagnoli)

// isAsciiAlnum reports whether r is an ASCII identifier character ([a-z0-9_], and the
// upper-case range before Normalizex lower-cases). Non-identifier bytes are handled as
// single-character punctuation tokens.
func isAsciiAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '_'
}

// minHash returns the minimum hash in a window, selecting the RIGHTMOST minimum on ties
// (the comparison is "<="). This matches the reference and the engine's min_hash; picking
// the leftmost would change which minutiae survive.
func minHash(hashes []uint32) uint32 {
	indexMin := 0
	for r := range hashes {
		if hashes[r] <= hashes[indexMin] {
			indexMin = r
		}
	}
	return hashes[indexMin]
}

// Normalizex maps source text to the wfp2 normalized byte stream, line by line:
//   - a reserved word or a single punctuation char → its elementsMap byte,
//   - a type keyword → 0x00 (its identity is dropped; the lastWasType guard suppresses a
//     repeated 0x00 only for an immediately-adjacent type, which separators prevent),
//   - any other identifier → 0xff,
//   - characters not in elementsMap (whitespace and the like) → dropped,
//   - newlines preserved between lines (so winnowing can number lines).
//
// elementsMap is consulted before typesMap, so a token that is both takes its element
// code. Input is lower-cased first, exactly as the reference does.
func Normalizex(input string) string {
	var result strings.Builder
	input = strings.ToLower(input)
	lines := strings.Split(input, "\n")

	for i, line := range lines {
		runes := []rune(line)
		j := 0
		lastWasType := false
		for j < len(runes) {
			r := runes[j]

			if isAsciiAlnum(r) {
				// Consume a full identifier token.
				start := j
				for j < len(runes) && isAsciiAlnum(runes[j]) {
					j++
				}
				word := string(runes[start:j])
				if index, exist := elementsMap[word]; exist { // reserved word?
					result.WriteByte(index)
					lastWasType = false
				} else if _, exist := typesMap[word]; exist { // type keyword?
					if !lastWasType {
						result.WriteByte(0x00) // one 0x00 per run of consecutive types
					}
					lastWasType = true
				} else { // any other identifier
					result.WriteByte(0xff)
					lastWasType = false
				}
			} else {
				// Single non-identifier character: emit its code if it has one, else drop.
				charStr := string(r)
				if index, exist := elementsMap[charStr]; exist {
					result.WriteByte(index)
				}
				lastWasType = false
				j++
			}
		}
		if i < len(lines)-1 {
			result.WriteByte('\n')
		}
	}

	return result.String()
}

// Minutiae computes the wfp2 minutiae of a source file: a map from line number to the
// CRC32C minutiae recorded on that line. It runs the full pipeline — DetectLanguage →
// RemoveCommentsFromSource → Normalizex → winnowing — then, per window, hashes the
// little-endian bytes of the window's minimum gram-hash and records it when it differs
// from the previous one (consecutive duplicates are dropped).
//
// The returned map matches the reference's line→hashes map exactly; callers format it as
// the "N=hash,hash,..." minutiae lines of the WFP (see pkg/wfp).
func Minutiae(src []byte) map[int][]uint32 {
	lang := DetectLanguage(string(src))
	noComments := RemoveCommentsFromSource(string(src), lang)
	norm := Normalizex(noComments)

	wfp := make(map[int][]uint32)
	var window []byte
	var hashes []uint32
	var last uint32
	var minBuf [4]byte // reused per minutia; stays on the stack (no per-emission alloc)
	lines := 1

	for i := 0; i < len(norm); i++ {
		c := norm[i]
		if c == '\n' {
			lines++
			if lines >= maxLines {
				break
			}
			continue
		}

		window = append(window, c)
		if len(window) >= gramWFP2 {
			hashes = append(hashes, crc32.Checksum(window, crc32Castagnoli))
			if len(hashes) >= windowWFP2 {
				a := minHash(hashes)
				if a != last {
					last = a
					binary.LittleEndian.PutUint32(minBuf[:], a)
					wfp[lines] = append(wfp[lines], crc32.Checksum(minBuf[:], crc32Castagnoli))
				}
				hashes = hashes[1:windowWFP2]
			}
			window = window[1:gramWFP2]
		}
	}

	return wfp
}

// SortedLines returns the line numbers of a minutiae map in ascending order — the order
// the minutiae must be emitted in.
func SortedLines(m map[int][]uint32) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
