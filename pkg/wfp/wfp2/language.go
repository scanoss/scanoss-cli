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

import "strings"

// languageKeywords scores a source language by how many of its marker tokens appear.
// The lists are byte-identical to the reference miner (scanoss-go utils.DetectLanguage)
// and the engine port (src/wfp2.c kw_* tables): they decide the comment style, and the
// comment style decides every downstream minutia.
var languageKeywords = map[string][]string{
	"python":     {"def", "import", "self", "print", "None", "True", "False", "elif", "except"},
	"java":       {"public", "static", "void", "class", "implements", "extends", "null", "package"},
	"go":         {"func", "package", "import", "defer", "chan", "go", "select", "map", "range"},
	"c":          {"#include", "printf", "scanf", "malloc", "free", "NULL", "int", "char"},
	"cpp":        {"#include", "cout", "cin", "std", "new", "delete", "namespace", "class"},
	"javascript": {"function", "var", "let", "const", "console", "undefined", "require", "export"},
	"ruby":       {"def", "end", "puts", "require", "class", "module", "elsif", "unless"},
	"php":        {"<?php", "echo", "var", "function", "$", "require", "include"},
}

// languageOrder is the fixed detection order, deciding tie-breaks deterministically:
// the first (lowest-index) language holding the maximum score wins. It must match the
// engine port's langs[] order (src/wfp2.c: python, java, go, c, cpp, javascript, ruby,
// php) exactly.
//
// This is the one deliberate deviation from the reference scanoss-go DetectLanguage,
// which ranges a Go map and so resolves ties at random (scanoss/go-minr#227): two runs,
// or the client and the engine, could pick different languages for the same tie-file and
// strip its comments differently, yielding different fingerprints. A CLI must be
// reproducible, and the client must agree with the engine, so the client commits to the
// engine's order. It changes nothing for files with a clear majority language — only
// genuine ties, and only when the tied languages have different comment styles. The mined
// KB stays noisy on such files until the miner adopts the same rule and is re-mined.
var languageOrder = []string{"python", "java", "go", "c", "cpp", "javascript", "ruby", "php"}

// DetectLanguage returns the best-scoring language's key, or "" when nothing matches
// (which leaves the source uncommented-stripped — see RemoveCommentsFromSource). Scoring
// counts every (token, keyword) hit where the token equals or is prefixed by the keyword,
// exactly as the reference does.
func DetectLanguage(content string) string {
	scores := make(map[string]int)
	tokens := strings.Fields(content)

	for _, lang := range languageOrder {
		keywords := languageKeywords[lang]
		for _, token := range tokens {
			for _, keyword := range keywords {
				if token == keyword || strings.HasPrefix(token, keyword) {
					scores[lang]++
				}
			}
		}
	}

	bestLang := ""
	maxScore := 0
	// Strict ">" over the fixed order: the first language to reach the max keeps it, so a
	// tie resolves to the lowest-index language — deterministically, and the same way the
	// engine resolves it.
	for _, lang := range languageOrder {
		if scores[lang] > maxScore {
			bestLang = lang
			maxScore = scores[lang]
		}
	}

	return bestLang
}

// commentPattern is a language's comment syntax: line-comment prefixes and the paired
// delimiters of a block comment.
type commentPattern struct {
	line     []string // line-comment prefixes
	multiBeg []string // block-comment openers
	multiEnd []string // block-comment closers (paired by index with multiBeg)
}

var commentPatterns = map[string]commentPattern{
	"python": {
		line:     []string{"#"},
		multiBeg: []string{"'''", `"""`},
		multiEnd: []string{"'''", `"""`},
	},
	"java": {
		line:     []string{"//"},
		multiBeg: []string{"/*"},
		multiEnd: []string{"*/"},
	},
	"go": {
		line:     []string{"//"},
		multiBeg: []string{"/*"},
		multiEnd: []string{"*/"},
	},
	"c": {
		line:     []string{"//"},
		multiBeg: []string{"/*"},
		multiEnd: []string{"*/"},
	},
	"cpp": {
		line:     []string{"//"},
		multiBeg: []string{"/*"},
		multiEnd: []string{"*/"},
	},
	"javascript": {
		line:     []string{"//"},
		multiBeg: []string{"/*"},
		multiEnd: []string{"*/"},
	},
	"ruby": {
		line:     []string{"#"},
		multiBeg: []string{"=begin"},
		multiEnd: []string{"=end"},
	},
	"php": {
		line:     []string{"//", "#"},
		multiBeg: []string{"/*"},
		multiEnd: []string{"*/"},
	},
}

// RemoveCommentsFromSource strips comments from code for the given language, preserving
// the line count: a line that becomes empty is kept as an empty line, so line numbers in
// the fingerprint still line up with the source. An unknown language returns the code
// unchanged. The algorithm is a line-by-line port of the reference and must track its
// trimming exactly.
func RemoveCommentsFromSource(code string, lang string) string {
	pattern, ok := commentPatterns[lang]
	if !ok {
		return code // no pattern: return unchanged
	}

	lines := strings.Split(code, "\n")
	var result []string
	inMultiComment := false
	multiEnd := ""

	for _, line := range lines {
		if inMultiComment {
			if multiEnd != "" && strings.Contains(line, multiEnd) {
				inMultiComment = false
				idx := strings.Index(line, multiEnd)
				afterComment := strings.TrimSpace(line[idx+len(multiEnd):])
				if afterComment != "" {
					result = append(result, afterComment)
				} else {
					// Line holding only the end of the block comment.
					result = append(result, "")
				}
			} else {
				// Line wholly inside a block comment: preserved as an empty line.
				result = append(result, "")
			}
			continue
		}

		// Does a block comment open on this line?
		foundMultiComment := false
		for i := 0; i < len(pattern.multiBeg); i++ {
			beg := pattern.multiBeg[i]
			end := pattern.multiEnd[i]
			if strings.Contains(line, beg) {
				begIdx := strings.Index(line, beg)
				before := strings.TrimRight(line[:begIdx], " \t")

				// Does it also close on the same line? Search AFTER the opener.
				searchStart := begIdx + len(beg)
				if strings.Contains(line[searchStart:], end) {
					endIdx := strings.Index(line[searchStart:], end)
					after := line[searchStart+endIdx+len(end):]

					// Join the code before and after the comment.
					combined := before
					if strings.TrimSpace(after) != "" {
						if combined != "" {
							combined += " " + strings.TrimLeft(after, " \t")
						} else {
							combined = strings.TrimLeft(after, " \t")
						}
					}

					if strings.TrimSpace(combined) != "" {
						result = append(result, combined)
					} else {
						result = append(result, "")
					}
					foundMultiComment = true
					break
				} else {
					// The block comment runs on into the following lines.
					inMultiComment = true
					multiEnd = end
					if strings.TrimSpace(before) != "" {
						// Code precedes the opener on this line.
						result = append(result, before)
					} else {
						// Line holds only the opener.
						result = append(result, "")
					}
					foundMultiComment = true
					break
				}
			}
		}
		if foundMultiComment {
			continue
		}

		// Strip line comments.
		clean := line
		for _, prefix := range pattern.line {
			if idx := strings.Index(clean, prefix); idx != -1 {
				clean = strings.TrimRight(clean[:idx], " \t")
				break
			}
		}

		if strings.TrimSpace(clean) != "" {
			// Line with code (comment stripped or none).
			result = append(result, clean)
		} else {
			// Line that was only a comment: preserved as an empty line.
			result = append(result, "")
		}
	}

	return strings.Join(result, "\n")
}
