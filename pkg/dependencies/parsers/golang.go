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

package parsers

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// goModRequireRegex matches lines in go.mod require blocks
	// Example: github.com/spf13/cobra v1.10.2
	goModRequireRegex = regexp.MustCompile(`^\s*([^\s]+)\s+([^\s]+)`)

	// goSumLineRegex matches lines in go.sum
	// Example: github.com/spf13/cobra v1.10.2 h1:xyz...
	goSumLineRegex = regexp.MustCompile(`^([^\s]+)\s+([^\s]+)(?:\s+h1:)?`)
)

// ParseGoMod parses a go.mod file and extracts dependencies
func ParseGoMod(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(fileContent))
	inRequireBlock := false
	lineNo := 0
	var goDirective, toolchainDirective directive

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := preprocessLine(raw)

		if line == "" {
			continue
		}

		if v, ok := strings.CutPrefix(line, "go "); ok && !inRequireBlock {
			goDirective = directive{strings.TrimSpace(v), lineNo, strings.TrimSpace(raw)}
			continue
		}
		if v, ok := strings.CutPrefix(line, "toolchain "); ok && !inRequireBlock {
			toolchainDirective = directive{strings.TrimSpace(v), lineNo, strings.TrimSpace(raw)}
			continue
		}

		// Check for require block start
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		// Check for require block end
		if inRequireBlock && strings.HasPrefix(line, ")") {
			inRequireBlock = false
			continue
		}

		// Parse single-line require or lines within require block
		if strings.HasPrefix(line, "require ") || inRequireBlock {
			// Remove "require " prefix if present
			line = strings.TrimPrefix(line, "require ")
			line = strings.TrimSpace(line)

			// Skip if it's the opening parenthesis
			if line == "(" {
				continue
			}

			matches := goModRequireRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				pkgPath := matches[1]
				version := matches[2]

				// Skip indirect dependencies if desired (they have // indirect comment)
				// For now, we include all dependencies

				namespace, name := splitNamespace(pkgPath)
				purl := BuildPURL("golang", namespace, name, version, nil)

				result.Purls = append(result.Purls, LocalPurl{
					Purl:         purl,
					Requirement:  version,
					Line:         lineNo,
					DeclaredText: strings.TrimSpace(raw),
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if v := GoStdVersion(goDirective.value, toolchainDirective.value); v != "" {
		d := goDirective
		if toolchainDirective.value != "" {
			d = toolchainDirective
		}
		result.Purls = append(result.Purls, LocalPurl{
			Purl:         BuildPURL("golang", "", GoStdName, v, nil),
			Requirement:  v,
			Line:         d.line,
			DeclaredText: d.text,
		})
	}

	return result, nil
}

// GoStdName is the module name of the Go standard library: pkg:golang/stdlib@go1.26.11.
// It is the name the Go vulnerability database files standard library advisories
// under, and the one Syft and Grype use; Grype matches nothing on cyclonedx-gomod's
// "std".
const GoStdName = "stdlib"

// directive is a go.mod directive's value and where it was declared.
type directive struct {
	value string
	line  int
	text  string
}

// GoStdVersion returns the version of the standard library a module is built
// with, from its go.mod directives: the toolchain directive ("go1.26.11") when
// there is one, since that is the toolchain the go command switches to, else the
// go directive ("1.26.11" becomes "go1.26.11"). It returns "" when neither is set.
//
// A go directive without a patch release ("1.26") is kept as it is: it is the
// oldest release the module allows, and a scanner reads it as the first one.
func GoStdVersion(goDirective, toolchainDirective string) string {
	if v := strings.TrimSpace(toolchainDirective); v != "" && v != "default" {
		if !strings.HasPrefix(v, "go") {
			v = "go" + v
		}
		return v
	}
	if v := strings.TrimSpace(goDirective); v != "" {
		return "go" + v
	}
	return ""
}

// ParseGoSum parses a go.sum file and extracts dependencies
func ParseGoSum(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(fileContent))
	seen := make(map[string]bool) // To avoid duplicates
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		if line == "" {
			continue
		}

		matches := goSumLineRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			pkgPath := matches[1]
			version := matches[2]

			// Remove /go.mod suffix from version if present
			// go.sum files have two entries per dependency:
			// - one for the module: github.com/foo/bar v1.0.0 h1:...
			// - one for go.mod: github.com/foo/bar v1.0.0/go.mod h1:...
			version = strings.TrimSuffix(version, "/go.mod")

			// Create a unique key to avoid duplicates
			key := pkgPath + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true

			namespace, name := splitNamespace(pkgPath)
			purl := BuildPURL("golang", namespace, name, version, nil)

			result.Purls = append(result.Purls, LocalPurl{
				Purl:         purl,
				Requirement:  version,
				Line:         lineNo,
				DeclaredText: strings.TrimSpace(raw),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// ParseGolang is the main entry point for parsing Go dependency files
func ParseGolang(fileContent []byte, filePath string) (*LocalDependency, error) {
	filename := filepath.Base(filePath)

	switch filename {
	case "go.mod":
		return ParseGoMod(fileContent, filePath)
	case "go.sum":
		return ParseGoSum(fileContent, filePath)
	default:
		// Return empty result for unsupported files
		return &LocalDependency{
			File:  filePath,
			Purls: []LocalPurl{},
		}, nil
	}
}
