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
	// dependenciesBlockRegex matches dependencies { ... } blocks
	dependenciesBlockRegex = regexp.MustCompile(`dependencies\s*\{`)

	// compactDepRegex matches compact dependency declarations
	// Example: implementation 'org.scala-lang:scala-library:2.11.12'
	compactDepRegex = regexp.MustCompile(`^\s*(\w+)\s+['"]([^:'"]+):([^:'"]+):([^:'"]+)['"]`)

	// extendedGroupRegex matches group: 'value'
	extendedGroupRegex = regexp.MustCompile(`group:\s*['"]([^'"]+)['"]`)

	// extendedNameRegex matches name: 'value'
	extendedNameRegex = regexp.MustCompile(`name:\s*['"]([^'"]+)['"]`)

	// extendedVersionRegex matches version: 'value'
	extendedVersionRegex = regexp.MustCompile(`version:\s*['"]([^'"]+)['"]`)

	// configRegex extracts configuration name from dependency line
	configRegex = regexp.MustCompile(`^\s*(\w+)\s+`)
)

// ParseBuildGradle parses a build.gradle file and extracts dependencies
func ParseBuildGradle(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(fileContent))
	inDependenciesBlock := false
	braceCount := 0

	var currentScope string
	var multiLineBuffer strings.Builder
	inMultiLine := false
	blockStartLine := 0
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		originalLine := raw

		// Remove inline comments
		line := trimComments(raw, "//")
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Check for dependencies block start
		if dependenciesBlockRegex.MatchString(line) {
			inDependenciesBlock = true
			braceCount = 1
			continue
		}

		if inDependenciesBlock {
			// Count braces to track block nesting
			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			// Check if we've exited the dependencies block
			if braceCount <= 0 {
				inDependenciesBlock = false
				continue
			}

			// Handle multi-line dependencies
			if strings.Contains(line, "(") && !strings.Contains(line, ")") {
				inMultiLine = true
				blockStartLine = lineNo
				multiLineBuffer.WriteString(line)
				multiLineBuffer.WriteString(" ")
				continue
			}

			if inMultiLine {
				multiLineBuffer.WriteString(line)
				multiLineBuffer.WriteString(" ")
				if strings.Contains(line, ")") {
					line = multiLineBuffer.String()
					multiLineBuffer.Reset()
					inMultiLine = false
				} else {
					continue
				}
			}

			// Try to parse compact format first
			if matches := compactDepRegex.FindStringSubmatch(line); len(matches) >= 5 {
				scope := matches[1]
				groupID := matches[2]
				artifactID := matches[3]
				version := matches[4]

				purl := BuildPURL("maven", groupID, artifactID, version, nil)

				result.Purls = append(result.Purls, LocalPurl{
					Purl:         purl,
					Requirement:  version,
					Scope:        scope,
					Dev:          gradleTestConfiguration(scope),
					Line:         lineNo,
					DeclaredText: strings.TrimSpace(originalLine),
				})
				continue
			}

			// Try to parse extended format
			// Extended format can span multiple physical lines or be on one line
			if configMatches := configRegex.FindStringSubmatch(originalLine); len(configMatches) >= 2 {
				currentScope = configMatches[1]
			}

			// Look for group, name, version in the line
			groupMatches := extendedGroupRegex.FindStringSubmatch(line)
			nameMatches := extendedNameRegex.FindStringSubmatch(line)
			versionMatches := extendedVersionRegex.FindStringSubmatch(line)

			if len(groupMatches) >= 2 && len(nameMatches) >= 2 && len(versionMatches) >= 2 {
				groupID := groupMatches[1]
				artifactID := nameMatches[1]
				version := versionMatches[1]

				purl := BuildPURL("maven", groupID, artifactID, version, nil)

				// For multi-line blocks, use blockStartLine; for single-line extended, use lineNo.
				depLine := lineNo
				if blockStartLine > 0 {
					depLine = blockStartLine
					blockStartLine = 0
				}

				result.Purls = append(result.Purls, LocalPurl{
					Purl:         purl,
					Requirement:  version,
					Scope:        currentScope,
					Dev:          gradleTestConfiguration(currentScope),
					Line:         depLine,
					DeclaredText: strings.TrimSpace(line),
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// ParseGradle is the main entry point for parsing Gradle dependency files
func ParseGradle(fileContent []byte, filePath string) (*LocalDependency, error) {
	filename := filepath.Base(filePath)

	if filename == "build.gradle" {
		return ParseBuildGradle(fileContent, filePath)
	}

	// Return empty result for unsupported files
	return &LocalDependency{
		File:  filePath,
		Purls: []LocalPurl{},
	}, nil
}

// gradleTestConfiguration reports whether a dependency configuration only
// builds or runs tests, such as testImplementation or androidTestImplementation.
func gradleTestConfiguration(configuration string) bool {
	return strings.HasPrefix(configuration, "test") || strings.Contains(configuration, "Test")
}
