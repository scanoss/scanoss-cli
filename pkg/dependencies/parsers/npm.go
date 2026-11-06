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
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// yarnLockEntryRegex matches yarn.lock dependency entries
	// Example: package@^1.0.0:
	yarnLockEntryRegex = regexp.MustCompile(`^([@\w\-\.\/]+)@([^:]+):`)

	// yarnVersionRegex matches version line in yarn.lock
	// Example:   version "1.0.0"
	yarnVersionRegex = regexp.MustCompile(`^\s+version\s+"([^"]+)"`)
)

// PackageJSON represents the structure of package.json
type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// packageLockV1 represents the structure of package-lock.json v1
type packageLockV1 struct {
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

// packageLockV2 represents the structure of package-lock.json v2+
type packageLockV2 struct {
	Packages map[string]packageLockPackage `json:"packages"`
}

// packageLockDependency represents a dependency in package-lock.json v1
type packageLockDependency struct {
	Version      string                           `json:"version"`
	Dependencies map[string]packageLockDependency `json:"dependencies"`
}

// packageLockPackage represents a package in package-lock.json v2+
type packageLockPackage struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

// jsonDepsObjectEntry holds a key name, its offset in the source, and its string value.
type jsonDepsObjectEntry struct {
	name  string
	off   int
	value string
}

// jsonReadDepsObject walks a JSON object (the decoder is positioned just after its opening '{')
// and returns each key-value pair with the byte offset of the key's opening '"'.
// It handles nested objects by skipping them.
func jsonReadDepsObject(dec *json.Decoder, fileContent []byte) ([]jsonDepsObjectEntry, error) {
	var entries []jsonDepsObjectEntry
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		// End of object
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			break
		}
		key, ok := tok.(string)
		if !ok {
			// Skip unexpected token types
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		// After reading the key token, InputOffset() is just past its closing '"'.
		// The key's opening '"' is at: inputOffset - len(key) - 2  (key bytes + 2 quotes).
		// ASCII-only assumption: npm package names are ASCII with no JSON escape sequences,
		// so decoded len(key) == raw JSON byte length. This arithmetic would be incorrect for
		// keys containing JSON escapes (e.g. \uXXXX) — do not reuse blindly for other JSON formats.
		keyOff := int(dec.InputOffset()) - len(key) - 2

		// Read the value
		valTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch v := valTok.(type) {
		case string:
			entries = append(entries, jsonDepsObjectEntry{name: key, off: keyOff, value: v})
		case json.Delim:
			// Nested object or array — skip it.
			if err := skipJSONObject(dec); err != nil {
				return nil, err
			}
		default:
			// Other value types (bool, number, nil) — ignore
		}
	}
	return entries, nil
}

// skipJSONValue skips a single JSON value at the current decoder position.
// It handles objects and arrays by consuming tokens until the matching close.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{', '[':
			return skipJSONObject(dec)
		}
	}
	return nil
}

// skipJSONObject skips all remaining tokens in the current object/array
// (called after the opening '{' or '[' has already been consumed).
func skipJSONObject(dec *json.Decoder) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// ParsePackageJSON parses a package.json file using a json.Decoder token walk
// to capture the source line and declared text of each dependency key.
func ParsePackageJSON(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	dec := json.NewDecoder(bytes.NewReader(fileContent))

	// Read the opening '{'
	if _, err := dec.Token(); err != nil {
		return nil, err
	}

	for dec.More() {
		offBefore := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}

		var scope string
		switch key {
		case "dependencies":
			scope = "dependencies"
		case "devDependencies":
			scope = "devDependencies"
		default:
			_ = offBefore
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}

		// Read the opening '{' of the deps object
		if _, err := dec.Token(); err != nil {
			return nil, err
		}

		entries, err := jsonReadDepsObject(dec, fileContent)
		if err != nil {
			return nil, err
		}

		for _, e := range entries {
			namespace, pkgName := GetScopedPackage(e.name)
			purl := BuildPURL("npm", namespace, pkgName, e.value, nil)
			result.Purls = append(result.Purls, LocalPurl{
				Purl:         purl,
				Requirement:  e.value,
				Scope:        scope,
				Dev:          scope == "devDependencies",
				Line:         offsetToLine(fileContent, e.off),
				DeclaredText: lineTextAt(fileContent, e.off),
			})
		}
	}

	return result, nil
}

// ParsePackageLock parses a package-lock.json file using json.Decoder token walks
// to capture source locations for each dependency key.
func ParsePackageLock(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	// Detect format by looking for "packages" or "dependencies" top-level key.
	// Use json.Unmarshal to detect format, then use token walk for extraction.
	var probe struct {
		HasPackages bool `json:"-"`
		PackagesLen int  `json:"-"`
	}
	var v2check packageLockV2
	if err := json.Unmarshal(fileContent, &v2check); err == nil && len(v2check.Packages) > 0 {
		probe.HasPackages = true
	}

	if probe.HasPackages {
		return parsePackageLockV2TokenWalk(fileContent, result)
	}
	return parsePackageLockV1TokenWalk(fileContent, result)
}

// parsePackageLockV2TokenWalk walks a v2 package-lock.json using json.Decoder
// to capture the source line of each "packages" entry key.
func parsePackageLockV2TokenWalk(fileContent []byte, result *LocalDependency) (*LocalDependency, error) {
	// We still need the version and dev fields from v2 — use Unmarshal for those.
	var lock packageLockV2
	if err := json.Unmarshal(fileContent, &lock); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(fileContent))
	// Read the opening '{' of the root object
	if _, err := dec.Token(); err != nil {
		return nil, err
	}

	// Walk to find the "packages" key and record offsets for each path key.
	pathOffsets := make(map[string]int)
	for dec.More() {
		offBefore := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		if key != "packages" {
			_ = offBefore
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		// Found "packages" — read its opening '{'
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		// Walk each path key
		for dec.More() {
			pkgTok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			pkgKey, ok := pkgTok.(string)
			if !ok {
				if err := skipJSONValue(dec); err != nil {
					return nil, err
				}
				continue
			}
			// After reading the key, InputOffset is just past its closing '"'.
			pkgKeyOff := int(dec.InputOffset()) - len(pkgKey) - 2
			pathOffsets[pkgKey] = pkgKeyOff
			// Skip the package object value
			if _, err := dec.Token(); err != nil { // opening '{'
				return nil, err
			}
			if err := skipJSONObject(dec); err != nil {
				return nil, err
			}
		}
		break
	}

	for path, pkg := range lock.Packages {
		if path == "" {
			continue
		}
		name := strings.TrimPrefix(path, "node_modules/")
		if strings.Count(name, "node_modules") > 0 {
			continue
		}
		namespace, pkgName := GetScopedPackage(name)
		purl := BuildPURL("npm", namespace, pkgName, pkg.Version, nil)
		scope := "dependencies"
		if pkg.Dev {
			scope = "devDependencies"
		}
		var line int
		var declText string
		if off, ok := pathOffsets[path]; ok {
			line = offsetToLine(fileContent, off)
			declText = lineTextAt(fileContent, off)
		}
		result.Purls = append(result.Purls, LocalPurl{
			Purl:         purl,
			Requirement:  pkg.Version,
			Scope:        scope,
			Dev:          pkg.Dev,
			Line:         line,
			DeclaredText: declText,
		})
	}

	return result, nil
}

// parsePackageLockV1TokenWalk walks a v1 package-lock.json using json.Decoder
// to capture the source line of each "dependencies" entry key (recursive).
func parsePackageLockV1TokenWalk(fileContent []byte, result *LocalDependency) (*LocalDependency, error) {
	var lock packageLockV1
	if err := json.Unmarshal(fileContent, &lock); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(fileContent))
	// Read the opening '{' of the root object
	if _, err := dec.Token(); err != nil {
		return nil, err
	}

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		if key != "dependencies" {
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		// Found "dependencies" — read its opening '{'
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		if err := collectV1DepsWithOffsets(dec, fileContent, lock.Dependencies, result); err != nil {
			return nil, err
		}
		break
	}

	return result, nil
}

// collectV1DepsWithOffsets walks a v1 "dependencies" object and emits LocalPurls with
// source offsets. It recurses into nested "dependencies" objects.
func collectV1DepsWithOffsets(
	dec *json.Decoder,
	fileContent []byte,
	deps map[string]packageLockDependency,
	result *LocalDependency,
) error {
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := tok.(string)
		if !ok {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
			continue
		}
		// After reading the key, InputOffset is just past its closing '"'.
		nameOff := int(dec.InputOffset()) - len(name) - 2

		dep, exists := deps[name]
		// Read opening '{' of this dependency object
		if _, err := dec.Token(); err != nil {
			return err
		}
		// Emit the dep if we have its data
		if exists {
			namespace, pkgName := GetScopedPackage(name)
			purl := BuildPURL("npm", namespace, pkgName, dep.Version, nil)
			result.Purls = append(result.Purls, LocalPurl{
				Purl:         purl,
				Requirement:  dep.Version,
				Line:         offsetToLine(fileContent, nameOff),
				DeclaredText: lineTextAt(fileContent, nameOff),
			})
		}
		// Walk the fields of this dep object to find nested "dependencies"
		for dec.More() {
			fieldTok, err := dec.Token()
			if err != nil {
				return err
			}
			fieldKey, ok := fieldTok.(string)
			if !ok {
				if err := skipJSONValue(dec); err != nil {
					return err
				}
				continue
			}
			if fieldKey == "dependencies" && exists && len(dep.Dependencies) > 0 {
				// Read opening '{' of nested deps
				if _, err := dec.Token(); err != nil {
					return err
				}
				if err := collectV1DepsWithOffsets(dec, fileContent, dep.Dependencies, result); err != nil {
					return err
				}
			} else {
				if err := skipJSONValue(dec); err != nil {
					return err
				}
			}
		}
		// Read closing '}' of this dep object
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	// Read closing '}' of the dependencies object
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// ParseYarnLock parses a yarn.lock file and extracts dependencies
func ParseYarnLock(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(fileContent))
	seen := make(map[string]bool)
	lineNo := 0

	var currentPackage string
	var currentVersion string
	var currentPackageLine int
	var currentPackageRaw string

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := raw

		// Check for yarn v2 marker
		if strings.Contains(line, "__metadata:") {
			// This is a yarn v2+ file, which has a different format
			// For now, we'll skip yarn v2 parsing as it's more complex
			continue
		}

		// Match package entry (e.g., "package@^1.0.0:")
		if matches := yarnLockEntryRegex.FindStringSubmatch(line); len(matches) >= 2 {
			currentPackage = matches[1]
			currentPackageLine = lineNo
			currentPackageRaw = strings.TrimSpace(raw)
			continue
		}

		// Match version line
		if currentPackage != "" {
			if matches := yarnVersionRegex.FindStringSubmatch(line); len(matches) >= 2 {
				currentVersion = matches[1]

				// Create unique key
				key := currentPackage + "@" + currentVersion
				if !seen[key] {
					seen[key] = true

					namespace, pkgName := GetScopedPackage(currentPackage)
					purl := BuildPURL("npm", namespace, pkgName, currentVersion, nil)

					result.Purls = append(result.Purls, LocalPurl{
						Purl:         purl,
						Requirement:  currentVersion,
						Line:         currentPackageLine,
						DeclaredText: currentPackageRaw,
					})
				}

				currentPackage = ""
				currentPackageLine = 0
				currentPackageRaw = ""
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// ParseNPM is the main entry point for parsing Node.js dependency files
func ParseNPM(fileContent []byte, filePath string) (*LocalDependency, error) {
	filename := filepath.Base(filePath)

	switch filename {
	case "package.json":
		return ParsePackageJSON(fileContent, filePath)
	case "package-lock.json":
		return ParsePackageLock(fileContent, filePath)
	case "yarn.lock":
		return ParseYarnLock(fileContent, filePath)
	default:
		// Return empty result for unsupported files
		return &LocalDependency{
			File:  filePath,
			Purls: []LocalPurl{},
		}, nil
	}
}
