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

// Package parsers provides functionality to parse dependency manifests
// from various package management systems and extract dependency information
// as standardized Package URLs (PURLs).
package parsers

// LocalPurl represents a single package URL with optional version requirement and scope.
// It follows the Package URL specification (https://github.com/package-url/purl-spec)
type LocalPurl struct {
	// Purl is the Package URL identifier (e.g., "pkg:npm/react@18.0.0")
	Purl string `json:"purl"`

	// Requirement is the optional version specifier (e.g., ">=1.0.0", "~1.2.3")
	Requirement string `json:"requirement,omitempty"`

	// Scope is the optional dependency scope (e.g., "dependencies", "devDependencies", "test")
	Scope string `json:"scope,omitempty"`

	// Dev is true when the manifest declares the dependency only to develop the
	// project (tests, linting, documentation, build tooling): devDependencies in
	// package.json, Maven's test scope, Gradle test configurations, and the
	// pyproject.toml groups and extras package pyscope names.
	Dev bool `json:"dev,omitempty"`

	// Line is the 1-based line number of the dependency declaration in the manifest file.
	// Zero means the location could not be determined.
	Line int `json:"line,omitempty"`

	// DeclaredText is the trimmed raw declaration text from the manifest.
	// Empty when the location could not be determined.
	DeclaredText string `json:"declaredText,omitempty"`
}

// FileType represents the type of dependency file
type FileType string

const (
	// FileTypeManifest indicates a manifest file with declared dependencies (package.json, go.mod, requirements.txt, etc.)
	FileTypeManifest FileType = "manifest"

	// FileTypeLockfile indicates a lockfile with resolved dependencies (package-lock.json, go.sum, yarn.lock, etc.)
	FileTypeLockfile FileType = "lockfile"
)

// LocalDependency represents the dependencies extracted from a single manifest file.
type LocalDependency struct {
	// File is the path to the manifest file that was parsed
	File string `json:"file"`

	// FileType indicates whether this is a manifest or lockfile
	FileType FileType `json:"fileType,omitempty"`

	// Purls is the list of package URLs extracted from the file
	Purls []LocalPurl `json:"purls"`
}

// LocalDependencies represents a collection of dependencies from multiple files.
type LocalDependencies struct {
	// Files contains the dependency information for each parsed file
	Files []LocalDependency `json:"files"`
}

// ParserFunc defines the function signature for dependency parsers.
// Each parser takes file content and path, and returns the parsed dependencies.
type ParserFunc func(fileContent []byte, filePath string) (*LocalDependency, error)
