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
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2/unstable"

	"github.com/scanoss/scanoss.go/pkg/dependencies/internal/pyscope"
)

// requirementRegex matches Python requirement lines
// Example: django>=4.2.0 or requests==2.28.0 or flask
var requirementRegex = regexp.MustCompile(`^(?P<name>[-\w]+)\s*(?P<sym>[>=~!]*)\s*(?P<version>[\d\.]*)`)

// ParseRequirementsTxt parses a requirements.txt file and extracts dependencies
func ParseRequirementsTxt(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	scanner := bufio.NewScanner(bytes.NewReader(fileContent))
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		// Skip empty lines
		if line == "" {
			continue
		}

		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Skip URLs
		if isValidURL(line) {
			continue
		}

		// Skip local file paths
		if isValidPath(line) {
			continue
		}

		// Skip recursive dependencies (-r requirements-dev.txt)
		if strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "--requirement") {
			continue
		}

		// Skip editable installs (-e .)
		if strings.HasPrefix(line, "-e") || strings.HasPrefix(line, "--editable") {
			continue
		}

		if lp, ok := pypiRequirement(line); ok {
			lp.Line = lineNo
			lp.DeclaredText = line
			result.Purls = append(result.Purls, lp)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// ParsePyprojectToml parses a pyproject.toml file and extracts the
// dependencies it declares: [project] dependencies, each extra in
// [project.optional-dependencies], each PEP 735 [dependency-groups] group, and
// Poetry's dependencies, dev-dependencies and groups. Scope is the TOML table
// the dependency is declared in, such as "project.optional-dependencies.dev",
// and Dev follows the rule in package pyscope. A malformed file is an error.
func ParsePyprojectToml(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	var p unstable.Parser
	p.Reset(fileContent)
	table := []string{}
	for p.NextExpression() {
		e := p.Expression()
		switch e.Kind {
		case unstable.Table:
			table = tomlKey(e.Key())
		case unstable.ArrayTable:
			table = nil // no dependency table is an array of tables
		case unstable.KeyValue:
			if table != nil {
				collectPyproject(&p, result, append(slices.Clone(table), tomlKey(e.Key())...), e)
			}
		}
	}
	if err := p.Error(); err != nil {
		return nil, err
	}
	return result, nil
}

// collectPyproject adds the dependencies value declares at the TOML key path,
// descending into inline tables such as optional-dependencies = {dev = [...]}.
func collectPyproject(p *unstable.Parser, result *LocalDependency, path []string, kv *unstable.Node) {
	value := kv.Value()
	add := func(lp LocalPurl, ok bool, scope string, dev bool, at *unstable.Node) {
		if !ok {
			return
		}
		lp.Scope = scope
		lp.Dev = dev
		lp.Line = p.Shape(at.Raw).Start.Line
		lp.DeclaredText = sourceLine(p.Data(), lp.Line)
		result.Purls = append(result.Purls, lp)
	}
	addAll := func(scope string, dev bool) {
		if value.Kind != unstable.Array {
			return
		}
		for it := value.Children(); it.Next(); {
			// A table such as {include-group = "test"} names another group,
			// which declares its dependencies itself.
			if n := it.Node(); n.Kind == unstable.String {
				lp, ok := pypiRequirement(string(n.Data))
				add(lp, ok, scope, dev, n)
			}
		}
	}
	addPoetry := func(name string, scope []string, dev bool) {
		lp, ok := poetryRequirement(name, value)
		add(lp, ok, strings.Join(scope, "."), dev, kv)
	}
	switch {
	case slices.Equal(path, []string{"project", "dependencies"}):
		addAll(strings.Join(path, "."), false)
	case len(path) == 3 && path[0] == "project" && path[1] == "optional-dependencies":
		addAll(strings.Join(path, "."), pyscope.DevExtra(path[2]))
	case len(path) == 2 && path[0] == "dependency-groups":
		addAll(strings.Join(path, "."), true)
	case len(path) == 4 && slices.Equal(path[:3], []string{"tool", "poetry", "dependencies"}):
		addPoetry(path[3], path[:3], false)
	case len(path) == 4 && slices.Equal(path[:3], []string{"tool", "poetry", "dev-dependencies"}):
		addPoetry(path[3], path[:3], true)
	case len(path) == 6 && slices.Equal(path[:3], []string{"tool", "poetry", "group"}) && path[4] == "dependencies":
		addPoetry(path[5], path[:5], pyscope.DevPoetryGroup(path[3]))
	case value.Kind == unstable.InlineTable:
		for it := value.Children(); it.Next(); {
			member := it.Node()
			collectPyproject(p, result, append(slices.Clone(path), tomlKey(member.Key())...), member)
		}
	}
}

// poetryRequirement reads a Poetry dependency, declared as name = "^1.2" or
// as a table with a version, into a purl, pinned when the version is exact.
// python is the interpreter, not a dependency.
func poetryRequirement(name string, value *unstable.Node) (LocalPurl, bool) {
	if strings.EqualFold(name, "python") {
		return LocalPurl{}, false
	}
	version := ""
	switch value.Kind {
	case unstable.String:
		version = string(value.Data)
	case unstable.InlineTable:
		for it := value.Children(); it.Next(); {
			field := it.Node()
			if slices.Equal(tomlKey(field.Key()), []string{"version"}) && field.Value().Kind == unstable.String {
				version = string(field.Value().Data)
			}
		}
	}
	version = strings.TrimSpace(version)
	if exact := strings.TrimPrefix(version, "=="); exact != "" && !strings.ContainsAny(exact, "<>=!~^*, |") {
		return LocalPurl{Purl: BuildPURL("pypi", "", name, exact, nil), Requirement: exact}, true
	}
	if version == "*" {
		version = ""
	}
	return LocalPurl{Purl: BuildPURL("pypi", "", name, "", nil), Requirement: version}, true
}

// pypiRequirement reads a requirement such as requests>=2.31 into a purl,
// pinned when the requirement is an exact version.
func pypiRequirement(spec string) (LocalPurl, bool) {
	m := requirementRegex.FindStringSubmatch(spec)
	if len(m) < 4 {
		return LocalPurl{}, false
	}
	name, symbol, version := m[1], m[2], m[3]
	switch {
	case symbol == "==" && version != "":
		return LocalPurl{Purl: BuildPURL("pypi", "", name, version, nil), Requirement: version}, true
	case symbol != "" && version != "":
		return LocalPurl{Purl: BuildPURL("pypi", "", name, "", nil), Requirement: symbol + version}, true
	default:
		return LocalPurl{Purl: BuildPURL("pypi", "", name, "", nil)}, true
	}
}

// tomlKey is the parts of a dotted TOML key.
func tomlKey(it unstable.Iterator) []string {
	var parts []string
	for it.Next() {
		parts = append(parts, string(it.Node().Data))
	}
	return parts
}

// sourceLine is the trimmed text of the 1-based line in data.
func sourceLine(data []byte, line int) string {
	for i, l := range bytes.Split(data, []byte("\n")) {
		if i+1 == line {
			return strings.TrimSpace(string(l))
		}
	}
	return ""
}

// ParsePython is the main entry point for parsing Python dependency files
func ParsePython(fileContent []byte, filePath string) (*LocalDependency, error) {
	filename := filepath.Base(filePath)

	switch filename {
	case "requirements.txt":
		return ParseRequirementsTxt(fileContent, filePath)
	case "pyproject.toml":
		return ParsePyprojectToml(fileContent, filePath)
	default:
		// Return empty result for unsupported files
		return &LocalDependency{
			File:  filePath,
			Purls: []LocalPurl{},
		}, nil
	}
}
