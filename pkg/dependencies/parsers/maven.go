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
	"bytes"
	"encoding/xml"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// propertyRegex matches Maven property references ${property.name}
	propertyRegex = regexp.MustCompile(`\$\{([^}]+)\}`)
)

// pomDependency represents a single dependency
type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Classifier string `xml:"classifier"`
	Type       string `xml:"type"`
}

// pomProperties represents the properties section
type pomProperties struct {
	Properties map[string]string
}

// UnmarshalXML custom unmarshaler for properties
func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Properties = make(map[string]string)

	for {
		token, err := d.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &t); err != nil {
				return err
			}
			p.Properties[t.Name.Local] = value
		case xml.EndElement:
			if t == start.End() {
				return nil
			}
		}
	}

	return nil
}

// pomCollectedDep holds a decoded pomDependency together with its source location.
type pomCollectedDep struct {
	dep      pomDependency
	startOff int
	endOff   int
}

// ParsePomXML parses a pom.xml file using a single xml.Decoder streaming pass.
// It collects project-level <dependencies> children (skipping <dependencyManagement>
// and plugin/build <dependency> elements), gathers <properties>, then resolves
// versions after the pass (collect-then-resolve).
func ParsePomXML(fileContent []byte, filePath string) (*LocalDependency, error) {
	result := &LocalDependency{
		File:     filePath,
		FileType: GetFileType(filepath.Base(filePath)),
		Purls:    []LocalPurl{},
	}

	d := xml.NewDecoder(bytes.NewReader(fileContent))

	// Parent-context tracking: we need to know which element contains the current
	// <dependency> to scope only project-level <dependencies> children.
	//
	// State machine — context element names on a stack:
	//   project > dependencies           → project-level deps (COLLECT)
	//   project > dependencyManagement   → skip
	//   project > build > ...            → skip
	//   project > properties             → collect properties
	//
	// We track a simplified 3-level context: project, section (dependencies|
	// dependencyManagement|build|properties), and whether we are in a project-level
	// dependencies section.

	type contextLevel int
	const (
		ctxRoot contextLevel = iota
		ctxProject
		ctxProjectDeps  // project > dependencies
		ctxProjectMgmt  // project > dependencyManagement (or its nested deps)
		ctxProjectBuild // project > build (or plugins, etc.)
		ctxProjectProperties
		ctxOther
	)

	// depth tracks nesting depth within each context level
	type frame struct {
		name  string
		level contextLevel
	}

	stack := []frame{}
	currentCtx := ctxRoot

	var collectedDeps []pomCollectedDep
	var properties pomProperties
	var projectGroupID, projectArtifactID, projectVersion string
	var propertiesCollected bool

	for {
		prevOff := int(d.InputOffset())
		tok, err := d.Token()
		if err != nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local

			switch currentCtx {
			case ctxRoot:
				if name == "project" {
					currentCtx = ctxProject
					stack = append(stack, frame{name: name, level: ctxProject})
				} else {
					stack = append(stack, frame{name: name, level: ctxOther})
				}

			case ctxProject:
				switch name {
				case "dependencies":
					currentCtx = ctxProjectDeps
					stack = append(stack, frame{name: name, level: ctxProjectDeps})
				case "dependencyManagement":
					currentCtx = ctxProjectMgmt
					stack = append(stack, frame{name: name, level: ctxProjectMgmt})
				case "build":
					currentCtx = ctxProjectBuild
					stack = append(stack, frame{name: name, level: ctxProjectBuild})
				case "properties":
					currentCtx = ctxProjectProperties
					stack = append(stack, frame{name: name, level: ctxProjectProperties})
					if !propertiesCollected {
						if err := d.DecodeElement(&properties, &t); err != nil {
							return nil, err
						}
						propertiesCollected = true
						// DecodeElement consumed the </properties>, so pop the frame
						if len(stack) > 0 {
							stack = stack[:len(stack)-1]
						}
						// Restore context to project
						currentCtx = ctxProject
					}
				case "groupId":
					var v string
					if err := d.DecodeElement(&v, &t); err == nil {
						projectGroupID = v
					}
				case "artifactId":
					var v string
					if err := d.DecodeElement(&v, &t); err == nil {
						projectArtifactID = v
					}
				case "version":
					var v string
					if err := d.DecodeElement(&v, &t); err == nil {
						projectVersion = v
					}
				default:
					stack = append(stack, frame{name: name, level: ctxProject})
				}

			case ctxProjectDeps:
				if name == "dependency" {
					// Collect this project-level dependency with its location
					var dep pomDependency
					if err := d.DecodeElement(&dep, &t); err != nil {
						return nil, err
					}
					endOff := int(d.InputOffset())
					collectedDeps = append(collectedDeps, pomCollectedDep{
						dep:      dep,
						startOff: prevOff,
						endOff:   endOff,
					})
					// DecodeElement consumed through </dependency> — no stack push needed
				} else {
					stack = append(stack, frame{name: name, level: ctxProjectDeps})
				}

			case ctxProjectMgmt, ctxProjectBuild, ctxOther:
				// Skip everything inside these contexts
				stack = append(stack, frame{name: name, level: currentCtx})

			case ctxProjectProperties:
				// Should not reach here since DecodeElement handles it
				stack = append(stack, frame{name: name, level: ctxProjectProperties})
			}

		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			// Restore context to parent
			if len(stack) == 0 {
				currentCtx = ctxRoot
			} else {
				currentCtx = stack[len(stack)-1].level
			}
			_ = top
		}
	}

	// Build properties map for version resolution
	props := make(map[string]string)
	if properties.Properties != nil {
		for k, v := range properties.Properties {
			props[k] = v
		}
	}
	props["project.version"] = projectVersion
	props["project.groupId"] = projectGroupID
	props["project.artifactId"] = projectArtifactID

	// Dedup map
	seen := make(map[string]bool)

	// Resolve versions and build PURLs over the collected deps
	for _, cd := range collectedDeps {
		dep := cd.dep
		groupID := dep.GroupID
		artifactID := dep.ArtifactID
		version := resolveVersion(dep.Version, props, string(fileContent))

		if version == "" || strings.HasPrefix(version, "${") {
			version = "unknown"
		}

		qualifiers := make(map[string]string)
		if dep.Type != "" && dep.Type != "jar" {
			qualifiers["type"] = dep.Type
		}
		if dep.Classifier != "" {
			qualifiers["classifier"] = dep.Classifier
		}

		purl := BuildPURL("maven", groupID, artifactID, version, qualifiers)

		if !seen[purl] {
			seen[purl] = true

			scope := dep.Scope
			if scope == "" {
				scope = "compile"
			}

			result.Purls = append(result.Purls, LocalPurl{
				Purl:         purl,
				Requirement:  version,
				Scope:        scope,
				Dev:          scope == "test",
				Line:         offsetToLine(fileContent, cd.startOff),
				DeclaredText: strings.TrimSpace(string(fileContent[cd.startOff:cd.endOff])),
			})
		}
	}

	return result, nil
}

// resolveVersion resolves Maven property variables in version strings
func resolveVersion(version string, properties map[string]string, fileContent string) string {
	if version == "" {
		return ""
	}

	// If it doesn't contain a property reference, return as-is
	if !strings.Contains(version, "${") {
		return version
	}

	// Try to resolve from properties map first
	matches := propertyRegex.FindStringSubmatch(version)
	if len(matches) >= 2 {
		propName := matches[1]
		if val, ok := properties[propName]; ok {
			return val
		}

		// Try to find the property in the file content
		propRegex := regexp.MustCompile(`<` + propName + `>([^<]+)</` + propName + `>`)
		if propMatches := propRegex.FindStringSubmatch(fileContent); len(propMatches) >= 2 {
			return propMatches[1]
		}
	}

	return version
}

// ParseMaven is the main entry point for parsing Maven dependency files
func ParseMaven(fileContent []byte, filePath string) (*LocalDependency, error) {
	filename := filepath.Base(filePath)

	if filename == "pom.xml" {
		return ParsePomXML(fileContent, filePath)
	}

	// Return empty result for unsupported files
	return &LocalDependency{
		File:  filePath,
		Purls: []LocalPurl{},
	}, nil
}
