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

package dependencies

import (
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
)

func TestNewDependencyParser(t *testing.T) {
	parser := NewDependencyParser()

	if parser == nil {
		t.Fatal("NewDependencyParser returned nil")
	}

	if len(parser.parserMap) == 0 {
		t.Error("Parser map is empty")
	}
}

func TestGetParserFunc(t *testing.T) {
	parser := NewDependencyParser()

	tests := []struct {
		name     string
		filePath string
		wantOk   bool
	}{
		{"Go mod file", "/path/to/go.mod", true},
		{"Python requirements", "/path/to/requirements.txt", true},
		{"Package JSON", "/path/to/package.json", true},
		{"Maven POM", "/path/to/pom.xml", true},
		{"Gradle build", "/path/to/build.gradle", true},
		{"Gemfile", "/path/to/Gemfile", true},
		{"Csproj wildcard", "/path/to/MyApp.csproj", true},
		{"Unsupported file", "/path/to/random.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parser.GetParserFunc(tt.filePath)
			if ok != tt.wantOk {
				t.Errorf("GetParserFunc() = %v, want %v", ok, tt.wantOk)
			}
		})
	}
}

func TestFilterFiles(t *testing.T) {
	parser := NewDependencyParser()

	files := []string{
		"/project/go.mod",
		"/project/requirements.txt",
		"/project/README.md",
		"/project/package.json",
		"/project/src/main.go",
	}

	filtered := parser.FilterFiles(files)

	expected := 3 // go.mod, requirements.txt, package.json
	if len(filtered) != expected {
		t.Errorf("FilterFiles returned %d files, expected %d", len(filtered), expected)
	}
}

func TestParseGoMod(t *testing.T) {
	content := []byte(`module github.com/example/project

go 1.22

require (
	github.com/spf13/cobra v1.10.2
	github.com/schollz/progressbar/v3 v3.18.0
)
`)

	result, err := parsers.ParseGoMod(content, "go.mod")
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	// The two requirements and the standard library (go 1.22).
	if len(result.Purls) != 3 {
		t.Errorf("Expected 3 dependencies, got %d", len(result.Purls))
	}

	// Check first dependency
	if result.Purls[0].Purl != "pkg:golang/github.com/spf13/cobra@v1.10.2" {
		t.Errorf("Unexpected PURL: %s", result.Purls[0].Purl)
	}
}

func TestFileType(t *testing.T) {
	tests := []struct {
		filename     string
		expectedType parsers.FileType
	}{
		// Manifests (declared dependencies)
		{"package.json", parsers.FileTypeManifest},
		{"go.mod", parsers.FileTypeManifest},
		{"requirements.txt", parsers.FileTypeManifest},
		{"pyproject.toml", parsers.FileTypeManifest},
		{"pom.xml", parsers.FileTypeManifest},
		{"build.gradle", parsers.FileTypeManifest},
		{"Gemfile", parsers.FileTypeManifest},
		{"my-app.csproj", parsers.FileTypeManifest},
		{"packages.config", parsers.FileTypeManifest},

		// Lockfiles (resolved dependencies)
		{"package-lock.json", parsers.FileTypeLockfile},
		{"yarn.lock", parsers.FileTypeLockfile},
		{"go.sum", parsers.FileTypeLockfile},
		{"Gemfile.lock", parsers.FileTypeLockfile},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := parsers.GetFileType(tt.filename)
			if got != tt.expectedType {
				t.Errorf("GetFileType(%s) = %v, want %v", tt.filename, got, tt.expectedType)
			}
		})
	}
}

func TestParseGoSum(t *testing.T) {
	// Test that go.sum parser correctly handles /go.mod suffix
	// go.sum files have two entries per dependency:
	// - one for the module hash
	// - one for the go.mod hash (with /go.mod suffix in version)
	content := []byte(`github.com/spf13/cobra v1.10.2 h1:DMTTonx5m65Ic0GOoRY2c16WCbHxOOw6xxezuLaBpcU=
github.com/spf13/cobra v1.10.2/go.mod h1:7C1pvHqHw5A4vrJfjNwvOdzYu0Gml16OCs2GRiTUUS4=
github.com/spf13/pflag v1.0.10 h1:oU+lLv1ULm5taqgV/CJivypVODI4SUz1znWjv3nNYS0=
github.com/spf13/pflag v1.0.10/go.mod h1:SmD6nW6nTyfqj6ABTjUi3V3JVMnlJmwcJI5acqYI6dE=
`)

	result, err := parsers.ParseGoSum(content, "go.sum")
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	// Should have 2 unique dependencies (duplicates with /go.mod suffix are deduplicated)
	if len(result.Purls) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(result.Purls))
	}

	// Check that PURLs don't contain /go.mod suffix
	for _, purl := range result.Purls {
		if strings.Contains(purl.Purl, "/go.mod") {
			t.Errorf("PURL should not contain /go.mod suffix: %s", purl.Purl)
		}
		if strings.Contains(purl.Requirement, "/go.mod") {
			t.Errorf("Requirement should not contain /go.mod suffix: %s", purl.Requirement)
		}
	}

	// Check first dependency
	if result.Purls[0].Purl != "pkg:golang/github.com/spf13/cobra@v1.10.2" {
		t.Errorf("Unexpected PURL: %s", result.Purls[0].Purl)
	}
	if result.Purls[0].Requirement != "v1.10.2" {
		t.Errorf("Unexpected requirement: %s", result.Purls[0].Requirement)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	content := []byte(`# Comment
django==4.2.0
requests>=2.28.0
flask

# Another comment
-r requirements-dev.txt
`)

	result, err := parsers.ParseRequirementsTxt(content, "requirements.txt")
	if err != nil {
		t.Fatalf("ParseRequirementsTxt failed: %v", err)
	}

	if len(result.Purls) != 3 {
		t.Errorf("Expected 3 dependencies, got %d", len(result.Purls))
	}

	// Check django (exact version)
	if result.Purls[0].Purl != "pkg:pypi/django@4.2.0" {
		t.Errorf("Unexpected PURL: %s", result.Purls[0].Purl)
	}

	// Check requests (version requirement)
	if result.Purls[1].Requirement != ">=2.28.0" {
		t.Errorf("Unexpected requirement: %s", result.Purls[1].Requirement)
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := []byte(`{
  "dependencies": {
    "react": "^18.0.0",
    "@angular/core": "15.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}`)

	result, err := parsers.ParsePackageJSON(content, "package.json")
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if len(result.Purls) != 3 {
		t.Errorf("Expected 3 dependencies, got %d", len(result.Purls))
	}

	// Check that scoped package is parsed correctly
	foundAngular := false
	for _, purl := range result.Purls {
		if purl.Purl == "pkg:npm/@angular/core@15.0.0" {
			foundAngular = true
			if purl.Scope != "dependencies" {
				t.Errorf("Expected scope 'dependencies', got '%s'", purl.Scope)
			}
		}
	}

	if !foundAngular {
		t.Error("Scoped package @angular/core not found")
	}
}

func TestParsePomXML(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.0</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>`)

	result, err := parsers.ParsePomXML(content, "pom.xml")
	if err != nil {
		t.Fatalf("ParsePomXML failed: %v", err)
	}

	if len(result.Purls) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(result.Purls))
	}

	// Check junit scope
	foundJUnit := false
	for _, purl := range result.Purls {
		if purl.Purl == "pkg:maven/junit/junit@4.13.2" {
			foundJUnit = true
			if purl.Scope != "test" {
				t.Errorf("Expected scope 'test', got '%s'", purl.Scope)
			}
		}
	}

	if !foundJUnit {
		t.Error("JUnit dependency not found")
	}
}

func TestParseBuildGradle(t *testing.T) {
	content := []byte(`
dependencies {
    implementation 'org.scala-lang:scala-library:2.11.12'
    testImplementation 'junit:junit:4.13.2'
}
`)

	result, err := parsers.ParseBuildGradle(content, "build.gradle")
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(result.Purls) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(result.Purls))
	}

	// Check first dependency
	if result.Purls[0].Purl != "pkg:maven/org.scala-lang/scala-library@2.11.12" {
		t.Errorf("Unexpected PURL: %s", result.Purls[0].Purl)
	}

	// Check scope
	if result.Purls[0].Scope != "implementation" {
		t.Errorf("Expected scope 'implementation', got '%s'", result.Purls[0].Scope)
	}
}

func TestParseGemfileLock(t *testing.T) {
	content := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.0)
    rake (13.0.6)

DEPENDENCIES
  rails
  rake
`)

	result, err := parsers.ParseGemfileLock(content, "Gemfile.lock")
	if err != nil {
		t.Fatalf("ParseGemfileLock failed: %v", err)
	}

	if len(result.Purls) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(result.Purls))
	}

	// Check rails version
	if result.Purls[0].Purl != "pkg:gem/rails@7.0.0" {
		t.Errorf("Unexpected PURL: %s", result.Purls[0].Purl)
	}
}

func TestParseCsproj(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Serilog" Version="2.12.0" />
  </ItemGroup>
</Project>`)

	result, err := parsers.ParseCsproj(content, "MyApp.csproj")
	if err != nil {
		t.Fatalf("ParseCsproj failed: %v", err)
	}

	if len(result.Purls) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(result.Purls))
	}

	// Check Newtonsoft.Json
	if result.Purls[0].Purl != "pkg:nuget/Newtonsoft.Json@13.0.1" {
		t.Errorf("Unexpected PURL: %s", result.Purls[0].Purl)
	}
}

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		name       string
		purlType   string
		namespace  string
		pkgName    string
		version    string
		qualifiers map[string]string
		want       string
	}{
		{
			name:      "Simple package",
			purlType:  "npm",
			namespace: "",
			pkgName:   "react",
			version:   "18.0.0",
			want:      "pkg:npm/react@18.0.0",
		},
		{
			name:      "Scoped package",
			purlType:  "npm",
			namespace: "@angular",
			pkgName:   "core",
			version:   "15.0.0",
			want:      "pkg:npm/@angular/core@15.0.0",
		},
		{
			name:       "Package with qualifiers",
			purlType:   "maven",
			namespace:  "org.example",
			pkgName:    "library",
			version:    "1.0.0",
			qualifiers: map[string]string{"type": "jar"},
			want:       "pkg:maven/org.example/library@1.0.0?type=jar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsers.BuildPURL(tt.purlType, tt.namespace, tt.pkgName, tt.version, tt.qualifiers)
			if got != tt.want {
				t.Errorf("BuildPURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
