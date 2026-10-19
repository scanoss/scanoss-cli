# Dependencies Parser Package

This package provides comprehensive dependency parsing functionality for multiple package management ecosystems. It extracts dependency information from manifest files and converts them into standardized Package URLs (PURLs) following the [Package URL specification](https://github.com/package-url/purl-spec).

## Supported Ecosystems

| Ecosystem | Files Supported | Features |
|-----------|----------------|----------|
| **Node.js** | `package.json`, `package-lock.json`, `yarn.lock` | Multi-version lock files, scoped packages, dev dependencies |
| **Python** | `requirements.txt`, `pyproject.toml` | Version operators, URL/path filtering |
| **Java (Maven)** | `pom.xml` | Property resolution, qualifiers, scopes |
| **Java (Gradle)** | `build.gradle` | Compact & extended formats, configuration scopes |
| **Go** | `go.mod`, `go.sum` | Direct & transitive dependencies |
| **Ruby** | `Gemfile`, `Gemfile.lock` | State machine parsing, platform specs |
| **.NET** | `*.csproj`, `packages.config` | Modern & legacy formats |

## Installation

```bash
go get github.com/scanoss/scanoss.go/pkg/dependencies
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/scanoss/scanoss.go/pkg/dependencies"
)

func main() {
    // Create a new dependency parser
    parser := dependencies.NewDependencyParser()

    // Parse a single file
    result, err := parser.ParseFile("path/to/go.mod")
    if err != nil {
        panic(err)
    }

    // Print dependencies
    for _, purl := range result.Purls {
        fmt.Printf("PURL: %s\n", purl.Purl)
        if purl.Requirement != "" {
            fmt.Printf("  Requirement: %s\n", purl.Requirement)
        }
        if purl.Scope != "" {
            fmt.Printf("  Scope: %s\n", purl.Scope)
        }
    }
}
```

### Parsing Multiple Files

```go
parser := dependencies.NewDependencyParser()

files := []string{
    "path/to/package.json",
    "path/to/go.mod",
    "path/to/pom.xml",
}

// Parsing is best-effort: a file that fails is skipped and its error returned in
// failed, keyed by path. The rest still parse, so failed is not a reason to stop —
// compare len(failed) against len(files) to tell "every manifest failed" from
// "the manifests declared nothing".
results, failed := parser.ParseFiles(files)
for path, err := range failed {
    log.Printf("could not parse %s: %v", path, err)
}

for _, fileDep := range results.Files {
    fmt.Printf("\nFile: %s\n", fileDep.File)
    fmt.Printf("Dependencies: %d\n", len(fileDep.Purls))
}
```

### Filtering Supported Files

```go
parser := dependencies.NewDependencyParser()

allFiles := []string{
    "README.md",
    "package.json",
    "go.mod",
    "main.go",
    "pom.xml",
}

// Filter only files that have a parser
supportedFiles := parser.FilterFiles(allFiles)
// Returns: ["package.json", "go.mod", "pom.xml"]
```

### Checking File Support

```go
parser := dependencies.NewDependencyParser()

if parser.IsSupportedFile("package.json") {
    fmt.Println("This file is supported!")
}

// Get list of all supported file patterns
patterns := parser.SupportedFiles()
for _, pattern := range patterns {
    fmt.Println(pattern)
}
```

## Data Structures

### LocalPurl

Represents a single package URL with metadata:

```go
type LocalPurl struct {
    Purl        string  // Package URL (e.g., "pkg:npm/react@18.0.0")
    Requirement string  // Version requirement (e.g., ">=1.0.0")
    Scope       string  // Dependency scope (e.g., "devDependencies")
}
```

### LocalDependency

Represents dependencies from a single file:

```go
type LocalDependency struct {
    File  string      // File path
    Purls []LocalPurl // List of package URLs
}
```

### LocalDependencies

Collection of dependencies from multiple files:

```go
type LocalDependencies struct {
    Files []LocalDependency
}
```

## Package URL (PURL) Format

All parsers generate standardized Package URLs:

```
pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
```

### Examples by Ecosystem

**Node.js:**
```
pkg:npm/react@18.0.0
pkg:npm/@angular/core@15.0.0
```

**Python:**
```
pkg:pypi/django@4.2.0
pkg:pypi/requests
```

**Java (Maven):**
```
pkg:maven/org.springframework/spring-core@5.3.0
pkg:maven/junit/junit@4.13.2?type=jar
```

**Go:**
```
pkg:golang/github.com/spf13/cobra@v1.10.2
```

**Ruby:**
```
pkg:gem/rails@7.0.0
```

**.NET:**
```
pkg:nuget/Newtonsoft.Json@13.0.1
```

## Parser-Specific Features

### Node.js Parser

- **package.json**: Separates dependencies and devDependencies
- **package-lock.json**: Handles both v1 (nested) and v2+ (flat) formats
- **yarn.lock**: Parses v1 format (v2 detection included)
- Supports scoped packages (`@angular/core`)

### Python Parser

- **requirements.txt**:
  - Filters out URLs, paths, and recursive dependencies
  - Handles operators: `==`, `>=`, `~`, `!=`, etc.
  - Exact versions (`==`) included in PURL, others in `Requirement`
- **pyproject.toml**: Parses dependencies from `[tool.poetry.dependencies]` section

### Maven Parser

- **pom.xml**:
  - Resolves property variables (`${project.version}`)
  - Extracts qualifiers (type, classifier)
  - Captures scopes (compile, test, etc.)
  - Deduplicates dependencies

### Gradle Parser

- **build.gradle**:
  - Supports compact format: `implementation 'group:artifact:version'`
  - Supports extended format with group/name/version keys
  - Handles multi-line declarations
  - Removes inline comments

### Go Parser

- **go.mod**: Parses `require` blocks (single-line and multi-line)
- **go.sum**: Extracts all dependencies with checksums
- Automatically splits namespace/name from import paths

### Ruby Parser

- **Gemfile**: Extracts gem names (no versions)
- **Gemfile.lock**:
  - State machine parsing (GEM, PATH, GIT sections)
  - Extracts versions and platform specs
  - Skips PATH dependencies (local gems)

### NuGet Parser

- **\*.csproj**: Parses modern PackageReference elements
- **packages.config**: Parses legacy package elements
- Both extract package ID and version

## Dependency Graphs

The parsers above return a flat list of PURLs per file. To know which package
pulled in which, use `resolve/lockfile`, which builds a `resolve.Graph` from a
lockfile without running any package manager:

```go
g, err := lockfile.ParseFS(os.DirFS(projectDir), "web/package-lock.json", lockfile.DefaultLimits())
if err != nil {
    return err // lockfile unreadable, or lockfile.ErrUnsupported
}
for _, root := range g.Roots {
    fmt.Println(root.Manifest, root.Status, root.Reason) // web/package.json complete
    for _, m := range root.Members {
        fmt.Println(m.ID, m.Direct) // pkg:npm/express@4.19.2 true
    }
}
```

- **Nodes** are `purl@version`, shared by every root.
- **Local nodes** (`Node.Local`) are the project's own packages, such as a
  workspace another workspace depends on. They keep their edges, so a root
  that depends on a sibling workspace reaches that workspace's dependencies.
  A local node may have no version. Skip local nodes to list only third-party
  packages.
- **Roots** are manifests: the project and, where the lockfile records them,
  each workspace. A root lists its members and its node-to-node edges.
  `Member.Direct` marks the packages the manifest declares.
- **Status** is `complete`, `partial` (usable but missing something) or
  `unknown` (no members), with a `Reason` such as `manifest_missing` or
  `malformed`.

Lockfiles are treated as untrusted: `Limits` caps the bytes read and the nodes
and edges kept, and a bad lockfile is reported on its root, never as a panic.

| Lockfile | Reads | Roots |
|----------|-------|-------|
| `package-lock.json` (v2, v3) | lockfile only | project and workspace folders |
| `yarn.lock` (v1) | lockfile and `package.json` | project |
| `yarn.lock` (berry) | lockfile only | every workspace |
| `pnpm-lock.yaml` (5.x, 6.x, 9.x) | lockfile only | every importer |

## Error Handling

The parser handles errors gracefully:

- **ParseFile**: Returns error if file can't be read or parsed
- **ParseFiles**: Skips the files that fail and returns their errors keyed by path; it
  writes nothing to stderr, so the caller decides what a failure is worth
- **Unsupported files**: Returns an empty result rather than an error — check
  `IsSupportedFile` first if the difference from "declared nothing" matters

Example:

```go
result, err := parser.ParseFile("invalid.json")
if err != nil {
    log.Printf("Failed to parse: %v", err)
}
```

## Testing

Run the test suite:

```bash
go test -v ./pkg/dependencies/...
```

The test suite includes:
- Parser orchestration tests
- Individual parser tests for each ecosystem
- PURL generation tests
- Utility function tests

## Architecture

```
pkg/dependencies/
├── parser.go              # Main orchestrator (DependencyParser)
├── parser_test.go         # Comprehensive test suite
└── parsers/
    ├── types.go           # Type definitions (LocalPurl, LocalDependency, etc.)
    ├── utils.go           # Utility functions
    ├── golang.go          # Go parser (go.mod, go.sum)
    ├── python.go          # Python parser (requirements.txt, pyproject.toml)
    ├── npm.go             # Node.js parser (package.json, package-lock.json, yarn.lock)
    ├── maven.go           # Maven parser (pom.xml)
    ├── gradle.go          # Gradle parser (build.gradle)
    ├── ruby.go            # Ruby parser (Gemfile, Gemfile.lock)
    └── nuget.go           # NuGet parser (*.csproj, packages.config)
```

## Contributing

To add a new parser:

1. Create a new file in `parsers/` (e.g., `rust.go`)
2. Implement the parser function with signature:
   ```go
   func ParseRust(fileContent []byte, filePath string) (*LocalDependency, error)
   ```
3. Register it in `NewDependencyParser()` in `parser.go`
4. Add tests in `parser_test.go`

## License

Part of the SCANOSS project. See the main repository for license information.
