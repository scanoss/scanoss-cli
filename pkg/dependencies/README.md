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
  workspace, path crate or `PATH` gem that something depends on. They keep their edges, so a root
  that depends on a sibling workspace reaches that workspace's dependencies.
  A local node may have no version. Skip local nodes to list only third-party
  packages.
- **Roots** are manifests: the project and, where the lockfile records them,
  each workspace. A root lists its members and its node-to-node edges.
  `Member.Direct` marks the packages the manifest declares.
- **Dev members** (`Member.Dev`) are the ones the root reaches only through
  its dev dependencies: test, lint and build tooling its users never install.
  A member that any runtime dependency reaches is not dev, so a package can be
  dev in one root and runtime in another. `Root.DevKnown` says whether the
  manifests say which direct dependencies are dev; when it is false no member
  is dev, and every member must be treated as runtime. Per-entry flags such as
  `dev: true` in `package-lock.json` are not used.
- **Status** is `complete`, `partial` (usable but missing something) or
  `unknown` (no members), with a `Reason` such as `manifest_missing` or
  `malformed`. `edges_unknown` marks a lockfile that pins every package but
  records no edges: its members are right, and a member that is not direct
  has no incoming edge.

Lockfiles are treated as untrusted: `Limits` caps the bytes read and the nodes
and edges kept, and a bad lockfile is reported on its root, never as a panic.

| Lockfile | Reads | Roots | Dev dependencies |
|----------|-------|-------|------------------|
| `package-lock.json` (v2, v3), `npm-shrinkwrap.json` | lockfile only | project and workspace folders | each root's `devDependencies` |
| `yarn.lock` (v1) | lockfile and `package.json` | project | `devDependencies` in `package.json`; unknown without it |
| `yarn.lock` (berry) | lockfile, and `package.json` when present | every workspace | the root workspace's `devDependencies` in `package.json`; unknown for other workspaces |
| `pnpm-lock.yaml` (5.x, 6.x, 9.x) | lockfile only | every importer | each importer's `devDependencies` |
| `Cargo.lock` | lockfile, `Cargo.toml` and workspace member manifests | `Cargo.toml` and each workspace member; a path crate that something depends on is a local node | `[dev-dependencies]`, including per target, that are not also normal or build dependencies; unknown for a root without its manifest |
| `Gemfile.lock` | lockfile and `Gemfile` | `Gemfile`; `PATH` gems are local nodes | gems declared only in the `development` and `test` groups; unknown without a `Gemfile` |
| `poetry.lock` | lockfile and `pyproject.toml` | project; path dependencies are local nodes | `dev-dependencies`, every Poetry group but `main`, and `[dependency-groups]`; unknown without `pyproject.toml` |
| `uv.lock` (version 1) | lockfile only | the project and each workspace member, at its `pyproject.toml`; editable, directory and path packages are local nodes | each root's `dev-dependencies` groups; extras are runtime |
| `packages.lock.json` (NuGet v1, v2) | lockfile, and the name of the project file beside it | the `.csproj`, `.fsproj` or `.vbproj` beside it, or the lockfile when there is not exactly one; every target framework is merged, and `Project` entries are local nodes | unknown: the lockfile does not record them |
| `composer.lock` | lockfile and `composer.json` | project; path repository packages are local nodes | `require-dev`; unknown without `composer.json` |
| `gradle.lockfile` | lockfile, and whether `build.gradle.kts` is beside it | `build.gradle`, or `build.gradle.kts` when it is the only build file; no direct members and no edges (`edges_unknown`) | unknown |
| `Pipfile.lock` | lockfile and `Pipfile` | `Pipfile`, with `[packages]` and `[dev-packages]` as directs; no edges (`edges_unknown`); path packages are local nodes and VCS packages are left out | `[dev-packages]`; unknown without a `Pipfile` |
| `go.mod` | `go.mod` only | `go.mod`, with requirements not marked `// indirect` as directs; no edges (`edges_unknown`); `replace` rewrites a module, and a directory replacement is a local node | unknown: Go has no dev dependencies |

The `Gemfile` is Ruby, so only `gem` lines, `group` blocks and `group:` or
`groups:` options are read. A gem declared in any other way counts as runtime,
and a `Gemfile` whose blocks do not balance leaves the root's dev dependencies
unknown.

### Resolving with the build tools

Some lockfiles record no edges, such as `go.mod`. `resolve/toolchain` builds
the same `resolve.Graph` by running the ecosystem's own tools on the manifest:

```go
g, err := toolchain.Resolve(ctx, projectDir, "svc/go.mod", toolchain.Options{
    Env: []string{"GOPROXY=https://proxy.golang.org"},
})
if err != nil {
    return err // toolchain.ErrUnsupported
}
root := g.Roots[0] // Manifest and Lockfile are both svc/go.mod
```

The tools run on files the scanned repository controls, and some run its own
code, so run `Resolve` inside an isolated sandbox. They need no credentials;
`Options.Env` sets the registry or mirror and overrides the tool's defaults.
Each run has a timeout (`Options.Timeout`, 10 minutes by default) and its
output is capped by `Limits`. A tool problem never fails the call: the root is
`unknown` with `tool_missing`, `tool_failed`, `timeout` or `too_large`, or
`partial` with `registry_unreachable` when the tool could not reach the
registry and the members are what it resolved without it.

| Manifest | Runs | Graph |
|----------|------|-------|
| `go.mod` | `go list -e -m -json all` and `go mod graph`, with `GOWORK=off`, `GOFLAGS=-mod=readonly` and `GOTOOLCHAIN=local` | the modules the build selects, with edges between the selected versions; `replace` as for the `go.mod` lockfile; `edges_unknown` when only `go mod graph` fails |
| `pom.xml` | `mvn -B -ntp -fae org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -Dverbose=true -DoutputType=text`, from `PATH`, never `mvnw` | one root per module of the reactor, resolved as that module resolves its dependencies, with the module's `pom.xml` as `Manifest` and `Lockfile`; `Limits` apply per module; edges to the nodes Maven omits for a duplicate, conflict or cycle; sibling modules are local nodes and `test` dependencies dev; a module that fails, or that Maven skips after another failed, gets that failure; `unresolved_dependency` for a dependency whose POM is missing |

`mvn` writes each module's tree to a hidden file, named afresh for each call,
in the module's directory; `Resolve` reads and removes them, also when `mvn`
fails or times out. Maven has no environment defaults here: set mirrors in
the `settings.xml` that `MAVEN_ARGS` (Maven 3.9 and later) or `MAVEN_OPTS`
points to through `Options.Env`.

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
