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

package cmd

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/dependencies"
	"github.com/scanoss/scanoss.go/pkg/dependencies/parsers"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/lockfile"
	"github.com/scanoss/scanoss.go/pkg/filter"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

var dependenciesCmd = &cobra.Command{
	Use:   "dependencies [path]",
	Short: "Extract local dependencies or query SCANOSS API for component dependencies",
	Long: `The dependencies command has three modes:

1. LOCAL MODE (--extract-local):
   Recursively scans a directory to find dependency manifest files and extracts
   dependency information as standardized Package URLs (PURLs).

   Supported ecosystems:
     - Node.js:      package.json, package-lock.json, yarn.lock
     - Python:       requirements.txt, pyproject.toml
     - Java (Maven): pom.xml
     - Java (Gradle): build.gradle
     - Go:           go.mod, go.sum
     - Ruby:         Gemfile, Gemfile.lock
     - .NET:         *.csproj, packages.config

   With --graph it prints the dependency graph resolved from the lockfiles
   instead: package-lock.json, npm-shrinkwrap.json, yarn.lock,
   pnpm-lock.yaml, Cargo.lock, Gemfile.lock, poetry.lock, uv.lock,
   composer.lock and packages.lock.json.

2. API MODE (--purl):
   Queries the SCANOSS API for component dependencies (direct or transitive).

3. SCAN MODE (default):
   Extracts local dependencies from the provided path and queries the SCANOSS API
   for dependency information (vulnerabilities, licenses, etc.).

Examples:
  # Extract local dependencies and display on console
  scanoss-cli dependencies ./my-project --extract-local

  # Extract local dependencies and save to file
  scanoss-cli dependencies ./my-project --extract-local --output deps.json

  # Print the dependency graph resolved from the project's lockfiles
  scanoss-cli dependencies ./my-project --extract-local --graph

  # Scan project dependencies and query API for direct dependencies
  scanoss-cli dependencies ./my-project

  # Scan project dependencies and query API for transitive dependencies
  scanoss-cli dependencies ./my-project --transient

  # Query direct dependencies from API for specific component
  scanoss-cli dependencies --purl 'pkg:github/scanoss/engine' --requirement '5.4.7'

  # Query transitive dependencies from API for specific component
  scanoss-cli dependencies --purl 'pkg:github/scanoss/engine' --requirement '5.4.7' --transient

  # With custom depth and limit for transitive
  scanoss-cli dependencies --purl 'pkg:github/scanoss/engine' --requirement '5.4.7' --transient --depth 5 --limit 20`,
	RunE: runDependencies,
}

func init() {
	rootCmd.AddCommand(dependenciesCmd)

	// Local extraction mode
	dependenciesCmd.Flags().Bool("extract-local", false, "Extract local dependencies from manifest files")
	dependenciesCmd.Flags().Bool("graph", false, "With --extract-local, print the dependency graph resolved from lockfiles")
	dependenciesCmd.Flags().String("settings", "", "Path to settings file (scanoss.json/settings.json)")

	// API mode flags
	dependenciesCmd.Flags().String("purl", "", "Package URL (purl) of the component (required for API mode)")
	dependenciesCmd.Flags().String("requirement", "", "Version requirement (required for API mode)")

	// Mode flag
	dependenciesCmd.Flags().Bool("transient", false, "Query transitive dependencies (API mode)")

	// Transitive-specific flags
	dependenciesCmd.Flags().Int("depth", 10, "Depth for transitive dependencies (only with --transient)")
	dependenciesCmd.Flags().Int("limit", 10, "Limit for transitive dependencies (only with --transient)")

	// API and output configuration
	addAPIFlags(dependenciesCmd)
}

func runDependencies(cmd *cobra.Command, args []string) error {
	extractLocal, _ := cmd.Flags().GetBool("extract-local")
	graph, _ := cmd.Flags().GetBool("graph")
	settingsFlag, _ := cmd.Flags().GetString("settings")
	outputFile, _ := cmd.Flags().GetString("output")
	purl, _ := cmd.Flags().GetString("purl")
	transient, _ := cmd.Flags().GetBool("transient")
	depth, _ := cmd.Flags().GetInt("depth")
	limit, _ := cmd.Flags().GetInt("limit")
	cfg, err := apiConfig(cmd)
	if err != nil {
		return err
	}

	if !extractLocal && purl == "" && len(args) == 0 {
		return usageError(cmd, "a path, --purl or --extract-local is required")
	}
	if graph && !extractLocal {
		return usageError(cmd, "--graph requires --extract-local")
	}

	// Mode 1: Local extraction only
	if extractLocal {
		if len(args) == 0 {
			return fmt.Errorf("path argument is required with --extract-local")
		}
		if graph {
			return runLocalGraph(args[0], outputFile, settingsFlag)
		}
		return runLocalExtraction(args[0], outputFile, settingsFlag)
	}

	// Mode 2: API query with specific purl. --requirement is optional (the API
	// treats it as optional, and the purl itself may carry the version).
	if purl != "" {
		requirement, _ := cmd.Flags().GetString("requirement")

		var response string
		var err error

		if transient {
			// Transitive dependencies endpoint
			response, err = queryTransitiveDependencies(cfg, purl, requirement, depth, limit)
		} else {
			// Direct dependencies endpoint
			response, err = queryDirectDependencies(cfg, purl, requirement)
		}

		if err != nil {
			return fmt.Errorf("error querying dependencies: %w", err)
		}

		return writeOutput(response, outputFile)
	}

	// Mode 3: Scan mode - extract local dependencies and query API
	if len(args) == 0 {
		return fmt.Errorf("path argument is required (use --purl for API-only mode or --extract-local for local-only mode)")
	}

	return runScanMode(cfg, args[0], outputFile, settingsFlag, transient, depth, limit)
}

// runLocalExtraction extracts dependencies from local manifest files
func runLocalExtraction(targetPath, outputFile, settingsFlag string) error {
	// Check if path exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", targetPath)
	}

	// Create dependency parser
	parser := dependencies.NewDependencyParser()

	infof("Scanning for dependency files in %s", targetPath)

	// Collect the candidate files
	allFiles, skipped, err := collectDependencyFiles(targetPath, settingsFlag)
	if err != nil {
		return fmt.Errorf("failed to collect files: %w", err)
	}

	infof("Total files found: %d", len(allFiles))
	if skipped > 0 {
		infof("Filtered %d files", skipped)
	}

	// Filter only dependency files
	depFiles := parser.FilterFiles(allFiles)

	if len(depFiles) == 0 {
		warnf("No dependency files found")

		// Return empty result
		emptyResult := &parsers.LocalDependencies{
			Files: []parsers.LocalDependency{},
		}

		return outputJSON(emptyResult, outputFile)
	}

	infof("Dependency files found: %d", len(depFiles))
	fmt.Fprintf(os.Stderr, "\n")

	// Create progress bar
	prog := newProgress()
	bar := addBar(prog, len(depFiles), "Parsing dependencies")

	// Parse all dependency files
	result := &parsers.LocalDependencies{
		Files: []parsers.LocalDependency{},
	}

	for _, filePath := range depFiles {
		dep, err := parser.ParseFile(filePath)
		if err != nil {
			warnf("failed to parse %s: %v", filePath, err)
			bar.Increment()
			continue
		}

		// Only add if there are dependencies
		if len(dep.Purls) > 0 {
			result.Files = append(result.Files, *dep)
		}

		bar.Increment()
	}

	bar.SetCurrent(int64(len(depFiles)))
	prog.Wait()

	// Count total dependencies
	totalDeps := 0
	for _, file := range result.Files {
		totalDeps += len(file.Purls)
	}

	okf("Successfully parsed %d files", len(result.Files))
	infof("Total dependencies found: %d", totalDeps)
	fmt.Fprintf(os.Stderr, "\n")

	return outputJSON(result, outputFile)
}

// runLocalGraph prints the dependency graph of every lockfile under targetPath,
// merged into one.
func runLocalGraph(targetPath, outputFile, settingsFlag string) error {
	root, err := filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(root); err != nil {
		return fmt.Errorf("path does not exist: %s", targetPath)
	}
	s, err := resolveSettings(settingsFlag, root)
	if err != nil {
		return fmt.Errorf("error loading settings: %w", err)
	}
	opts := filter.Dependencies(s)
	// The built-in extension list drops .lock and .yaml, which would hide
	// Cargo.lock, pnpm-lock.yaml, poetry.lock and composer.lock. Lockfiles are
	// selected by name below instead.
	opts.BuiltinFileRules = false
	res, err := filter.Collect(root, opts)
	if err != nil {
		return fmt.Errorf("failed to collect files: %w", err)
	}

	fsys := os.DirFS(root)
	var graphs []resolve.Graph
	for _, file := range res.Files {
		if !lockfile.Supported(file) {
			continue
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		g, err := lockfile.ParseFS(fsys, filepath.ToSlash(rel), lockfile.DefaultLimits())
		if err != nil {
			warnf("failed to parse %s: %v", file, err)
			continue
		}
		graphs = append(graphs, g)
	}
	infof("Lockfiles resolved: %d", len(graphs))
	return outputJSON(mergeGraphs(graphs), outputFile)
}

// mergeGraphs joins graphs into one, keeping each node once and the order
// resolve.Graph documents.
func mergeGraphs(graphs []resolve.Graph) resolve.Graph {
	out := resolve.Graph{Nodes: []resolve.Node{}, Roots: []resolve.Root{}}
	seen := map[resolve.NodeID]bool{}
	for _, g := range graphs {
		for _, n := range g.Nodes {
			if !seen[n.ID] {
				seen[n.ID] = true
				out.Nodes = append(out.Nodes, n)
			}
		}
		out.Roots = append(out.Roots, g.Roots...)
	}
	slices.SortFunc(out.Nodes, func(a, b resolve.Node) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(out.Roots, func(a, b resolve.Root) int {
		return cmp.Or(cmp.Compare(a.Manifest, b.Manifest), cmp.Compare(a.Lockfile, b.Lockfile))
	})
	return out
}

// runScanMode extracts local dependencies and queries the SCANOSS API
func runScanMode(cfg scanoss.Config, targetPath, outputFile, settingsFlag string, transient bool, depth, limit int) error {
	// Check if path exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", targetPath)
	}

	// Create dependency parser
	parser := dependencies.NewDependencyParser()

	infof("Scanning for dependency files in %s", targetPath)

	// Collect the candidate files
	allFiles, skipped, err := collectDependencyFiles(targetPath, settingsFlag)
	if err != nil {
		return fmt.Errorf("failed to collect files: %w", err)
	}

	infof("Total files found: %d", len(allFiles))
	if skipped > 0 {
		infof("Filtered %d files", skipped)
	}

	// Filter only dependency files
	depFiles := parser.FilterFiles(allFiles)

	if len(depFiles) == 0 {
		return fmt.Errorf("no dependency files found in %s", targetPath)
	}

	infof("Dependency files found: %d", len(depFiles))
	fmt.Fprintf(os.Stderr, "\n")

	// Create progress bar
	prog := newProgress()
	bar := addBar(prog, len(depFiles), "Parsing dependencies")

	// Parse all dependency files
	localDeps := &parsers.LocalDependencies{
		Files: []parsers.LocalDependency{},
	}

	for _, filePath := range depFiles {
		dep, err := parser.ParseFile(filePath)
		if err != nil {
			warnf("failed to parse %s: %v", filePath, err)
			bar.Increment()
			continue
		}

		// Only add if there are dependencies
		if len(dep.Purls) > 0 {
			localDeps.Files = append(localDeps.Files, *dep)
		}

		bar.Increment()
	}

	bar.SetCurrent(int64(len(depFiles)))
	prog.Wait()

	// Count total dependencies
	totalDeps := 0
	for _, file := range localDeps.Files {
		totalDeps += len(file.Purls)
	}

	okf("Successfully parsed %d files", len(localDeps.Files))
	infof("Total dependencies found: %d", totalDeps)
	fmt.Fprintf(os.Stderr, "\n")

	if totalDeps == 0 {
		return fmt.Errorf("no dependencies found in any files")
	}

	// Query SCANOSS API with extracted dependencies
	infof("Querying SCANOSS API...")

	var response string
	if transient {
		response, err = queryTransitiveDependenciesWithFiles(cfg, localDeps, depth, limit)
	} else {
		response, err = queryDirectDependenciesWithFiles(cfg, localDeps)
	}

	if err != nil {
		return fmt.Errorf("error querying SCANOSS API: %w", err)
	}

	okf("API query successful")

	return writeOutput(response, outputFile)
}

// collectDependencyFiles collects the files a dependency scan may parse, using
// the shared filter with the dependency profile: the same rules the rest of the
// CLI applies, and the same ones `scan --include deps` uses for this stage.
//
// It replaces a hand-written walk that carried its own directory list and read
// neither scanoss.json nor the shared defaults. The manifests survive the
// default extension list (.json, .mod, .xml, …) through
// KeepManifests, so what the parser receives is unchanged.
func collectDependencyFiles(root, settingsFlag string) ([]string, int, error) {
	depSettings, err := resolveSettings(settingsFlag, root)
	if err != nil {
		return nil, 0, fmt.Errorf("error loading settings: %w", err)
	}
	opts := filter.Dependencies(depSettings)

	res, err := filter.Collect(root, opts)
	if err != nil {
		return nil, 0, err
	}
	return res.Files, res.SkippedCount, nil
}

// outputJSON marshals data to JSON and writes to file or stdout
func outputJSON(data interface{}, outputFile string) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to generate JSON: %w", err)
	}

	if outputFile != "" {
		err := os.WriteFile(outputFile, jsonData, 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		okf("Results saved to %s", outputFile)
	} else {
		fmt.Println(string(jsonData))
	}

	return nil
}

// componentsFromLocalDeps flattens the per-file extracted PURLs into a single
// component list for the v3 batch / transitive endpoints.
func componentsFromLocalDeps(localDeps *parsers.LocalDependencies) []scanoss.Component {
	var comps []scanoss.Component
	for _, file := range localDeps.Files {
		for _, p := range file.Purls {
			comps = append(comps, scanoss.Component{Purl: p.Purl, Requirement: p.Requirement})
		}
	}
	return comps
}

// marshalDepResponse pretty-prints a typed SDK response as JSON for CLI output.
func marshalDepResponse(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error encoding response: %w", err)
	}
	return string(b), nil
}

// queryDirectDependencies resolves declared dependencies for a single purl via the
// v3 dependencies endpoint (SDK-typed response).
func queryDirectDependencies(cfg scanoss.Config, purl, requirement string) (string, error) {
	client, err := scanoss.New(cfg)
	if err != nil {
		return "", err
	}
	resp, err := client.Dependencies.Dependency(context.Background(), scanoss.Component{Purl: purl, Requirement: requirement})
	if err != nil {
		return "", err
	}
	return marshalDepResponse(resp)
}

// queryTransitiveDependencies walks the transitive dependency tree for a single purl.
func queryTransitiveDependencies(cfg scanoss.Config, purl, requirement string, depth, limit int) (string, error) {
	client, err := scanoss.New(cfg)
	if err != nil {
		return "", err
	}
	resp, err := client.Dependencies.Transitive(context.Background(), []scanoss.Component{{Purl: purl, Requirement: requirement}}, depth, limit)
	if err != nil {
		return "", err
	}
	return marshalDepResponse(resp)
}

// queryDirectDependenciesWithFiles resolves declared dependencies for all PURLs
// extracted from local manifests (v3 batch endpoint).
func queryDirectDependenciesWithFiles(cfg scanoss.Config, localDeps *parsers.LocalDependencies) (string, error) {
	client, err := scanoss.New(cfg)
	if err != nil {
		return "", err
	}
	resp, err := client.Dependencies.Dependencies(context.Background(), componentsFromLocalDeps(localDeps))
	if err != nil {
		return "", err
	}
	return marshalDepResponse(resp)
}

// queryTransitiveDependenciesWithFiles walks the transitive tree for all PURLs
// extracted from local manifests.
func queryTransitiveDependenciesWithFiles(cfg scanoss.Config, localDeps *parsers.LocalDependencies, depth, limit int) (string, error) {
	client, err := scanoss.New(cfg)
	if err != nil {
		return "", err
	}
	resp, err := client.Dependencies.Transitive(context.Background(), componentsFromLocalDeps(localDeps), depth, limit)
	if err != nil {
		return "", err
	}
	return marshalDepResponse(resp)
}
