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
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/sbom/depsource"
)

const toolchainFlagHelp = "ecosystem tools used to resolve transitive dependencies (comma-separated): go, or none. " +
	"Defaults to go when a go is on PATH: go.mod is then resolved with go list and go mod graph, which reach the module " +
	"proxy with your environment and need a go at least as new as the module's go directive. " +
	"none reads go.mod only, with no network access"

// toolchainManifests maps each --toolchain value to the manifest it resolves.
var toolchainManifests = map[string]string{"go": "go.mod"}

// lookPath finds a tool on PATH; tests replace it.
var lookPath = exec.LookPath

// depsourceOptions reads --toolchain into the options dependency resolution runs with.
func depsourceOptions(cmd *cobra.Command) (depsource.Options, error) {
	values, _ := cmd.Flags().GetStringSlice("toolchain")
	set, err := toolchainSet(values, cmd.Flags().Changed("toolchain"))
	return depsource.Options{Toolchain: set}, err
}

// toolchainSet turns the --toolchain values into the manifests resolved with tools. Without the
// flag, go.mod is resolved with go when a go is on PATH: without one the resolver would only fall
// back with a warning on every run. "none" turns tools off and stands alone.
func toolchainSet(values []string, changed bool) (map[string]bool, error) {
	if !changed {
		if _, err := lookPath("go"); err != nil {
			return nil, nil
		}
		return map[string]bool{"go.mod": true}, nil
	}
	set := map[string]bool{}
	none := false
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "none" {
			none = true
			continue
		}
		manifest, ok := toolchainManifests[v]
		if !ok {
			names := []string{"none"}
			for n := range toolchainManifests {
				names = append(names, n)
			}
			slices.Sort(names)
			return nil, fmt.Errorf("unknown --toolchain value %q (valid: %s)", v, strings.Join(names, ", "))
		}
		set[manifest] = true
	}
	if none && len(set) > 0 {
		return nil, fmt.Errorf("--toolchain none cannot be combined with other values")
	}
	if len(set) == 0 {
		return nil, nil
	}
	return set, nil
}
