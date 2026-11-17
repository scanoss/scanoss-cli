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
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/sbom/depsource"
)

const toolchainFlagHelp = "resolve transitive dependencies by running the ecosystem's own tools (comma-separated): go. " +
	"Needs a go on PATH at least as new as the module's go directive, and reaches the module proxy with your environment"

// toolchainManifests maps each --toolchain value to the manifest it resolves.
var toolchainManifests = map[string]string{"go": "go.mod"}

// depsourceOptions reads --toolchain into the options dependency resolution runs with. Without
// the flag it returns the zero value, which reads lockfiles only.
func depsourceOptions(cmd *cobra.Command) (depsource.Options, error) {
	values, _ := cmd.Flags().GetStringSlice("toolchain")
	var opts depsource.Options
	for _, v := range values {
		manifest, ok := toolchainManifests[strings.ToLower(strings.TrimSpace(v))]
		if !ok {
			names := make([]string, 0, len(toolchainManifests))
			for n := range toolchainManifests {
				names = append(names, n)
			}
			slices.Sort(names)
			return opts, fmt.Errorf("unknown --toolchain value %q (valid: %s)", v, strings.Join(names, ", "))
		}
		if opts.Toolchain == nil {
			opts.Toolchain = map[string]bool{}
		}
		opts.Toolchain[manifest] = true
	}
	return opts, nil
}
