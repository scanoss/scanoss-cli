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
	"context"

	scanossapi "github.com/scanoss/scanoss.api-sdk"
	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

func callRemediation(c *scanoss.Client, ctx context.Context, comps []scanoss.Component, opts ...scanoss.DecorateOption) (*scanossapi.RemediationResponse, error) {
	return c.Remediation.Components(ctx, comps, opts...)
}

var remediationCmd = &cobra.Command{
	Use:   "remediation",
	Short: "Query Remediation Intelligence for component versions from the SCANOSS API",
	Long: `The remediation command queries SCANOSS Remediation Intelligence: for each component
version, its risk band and what limits it, any hard stop, the advisory findings and the ranked
upgrade, replace or remove actions.

Remediation Intelligence answers for exact versions only. Give the version in the purl
(pkg:npm/left-pad@1.3.0) or as an exact --requirement; a range comes back VERSION_NOT_FOUND.
A component it has no record for comes back COMPONENT_NOT_FOUND. Go modules are indexed by
module path (pkg:golang/github.com/gorilla/mux), not by repository (pkg:github/gorilla/mux).

The input is a list of PURLs, split into chunks and sent concurrently by a pool of workers
(at most 500 per chunk). The combined status counts every chunk, and data_as_of is the oldest
date over all the hits.

Examples:
  # One component version
  scanoss-cli remediation --purl 'pkg:golang/github.com/gorilla/mux@v1.8.1'

  # Version as a requirement
  scanoss-cli remediation --purl 'pkg:npm/left-pad' --requirement '1.3.0'

  # From a file (purl[,requirement] per line), in chunks of 100
  scanoss-cli remediation --input purls.txt --chunk-size 100`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error { return runPurlServiceTyped(cmd, callRemediation) },
}

func init() {
	rootCmd.AddCommand(remediationCmd)
	addPurlServiceFlags(remediationCmd)
}
