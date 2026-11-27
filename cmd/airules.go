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
	"errors"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/rulesets"
	"github.com/scanoss/scanoss.go/pkg/sbom"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

// AI rulesets the API serves: the private one needs an API key, the open one does not.
const (
	aiRulesDomain      = "ai"
	aiPrivateRulesRef  = "ai@latest"
	aiOpenRulesRef     = "ai-open@latest"
	aiRulesFlagHelp    = "AI ruleset to download, name@version (default: ai@latest with an API key, ai-open@latest without)"
	noRemoteRulesUsage = "Do not download AI rules; needs --rules-dir"
)

// addAIRulesFlags adds the flags that choose where AI rules come from.
func addAIRulesFlags(cmd *cobra.Command) {
	fs := cmd.Flags()
	fs.String("ruleset", "", aiRulesFlagHelp)
	fs.Bool("no-remote-rules", false, noRemoteRulesUsage)
	fs.Bool("no-cache", false, "Do not read or write the ruleset cache")
}

// aiRules are the rules a run matches: a local directory, or a downloaded ruleset unpacked into a
// private directory that close removes.
type aiRules struct {
	dir   string
	info  []sbom.AIRuleset
	close func()
}

// resolveAIRules returns the AI rules a command runs with: --rules-dir when given, else the
// ruleset the API serves for the key. Rules that cannot be had end the run with exit code 3.
func resolveAIRules(cmd *cobra.Command) (*aiRules, error) {
	if dir, _ := cmd.Flags().GetString("rules-dir"); dir != "" {
		return &aiRules{dir: dir, info: []sbom.AIRuleset{{Source: "local"}}, close: func() {}}, nil
	}
	if noRemote, _ := cmd.Flags().GetBool("no-remote-rules"); noRemote {
		return nil, &exitError{code: rulesets.ExitCode, err: errors.New("no AI rules: --no-remote-rules needs --rules-dir")}
	}
	cfg, err := apiConfig(cmd)
	if err != nil {
		return nil, err
	}
	ref, _ := cmd.Flags().GetString("ruleset")
	if ref == "" {
		ref = aiOpenRulesRef
		if cfg.APIKey != "" {
			ref = aiPrivateRulesRef
		}
	}
	name, version, err := rulesets.ParseRef(ref)
	if err != nil {
		return nil, err
	}
	hc, err := scanoss.NewHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	noCache, _ := cmd.Flags().GetBool("no-cache")
	client, err := rulesets.New(rulesets.Options{Domain: aiRulesDomain, APIURL: cfg.APIURL, APIKey: cfg.APIKey, HTTPClient: hc, NoCache: noCache})
	if err != nil {
		return nil, err
	}
	rs, err := client.Fetch(context.Background(), name, version)
	if err != nil {
		if errors.Is(err, rulesets.ErrUnavailable) {
			return nil, &exitError{code: rulesets.ExitCode, err: err}
		}
		return nil, err
	}
	return &aiRules{
		dir:   rs.Dir,
		info:  []sbom.AIRuleset{{Name: rs.Name, Version: rs.Version, Source: string(rs.Source)}},
		close: func() { _ = rs.Close() },
	}, nil
}
