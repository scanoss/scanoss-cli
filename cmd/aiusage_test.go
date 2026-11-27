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
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

func TestFindingsAtOrAbove(t *testing.T) {
	risk := func(r string) sbom.AIUsageFinding {
		return sbom.AIUsageFinding{Metadata: map[string]any{"ai": map[string]any{"risk": r}}}
	}
	report := &sbom.AIUsage{Findings: []sbom.AIUsageFinding{risk("info"), risk("medium"), risk("high"), risk("critical"), {}}}
	for level, want := range map[string]int{"low": 3, "medium": 3, "high": 2, "critical": 1} {
		if got := findingsAtOrAbove(report, riskRank[level]); got != want {
			t.Errorf("--fail-on %s: %d findings, want %d", level, got, want)
		}
	}
}

func aiRulesCommand(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("rules-dir", "", "")
	addAIRulesFlags(cmd)
	addAPIFlags(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// --rules-dir is used as given; without it and with --no-remote-rules there are no rules, which
// ends the run with exit code 3.
func TestResolveAIRules(t *testing.T) {
	rules, err := resolveAIRules(aiRulesCommand(t, "--rules-dir", "some/dir"))
	if err != nil || rules.dir != "some/dir" || rules.info[0].Source != "local" {
		t.Fatalf("local rules = %+v, %v", rules, err)
	}
	rules.close()
	_, err = resolveAIRules(aiRulesCommand(t, "--no-remote-rules"))
	var exit *exitError
	if !errors.As(err, &exit) || exit.code != 3 {
		t.Fatalf("--no-remote-rules without --rules-dir: %v, want exit code 3", err)
	}
}
