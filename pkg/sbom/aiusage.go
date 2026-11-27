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

package sbom

// AIUsageFormat identifies the ai_usage section's shape.
const AIUsageFormat = "scanoss-ai-usage/1"

// AIUsage is the ai_usage section of a raw document: the AI usage a scan found in source code.
type AIUsage struct {
	Format string `json:"format"`
	// Rules are the rulesets the findings come from.
	Rules []AIRuleset `json:"rules"`
	// Reachability is "enabled" when each finding carries a call-graph verdict, else "disabled".
	Reachability string           `json:"reachability"`
	Summary      AIUsageSummary   `json:"summary"`
	Findings     []AIUsageFinding `json:"findings"`
}

// AIRuleset names one ruleset a scan ran: a released one by name and version, or a local
// directory by its source.
type AIRuleset struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source"`
}

// AIUsageSummary counts the findings by category and by risk.
type AIUsageSummary struct {
	Findings   int            `json:"findings"`
	ByCategory map[string]int `json:"by_category"`
	ByRisk     map[string]int `json:"by_risk"`
}

// AIUsageFinding is one rule reported at one line. Metadata holds the rule's ai block, filled
// from the matched call: provider, model, risk, owasp, cwe and the like.
type AIUsageFinding struct {
	RuleID        string         `json:"rule_id"`
	Category      string         `json:"category"`
	Tier          string         `json:"tier"`
	File          string         `json:"file"`
	Line          int            `json:"line"`
	Reachability  string         `json:"reachability"`
	EntryPoint    *AIEntryPoint  `json:"entry_point,omitempty"`
	FlowTruncated bool           `json:"flow_truncated,omitempty"`
	Metadata      map[string]any `json:"metadata"`
}

// AIEntryPoint is where a reachable finding's call chain starts.
type AIEntryPoint struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	Route string `json:"route,omitempty"`
}

// Reachability verdicts of an AI usage finding.
const (
	AIReachable     = "reachable"
	AIUnreachable   = "unreachable"
	AIUnknown       = "unknown"
	AINotApplicable = "not_applicable"
)
