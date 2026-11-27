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

// Package aiusage reports AI usage in source code: it builds each language's call graph with
// reach, projects it as a graph fragment and matches the AI cards against it.
package aiusage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/cardmatch"
	"github.com/scanoss/reach/fragbuild"
	"github.com/scanoss/reach/javaruntime"
	"github.com/scanoss/reach/skip"

	"github.com/scanoss/scanoss.go/pkg/sbom"
)

// MetadataKey is the rule block AI cards carry their metadata in.
const MetadataKey = "ai"

// Options select the rules and languages of a scan.
type Options struct {
	// RulesDir holds the card files, one directory per card language (python/, javascript/).
	RulesDir string
	// Rules names the rulesets RulesDir holds, for the report; empty means a local directory.
	Rules []sbom.AIRuleset
	// Languages are the languages to scan: python, javascript, typescript. Empty scans every
	// card language RulesDir holds.
	Languages []string
	// IncludeTests also scans test files.
	IncludeTests bool
	// Reachability decides for each finding whether it runs from an entry point.
	Reachability bool
}

// cardLanguages maps a language name to the card directory and call-graph ecosystem it uses.
var cardLanguages = map[string]struct{ cards, ecosystem string }{
	"python":     {"python", fragbuild.EcosystemPython},
	"javascript": {"javascript", fragbuild.EcosystemNode},
	"typescript": {"javascript", fragbuild.EcosystemNode},
}

// Scan reports the AI usage under target.
func Scan(target string, opts Options) (*sbom.AIUsage, error) {
	root, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	langs, err := selectCardLanguages(opts)
	if err != nil {
		return nil, err
	}
	var findings []sbom.AIUsageFinding
	for _, lang := range langs {
		found, err := scanLanguage(root, lang, opts)
		if err != nil {
			return nil, fmt.Errorf("aiusage: %s: %w", lang, err)
		}
		findings = append(findings, found...)
	}
	rules := opts.Rules
	if len(rules) == 0 {
		rules = []sbom.AIRuleset{{Source: "local"}}
	}
	report := newReport(rules, findings)
	if opts.Reachability {
		report.Reachability = "enabled"
	}
	return report, nil
}

// selectCardLanguages returns the card directories to match, each once.
func selectCardLanguages(opts Options) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(cards string) {
		if !seen[cards] && isDir(filepath.Join(opts.RulesDir, cards)) {
			seen[cards] = true
			out = append(out, cards)
		}
	}
	if len(opts.Languages) == 0 {
		for _, l := range cardLanguages {
			add(l.cards)
		}
	}
	for _, name := range opts.Languages {
		l, ok := cardLanguages[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("aiusage: unsupported language %q (want python, javascript or typescript)", name)
		}
		add(l.cards)
	}
	sort.Strings(out)
	return out, nil
}

func scanLanguage(root, cards string, opts Options) ([]sbom.AIUsageFinding, error) {
	ecosystem := cardLanguages[cards].ecosystem
	cardsDir := filepath.Join(opts.RulesDir, cards)
	assets, err := cardmatch.Load("", cardsDir, "", cardmatch.Options{MetadataKey: MetadataKey, LanguageOf: func(string) string { return cards }})
	if err != nil {
		return nil, fmt.Errorf("load cards: %w", err)
	}
	ruleMeta, err := loadRuleMetadata(cardsDir)
	if err != nil {
		return nil, err
	}
	graph, err := buildGraph(root, ecosystem, opts.IncludeTests)
	if err != nil {
		return nil, err
	}
	export := fragbuild.Build(fragbuild.Input{Graph: graph, Ecosystem: ecosystem, ProjectRoot: root})
	raw, err := json.Marshal(export)
	if err != nil {
		return nil, err
	}
	var frag cardmatch.FragmentJSON
	if err := json.Unmarshal(raw, &frag); err != nil {
		return nil, err
	}
	matched, _, err := assets.Match(&frag)
	if err != nil {
		return nil, fmt.Errorf("match cards: %w", err)
	}
	var reach *reachability
	if opts.Reachability {
		reach = newReachability(root, ecosystem, graph)
	}
	out := make([]sbom.AIUsageFinding, 0, len(matched))
	for _, f := range matched {
		finding := newFinding(f.RuleID, f.File, f.Line, typedMetadata(f.MetadataFields(), ruleMeta[f.RuleID]))
		if reach != nil {
			v := reach.of(f.Caller)
			finding.Reachability, finding.EntryPoint = v.status, v.entry
		}
		out = append(out, finding)
	}
	return out, nil
}

func buildGraph(root, ecosystem string, includeTests bool) (*callgraph.CallGraph, error) {
	parser := callgraph.NewParserForEcosystem(ecosystem, callgraph.WithIncludeTests(includeTests))
	builder := callgraph.NewBuilderForEcosystem(ecosystem, parser)
	builder.SetSkipMatcher(skip.NewDefaultMatcher())
	if resolver := callgraph.NewTypeResolverForEcosystem(ecosystem, javaruntime.Config{}); resolver != nil {
		builder.SetTypeResolver(resolver)
	}
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		return nil, fmt.Errorf("build call graph: %w", err)
	}
	return graph, nil
}

func newFinding(ruleID, file string, line int, meta map[string]any) sbom.AIUsageFinding {
	str := func(k string) string {
		s, _ := meta[k].(string)
		return s
	}
	return sbom.AIUsageFinding{
		RuleID:       ruleID,
		Category:     str("type"),
		Tier:         str("tier"),
		File:         filepath.ToSlash(file),
		Line:         line,
		Reachability: sbom.AIUnknown,
		Metadata:     map[string]any{MetadataKey: meta},
	}
}

// newReport sorts and de-duplicates findings and counts them.
func newReport(rules []sbom.AIRuleset, findings []sbom.AIUsageFinding) *sbom.AIUsage {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
	out := &sbom.AIUsage{
		Format:       sbom.AIUsageFormat,
		Rules:        rules,
		Reachability: "disabled",
		Summary:      sbom.AIUsageSummary{ByCategory: map[string]int{}, ByRisk: map[string]int{}},
		Findings:     []sbom.AIUsageFinding{},
	}
	for i, f := range findings {
		if i > 0 && f.RuleID == findings[i-1].RuleID && f.File == findings[i-1].File && f.Line == findings[i-1].Line {
			continue
		}
		out.Findings = append(out.Findings, f)
		out.Summary.Findings++
		out.Summary.ByCategory[f.Category]++
		if risk, _ := f.Metadata[MetadataKey].(map[string]any)["risk"].(string); risk != "" {
			out.Summary.ByRisk[risk]++
		}
	}
	return out
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
