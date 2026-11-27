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

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func aiFinding(rule, category, file string, line int, meta map[string]any) AIUsageFinding {
	return AIUsageFinding{RuleID: rule, Category: category, File: file, Line: line, Reachability: AIReachable, Metadata: map[string]any{"ai": meta}}
}

// Providers become services, named models machine-learning-model components, and risks above
// info vulnerabilities that affect them, or the project when they name no model or service.
func TestCycloneDXRendersAIUsage(t *testing.T) {
	usage := &AIUsage{Format: AIUsageFormat, Findings: []AIUsageFinding{
		aiFinding("ai.test.chat", "model_usage", "a.py", 3, map[string]any{"provider": "acme", "model": "m-1", "risk": "info"}),
		aiFinding("ai.test.chat", "model_usage", "b.py", 7, map[string]any{"provider": "acme", "model": "m-1", "risk": "info"}),
		aiFinding("ai.test.chat-unresolved", "model_usage", "c.py", 2, map[string]any{"provider": "acme", "risk": "info"}),
		aiFinding("ai.test.load", "model_load", "d.py", 5, map[string]any{"provider": "huggingface", "model": "org/m", "risk": "high", "owasp": "LLM03", "cwe": []any{"CWE-94"}}),
		aiFinding("ai.test.exec", "prompt_flow", "e.py", 9, map[string]any{"risk": "critical", "cwe": []any{"CWE-78"}}),
	}}
	out, err := Generate(Inventory{}, FormatCycloneDX, WithProjectName("proj"), WithAIUsage(usage))
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(strings.NewReader(out), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatal(err)
	}
	if bom.Services == nil || len(*bom.Services) != 1 || (*bom.Services)[0].BOMRef != "svc:acme" {
		t.Fatalf("services = %+v, want svc:acme only", bom.Services)
	}
	models := map[string]cdx.Component{}
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeMachineLearningModel {
			models[c.BOMRef] = c
		}
	}
	if len(models) != 2 || len(*models["model:acme/m-1"].Evidence.Occurrences) != 2 || models["model:huggingface/org/m"].PackageURL != "pkg:huggingface/org/m" {
		t.Fatalf("models = %+v", models)
	}
	vulns := map[string]cdx.Vulnerability{}
	for _, v := range *bom.Vulnerabilities {
		vulns[v.ID] = v
	}
	load, exec := vulns["SCANOSS-AI-TEST-LOAD"], vulns["SCANOSS-AI-TEST-EXEC"]
	if len(vulns) != 2 || (*load.CWEs)[0] != 94 || (*load.Affects)[0].Ref != "model:huggingface/org/m" || (*load.Ratings)[0].Severity != cdx.SeverityHigh {
		t.Fatalf("vulnerabilities = %+v", vulns)
	}
	if (*exec.Affects)[0].Ref != "proj" || (*exec.Ratings)[0].Severity != cdx.SeverityCritical {
		t.Fatalf("exec vulnerability = %+v, want it on the project", exec)
	}
}
