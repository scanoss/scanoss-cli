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
	"fmt"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// AI usage in CycloneDX: each provider is a service, each named model a machine-learning-model
// component, and each rule with a risk above info a vulnerability affecting them. What has no
// CycloneDX field travels as scanoss:ai:* properties.
const aiPropPrefix = "scanoss:ai:"

// appendAIUsage adds the AI usage report to bom; projectRef is the project component's bom-ref,
// which a risk with no model or service affects.
func appendAIUsage(bom *cdx.BOM, u *AIUsage, projectRef string) {
	if u == nil || len(u.Findings) == 0 {
		return
	}
	services := map[string]*cdx.Service{}
	models := map[string]*cdx.Component{}
	vulns := map[string]*cdx.Vulnerability{}
	for _, f := range u.Findings {
		meta, _ := f.Metadata["ai"].(map[string]any)
		provider, model := metaString(meta, "provider"), metaString(meta, "model")
		var refs []string
		if provider != "" && (f.Category == "model_usage" || f.Category == "prompt_flow") {
			ref := "svc:" + provider
			if services[ref] == nil {
				services[ref] = &cdx.Service{BOMRef: ref, Name: provider}
			}
			refs = append(refs, ref)
		}
		if model != "" {
			ref := "model:" + provider + "/" + model
			c := models[ref]
			if c == nil {
				c = &cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeMachineLearningModel, Name: model, Evidence: &cdx.Evidence{Occurrences: &[]cdx.EvidenceOccurrence{}}}
				if provider == "huggingface" {
					c.PackageURL = "pkg:huggingface/" + model
				}
				props := []cdx.Property{{Name: aiPropPrefix + "type", Value: f.Category}}
				if provider != "" {
					props = append(props, cdx.Property{Name: aiPropPrefix + "provider", Value: provider})
				}
				if services["svc:"+provider] != nil {
					props = append(props, cdx.Property{Name: aiPropPrefix + "service", Value: "svc:" + provider})
				}
				c.Properties = &props
				models[ref] = c
			}
			line := f.Line
			*c.Evidence.Occurrences = append(*c.Evidence.Occurrences, cdx.EvidenceOccurrence{Location: f.File, Line: &line})
			refs = append(refs, ref)
		}
		risk := metaString(meta, "risk")
		if risk == "" || strings.EqualFold(risk, "info") {
			continue
		}
		v := vulns[f.RuleID]
		if v == nil {
			v = &cdx.Vulnerability{
				ID:         aiVulnerabilityID(f.RuleID),
				Source:     &cdx.Source{Name: "SCANOSS"},
				Ratings:    &[]cdx.VulnerabilityRating{{Severity: mapSeverity(risk), Method: cdx.ScoringMethodOther}},
				Affects:    &[]cdx.Affects{},
				Properties: &[]cdx.Property{{Name: aiPropPrefix + "rule", Value: f.RuleID}},
			}
			if cwes := aiCWEs(meta["cwe"]); len(cwes) > 0 {
				v.CWEs = &cwes
			}
			if owasp := metaString(meta, "owasp"); owasp != "" {
				*v.Properties = append(*v.Properties, cdx.Property{Name: aiPropPrefix + "owasp", Value: owasp})
			}
			vulns[f.RuleID] = v
		}
		if len(refs) == 0 {
			refs = []string{projectRef}
		}
		for _, ref := range refs {
			addAffects(v, ref)
		}
		// One per finding: where the risk is and whether that code runs.
		*v.Properties = append(*v.Properties, cdx.Property{Name: aiPropPrefix + "location", Value: f.File + ":" + strconv.Itoa(f.Line) + " " + f.Reachability})
	}
	if len(services) > 0 {
		list := make([]cdx.Service, 0, len(services))
		for _, ref := range sortedKeys(services) {
			list = append(list, *services[ref])
		}
		bom.Services = &list
	}
	comps := []cdx.Component{}
	if bom.Components != nil {
		comps = *bom.Components
	}
	for _, ref := range sortedKeys(models) {
		comps = append(comps, *models[ref])
	}
	bom.Components = &comps
	if len(vulns) > 0 {
		list := []cdx.Vulnerability{}
		if bom.Vulnerabilities != nil {
			list = *bom.Vulnerabilities
		}
		for _, id := range sortedKeys(vulns) {
			list = append(list, *vulns[id])
		}
		bom.Vulnerabilities = &list
	}
}

// aiVulnerabilityID names the risk a rule reports, e.g. SCANOSS-AI-MODEL-LOAD-TORCH-LOAD.
func aiVulnerabilityID(ruleID string) string {
	return "SCANOSS-" + strings.ToUpper(strings.NewReplacer(".", "-", "_", "-").Replace(ruleID))
}

// aiCWEs reads a cwe list ("CWE-94", 94) as numbers.
func aiCWEs(v any) []int {
	list, _ := v.([]any)
	var out []int
	for _, item := range list {
		s := strings.TrimPrefix(strings.ToUpper(fmt.Sprint(item)), "CWE-")
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func addAffects(v *cdx.Vulnerability, ref string) {
	for _, a := range *v.Affects {
		if a.Ref == ref {
			return
		}
	}
	*v.Affects = append(*v.Affects, cdx.Affects{Ref: ref})
}

func metaString(meta map[string]any, key string) string {
	s, _ := meta[key].(string)
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
