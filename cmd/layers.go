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
	"sort"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

// Layer is a value of the --include flag. Layers are the CLI's vocabulary, not the pipeline's:
// "vulns" is what a user types, whereas the pipeline is handed the vulnerabilities service and
// never learns that a flag was involved. Keeping the two apart is what lets the flag names change
// without touching the pipeline, and the pipeline serve callers that have no flags at all.
type Layer string

// Supported --include values.
const (
	LayerDeps     Layer = "deps"
	LayerVulns    Layer = "vulns"
	LayerLicenses Layer = "licenses"
	LayerCrypto   Layer = "crypto"
	LayerGeo      Layer = "geo"
	// LayerAI is the AI usage in the scanned source, found locally by matching AI rules
	// against its call graph.
	LayerAI Layer = "ai"
)

// layerServices maps each enrichment layer to the API service that gathers it. It is the single
// declaration of which layers exist: ParseLayers validates against it, its error message is built
// from it, and servicesFor turns a request into the service list the pipeline runs. Adding a layer
// is one entry here.
//
// LayerDeps has no entry: declared dependencies are sourced from the parsed manifests during
// collection, not fetched from a decoration service.
var layerServices = map[Layer]scanoss.Service{
	LayerVulns:    scanoss.ServiceVulnerabilities,
	LayerLicenses: scanoss.ServiceLicenses,
	LayerCrypto:   scanoss.ServiceCryptographyAlgorithms,
	LayerGeo:      scanoss.ServiceGeoprovenanceOrigin,
}

// Set is a set of requested layers.
type Set map[Layer]bool

// Has reports whether the layer was requested.
func (s Set) Has(l Layer) bool { return s[l] }

// ParseLayers validates a list of --include values into a Set, accepting only the layers the
// calling command can gather.
//
// The accepted set is a parameter rather than the full list of layers the CLI knows, because a
// command that names a layer as valid and then refuses it has told the user two different things
// — and the second one arrives only after they tried it.
func ParseLayers(values []string, accepted []Layer) (Set, error) {
	allowed := make(Set, len(accepted))
	for _, l := range accepted {
		allowed[l] = true
	}

	set := make(Set, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		l := Layer(v)
		if !allowed[l] {
			return nil, fmt.Errorf("unknown --include layer %q (valid: %s)", v, layerList(accepted))
		}
		set[l] = true
	}
	return set, nil
}

// AllLayers is every layer a user may request: the PURL-keyed ones plus the two read from the
// scanned tree, declared dependencies and AI usage.
func AllLayers() []Layer {
	return append(PurlLayers(), LayerDeps, LayerAI)
}

// PurlLayers are the layers gathered from a decoration service keyed by PURL, so they can be
// gathered over any component list — including one parsed from an SBOM file, with no scanned tree
// behind it.
//
// LayerDeps is not among them: declared dependencies are read from the manifests in the tree that
// was scanned, which an inventory on its own does not carry.
func PurlLayers() []Layer {
	out := make([]Layer, 0, len(layerServices))
	for l := range layerServices {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// layerList names the given layers for an error message. Sorted because ranging a map is
// randomised, and an error whose wording reshuffles between runs is a bad error.
func layerList(layers []Layer) string {
	names := make([]string, 0, len(layers))
	for _, l := range layers {
		names = append(names, string(l))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// servicesFor translates requested layers into the decoration services the pipeline should run.
// This is the whole of what the pipeline needs to know about --include.
func servicesFor(layers Set) []scanoss.Service {
	requested := make([]Layer, 0, len(layerServices))
	for l := range layerServices {
		if layers.Has(l) {
			requested = append(requested, l)
		}
	}
	// Sorted so the services are requested the same way on every run.
	sort.Slice(requested, func(i, j int) bool { return requested[i] < requested[j] })

	out := make([]scanoss.Service, 0, len(requested))
	for _, l := range requested {
		out = append(out, layerServices[l])
	}
	return out
}
