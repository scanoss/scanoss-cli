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
	"encoding/json"
	"fmt"
)

// RawSchemaVersion is the version of the raw inventory document. Bump the major on a breaking
// shape change and the minor on an additive one, so a reader can tell which documents it has to
// handle differently from which merely carry more than it knows about.
//
// 2.1 added the `dependencies` roots, `local` on a component and the `transitive` match type.
const RawSchemaVersion = "2.1"

// RawDocument is the raw output format: an Inventory wrapped in a versioned envelope. The embedded
// Inventory promotes its `components`/`vulnerabilities` keys to the top level, so the JSON is
// `{schema_version, metadata, components, vulnerabilities}` — the neutral interchange contract for
// the scan → enrich → convert pipe. It is the raw counterpart to the CycloneDX/SPDX documents that
// Generate produces, kept here so a single definition serves both the writer and the reader.
type RawDocument struct {
	SchemaVersion string      `json:"schema_version"`
	Metadata      RawMetadata `json:"metadata"`
	Inventory
}

// RawMetadata identifies the tool and project that produced a raw document. Values are supplied by
// the caller (the CLI), so pkg/sbom carries no application identity of its own.
type RawMetadata struct {
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	Project     string `json:"project,omitempty"`
}

// NewRawDocument wraps inv in a raw envelope stamped with the current schema version and the given
// metadata.
func NewRawDocument(inv Inventory, meta RawMetadata) RawDocument {
	// A scan that matched nothing must still emit `"components": []`, not null:
	// a nil slice marshals to null, and a consumer then has to special-case it
	// before ranging over the field. "No components" is an empty list, not the
	// absence of an answer.
	// (Vulnerabilities needs no such guard: it is omitempty, so nil and empty
	// both disappear from the output.)
	if inv.Components == nil {
		inv.Components = []Component{}
	}
	return RawDocument{SchemaVersion: RawSchemaVersion, Metadata: meta, Inventory: inv}
}

// Marshal renders the raw document as indented JSON — the raw-format counterpart to Generate.
func (d RawDocument) Marshal() (string, error) {
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ParseRaw reads a raw inventory document back into an Inventory. Any envelope fields
// (schema_version, metadata) are accepted and ignored; a bare `{components, vulnerabilities}`
// object parses too. To be recognized as an inventory the input must carry a `schema_version` or a
// `components` key — arbitrary JSON that has neither is rejected. A v3 scan result (whose
// `components` are an object keyed by url_hash, not an array) also fails and returns an error.
func ParseRaw(data []byte) (Inventory, error) {
	var probe struct {
		SchemaVersion string          `json:"schema_version"`
		Components    json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Inventory{}, err
	}
	if probe.SchemaVersion == "" && probe.Components == nil {
		return Inventory{}, fmt.Errorf("not a scanoss raw inventory (no schema_version or components)")
	}
	var doc RawDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return Inventory{}, err
	}
	return doc.Inventory, nil
}
