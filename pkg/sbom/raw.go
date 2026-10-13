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

// RawSchemaVersion is the version of the raw inventory document. Bump on a breaking shape change.
const RawSchemaVersion = "2.0"

// RawDocument is the raw output format: an Inventory wrapped in a versioned envelope. The embedded
// Inventory promotes its `components`/`vulnerabilities` keys to the top level, so the JSON is
// `{schema_version, metadata, components, vulnerabilities}` — the neutral interchange contract for
// the scan → enrich → convert pipe. It is the raw counterpart to the CycloneDX/SPDX documents that
// Generate produces, kept here so a single definition serves both the writer and the reader.
type RawDocument struct {
	SchemaVersion string      `json:"schema_version"`
	Metadata      RawMetadata `json:"metadata"`
	// Server is the batchScanner report's `server` block: the engine and Knowledge Base versions the
	// scan ran against. It is a pointer with omitempty so a report that carries no `server` (any API
	// that does not emit one) leaves the output byte-for-byte unchanged. Placed between the envelope
	// and the promoted inventory keys, it mirrors the batch report's own `{..., server, components}`.
	Server *RawServer `json:"server,omitempty"`
	Inventory
}

// RawServer is the run/server metadata a batchScanner report carries in its `server` block. It is
// provenance for the match results — it records which engine and Knowledge Base produced them — so
// it travels on the raw document beside the components rather than inside the inventory, and is
// omitted entirely when the scan report carried no such block.
//
// EngineVersion and KnowledgeBaseLatest await the scanoss.api-sdk release that models them; until
// then they stay empty (and, being omitempty, absent from the output). The rest mirror what the
// current SDK's ScanServer exposes.
type RawServer struct {
	// EngineVersion is the SCANOSS engine build the scan ran on, e.g. "6.0.1-crc64".
	EngineVersion string `json:"engine_version,omitempty"`
	// KnowledgeBase is the Knowledge Base version the scan matched against.
	KnowledgeBase *RawKnowledgeBase `json:"knowledge_base,omitempty"`
	// KnowledgeBaseLatest, when present, is the newest Knowledge Base the server holds. It appears
	// only when it diverges from KnowledgeBase — i.e. the scan ran against an older KB than available.
	KnowledgeBaseLatest *RawKnowledgeBase `json:"knowledge_base_latest,omitempty"`
	// APIVersion is the batchScanner API version that produced the report.
	APIVersion string `json:"api_version,omitempty"`
	// Hostname is the host that ran the scan.
	Hostname string `json:"hostname,omitempty"`
	// ElapsedMs is the scan wall-clock time in milliseconds.
	ElapsedMs int `json:"elapsed_ms,omitempty"`
}

// RawKnowledgeBase is a Knowledge Base version pair: the monthly snapshot and the daily delta
// applied on top of it.
type RawKnowledgeBase struct {
	MonthlyVersion string `json:"monthly_version,omitempty"`
	DailyVersion   string `json:"daily_version,omitempty"`
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
