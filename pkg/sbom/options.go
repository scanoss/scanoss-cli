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
	"time"

	"github.com/scanoss/scanoss.go/internal/config"
)

// defaultProjectName names the top-level component / document when none is supplied.
const defaultProjectName = "scanoss-project"

// options holds the resolved per-call configuration.
type options struct {
	projectName string
	toolName    string    // recorded as the generating tool in document metadata
	toolVersion string    // its version, kept apart: CycloneDX has a field for it
	author      string    // recorded as the author / organization in document metadata
	timestamp   time.Time // document creation timestamp; zero => resolved to now at render
	aiUsage     *AIUsage  // AI usage to render (CycloneDX only); nil for none
}

// Option configures SBOM generation.
type Option func(*options)

// WithProjectName sets the name of the top-level project component (CycloneDX) /
// document (SPDX). Empty values are ignored and the default is kept.
func WithProjectName(name string) Option {
	return func(o *options) {
		if name != "" {
			o.projectName = name
		}
	}
}

// WithTool sets the generating tool recorded in the document metadata. The value
// is taken literally: a caller passing "my-tool-1.4.0" gets exactly that, with no
// version appended. Pass WithToolVersion as well to have CycloneDX record the
// version in its own field.
func WithTool(name string) Option {
	return func(o *options) {
		if name != "" {
			o.toolName = name
			o.toolVersion = "" // the caller owns the identifier now
		}
	}
}

// WithToolVersion sets the version recorded alongside the tool name. Empty leaves
// the default. CycloneDX records it in its own field; SPDX has no such field, so
// there the two are joined as "name-version", which is that format's convention.
func WithToolVersion(version string) Option {
	return func(o *options) {
		if version != "" {
			o.toolVersion = version
		}
	}
}

// toolIdentifier is the SPDX "Tool:" creator string, where name and version are
// one value by convention.
func (o options) toolIdentifier() string {
	if o.toolVersion == "" {
		return o.toolName
	}
	return o.toolName + "-" + o.toolVersion
}

// WithAuthor sets the author / organization recorded in the document metadata. Empty
// values are ignored (default: the SCANOSS organization name).
func WithAuthor(name string) Option {
	return func(o *options) {
		if name != "" {
			o.author = name
		}
	}
}

// WithTimestamp sets the document creation timestamp (e.g. a point-in-time snapshot time,
// or a fixed value for reproducible output). The zero time is ignored and the current time
// is used at render.
func WithTimestamp(t time.Time) Option {
	return func(o *options) {
		if !t.IsZero() {
			o.timestamp = t
		}
	}
}

func newOptions(opts ...Option) options {
	o := options{
		projectName: defaultProjectName,
		toolName:    config.AppName,
		toolVersion: config.AppVersion,
		author:      config.OrganizationName,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// resolvedTimestamp returns the configured timestamp, or the current UTC time when none
// was supplied.
func (o options) resolvedTimestamp() time.Time {
	if o.timestamp.IsZero() {
		return time.Now().UTC()
	}
	return o.timestamp
}

// WithAIUsage adds an AI usage report to a CycloneDX document: providers as services, models as
// machine-learning-model components and risks as vulnerabilities. SPDX ignores it.
func WithAIUsage(u *AIUsage) Option {
	return func(o *options) { o.aiUsage = u }
}
