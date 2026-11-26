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

package scanoss

import (
	"context"
	"encoding/json"
	"fmt"

	scanossapi "github.com/scanoss/scanoss.api-sdk"
)

// Remediation Intelligence endpoints: what to do about each component version (risk band, what
// limits it, ranked upgrade, replace or remove actions), as a batch (POST) and a single (GET)
// endpoint on the same path.
var (
	ServiceRemediation = Service{Name: "remediation", endpoint: "/v3/remediation/intelligence"}
	serviceRemediation = Service{Name: "remediation.single", endpoint: "/v3/remediation/intelligence"}
)

// RemediationAPI is the Remediation Intelligence service surface.
//
// Remediation Intelligence answers for exact versions only: a component needs a version in its
// PURL (pkg:npm/left-pad@1.3.0) or an exact Requirement. A range comes back VERSION_NOT_FOUND.
type RemediationAPI interface {
	Components(ctx context.Context, comps []Component, opts ...DecorateOption) (*scanossapi.RemediationResponse, error)
	Component(ctx context.Context, comp Component, opts ...DecorateOption) (*scanossapi.RemediationResponse, error)
}

type remediationService struct{ c *Client }

var _ RemediationAPI = remediationService{}

// Components returns the Remediation Intelligence answer for the given components (batch).
func (s remediationService) Components(ctx context.Context, comps []Component, opts ...DecorateOption) (*scanossapi.RemediationResponse, error) {
	res, err := s.c.decorate(ctx, ServiceRemediation, comps, opts...)
	if err != nil {
		return nil, err
	}
	out, err := remediationFrom(res.responses)
	if err != nil {
		return nil, err
	}
	out.Components = inRequestOrder(comps, out.Components)
	return out, nil
}

// Component returns the Remediation Intelligence answer for a single component.
func (s remediationService) Component(ctx context.Context, comp Component, opts ...DecorateOption) (*scanossapi.RemediationResponse, error) {
	res, err := s.c.decorateOne(ctx, serviceRemediation, comp, opts...)
	if err != nil {
		return nil, err
	}
	return remediationFrom(res.responses)
}

// remediationFrom combines the chunk responses of one query. The generic merge keeps the last
// chunk's scalars, which is wrong here twice over: data_as_of is the oldest of each date over the
// hits, and the status counts the hits of the whole query, not of one chunk.
func remediationFrom(responses []json.RawMessage) (*scanossapi.RemediationResponse, error) {
	out := &scanossapi.RemediationResponse{Components: []scanossapi.ComponentRemediationInfo{}}
	for _, raw := range responses {
		var r scanossapi.RemediationResponse
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("decoding the remediation response: %w", err)
		}
		out.Components = append(out.Components, r.Components...)
		out.DataAsOf = oldestDataAsOf(out.DataAsOf, r.DataAsOf)
		if len(responses) == 1 {
			out.Status = r.Status
		}
	}
	if len(responses) > 1 {
		out.Status = remediationStatus(out.Components)
	}
	return out, nil
}

// remediationStatus is the batch status the API gives one request, over every chunk: a hit is an
// entry with no info_code.
func remediationStatus(comps []scanossapi.ComponentRemediationInfo) scanossapi.BatchStatus {
	hits := 0
	for _, c := range comps {
		if c.InfoCode == nil {
			hits++
		}
	}
	st := scanossapi.BatchStatus{Message: fmt.Sprintf("Resolved %d of %d purls", hits, len(comps))}
	switch {
	case hits == len(comps):
		st.Status = scanossapi.BatchStatusStatusSUCCESS
	case hits == 0:
		st.Status = scanossapi.BatchStatusStatusERROR
	default:
		st.Status = scanossapi.BatchStatusStatusPARTIALSUCCESS
	}
	return st
}

// oldestDataAsOf keeps the oldest of each date. A nil side is a chunk with no hits, which says
// nothing about freshness.
func oldestDataAsOf(a, b *scanossapi.DataAsOf) *scanossapi.DataAsOf {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := *a
	if b.ScoredAt != nil && (out.ScoredAt == nil || b.ScoredAt.Before(*out.ScoredAt)) {
		out.ScoredAt = b.ScoredAt
	}
	if b.KevSnapshot != nil && (out.KevSnapshot == nil || b.KevSnapshot.Before(out.KevSnapshot.Time)) {
		out.KevSnapshot = b.KevSnapshot
	}
	if b.EpssSnapshot != nil && (out.EpssSnapshot == nil || b.EpssSnapshot.Before(out.EpssSnapshot.Time)) {
		out.EpssSnapshot = b.EpssSnapshot
	}
	return &out
}

// inRequestOrder puts the entries back in the order they were asked for. Chunks are answered
// concurrently and collected as they finish, while the API keeps request order within a request,
// so a caller reading the batch positionally would otherwise read it shuffled. Each entry echoes
// its purl and requirement; repeated components are matched in turn, and an entry that matches
// none is kept at the end.
func inRequestOrder(comps []Component, entries []scanossapi.ComponentRemediationInfo) []scanossapi.ComponentRemediationInfo {
	pending := make(map[string][]int, len(entries))
	for i, e := range entries {
		k := e.Purl + "\x00" + derefString(e.Requirement)
		pending[k] = append(pending[k], i)
	}
	out := make([]scanossapi.ComponentRemediationInfo, 0, len(entries))
	used := make([]bool, len(entries))
	for _, c := range comps {
		k := c.Purl + "\x00" + c.Requirement
		if idx := pending[k]; len(idx) > 0 {
			out = append(out, entries[idx[0]])
			used[idx[0]] = true
			pending[k] = idx[1:]
		}
	}
	for i, e := range entries {
		if !used[i] {
			out = append(out, e)
		}
	}
	return out
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
