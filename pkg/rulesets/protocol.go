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

package rulesets

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Wire formats and headers of the rulesets API.
const (
	ReleaseFormat  = "scanoss-ruleset-release/1"
	LeaseFormat    = "scanoss-ruleset-lease/1"
	LeaseHeader    = "SCANOSS-Ruleset-Lease"
	ChecksumHeader = "X-Checksum-SHA256"
)

// Summary is one entry of GET /v3/<domain>/rulesets.
type Summary struct {
	Name     string   `json:"name"`
	Domain   string   `json:"domain"`
	Latest   string   `json:"latest"`
	Versions []string `json:"versions"`
}

// Release is GET /v3/<domain>/rulesets/{name}/{version}.
type Release struct {
	Format        string    `json:"format"`
	Name          string    `json:"name"`
	Domain        string    `json:"domain"`
	Version       string    `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	Description   string    `json:"description,omitempty"`
	PayloadSHA256 string    `json:"payload_sha256"`
	PayloadSize   int64     `json:"payload_size"`
}

// Lease is the signed grant that comes with a downloaded bundle.
type Lease struct {
	Format        string    `json:"format"`
	Name          string    `json:"name"`
	Domain        string    `json:"domain"`
	Version       string    `json:"version"`
	PayloadSHA256 string    `json:"payload_sha256"`
	BundleSHA256  string    `json:"bundle_sha256"`
	KeyRef        string    `json:"key_ref,omitempty"`
	Tenant        string    `json:"tenant,omitempty"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	SigningKeyID  string    `json:"signing_key_id"`
}

// envelope is the JSON inside LeaseHeader (after base64). The signature
// covers the lease bytes exactly as sent, so they are kept raw.
type envelope struct {
	Format    string `json:"format"`
	Lease     []byte `json:"lease"`
	Signature []byte `json:"signature"`
}

// parseLease decodes an envelope and verifies its signature against keys.
func parseLease(data []byte, keys map[string]ed25519.PublicKey) (Lease, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Lease{}, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	var l Lease
	if err := json.Unmarshal(env.Lease, &l); err != nil {
		return Lease{}, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	if env.Format != LeaseFormat || l.Format != LeaseFormat {
		return Lease{}, fmt.Errorf("%w: format %q", ErrBadLease, env.Format)
	}
	if len(keys) == 0 {
		return Lease{}, ErrNoTrustedKeys
	}
	pub, ok := keys[l.SigningKeyID]
	if !ok {
		return Lease{}, fmt.Errorf("%w: %q", ErrUnknownKey, l.SigningKeyID)
	}
	if !ed25519.Verify(pub, env.Lease, env.Signature) {
		return Lease{}, ErrSignature
	}
	return l, nil
}

// check verifies that l is current, covers bundle and is for name and, unless
// "latest" was asked for, for version.
func (l Lease) check(name, version string, bundle []byte, now time.Time) error {
	if l.Name != name {
		return fmt.Errorf("%w: issued for %q, not %q", ErrBadLease, l.Name, name)
	}
	if version != latest && l.Version != version {
		return fmt.Errorf("%w: issued for version %q, not %q", ErrBadLease, l.Version, version)
	}
	if !now.Before(l.ExpiresAt) {
		return fmt.Errorf("%w: %s", ErrLeaseExpired, l.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if sha256Hex(bundle) != l.BundleSHA256 {
		return fmt.Errorf("%w: bundle does not match the lease", ErrChecksum)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
