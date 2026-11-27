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
	"errors"
	"fmt"
	"net/http"
)

// ExitCode is the CLI exit code for "rules unavailable": any error that
// matches ErrUnavailable.
const ExitCode = 3

var (
	// ErrUnavailable is matched by every error Fetch, List and Release return,
	// so a command maps it to ExitCode with one errors.Is.
	ErrUnavailable = errors.New("rules unavailable")
	// ErrUpgradeRequired is the API refusing this client version (HTTP 410 or 426).
	ErrUpgradeRequired = errors.New("upgrade_required: the rulesets API no longer serves this client version, upgrade scanoss-cli")
	// ErrChecksum is a bundle whose SHA-256 differs from X-Checksum-SHA256 or the lease.
	ErrChecksum = errors.New("ruleset bundle checksum mismatch")
	// ErrSignature is a lease whose Ed25519 signature does not verify.
	ErrSignature = errors.New("ruleset lease signature does not verify")
	// ErrUnknownKey is a lease signed by a key that is not trusted.
	ErrUnknownKey = errors.New("ruleset lease signed by an untrusted key")
	// ErrLeaseExpired is a lease past its expires_at.
	ErrLeaseExpired = errors.New("ruleset lease has expired")
	// ErrBadLease is a lease that is malformed or does not describe the bundle requested.
	ErrBadLease = errors.New("invalid ruleset lease")
	// ErrNoTrustedKeys means neither the built-in list nor PubKeysEnv holds a key.
	ErrNoTrustedKeys = errors.New("no trusted ruleset signing keys (set " + PubKeysEnv + ")")
)

// StatusError is a non-2xx answer from the rulesets API. Code and Message come
// from the API's JSON error body when it sent one.
type StatusError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *StatusError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("rulesets API returned %d %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("rulesets API returned %d", e.StatusCode)
}

// Unwrap makes 410 and 426 match ErrUpgradeRequired.
func (e *StatusError) Unwrap() error {
	if e.StatusCode == http.StatusGone || e.StatusCode == http.StatusUpgradeRequired {
		return ErrUpgradeRequired
	}
	return nil
}

// unreachable says whether err means the API could not answer, the only case
// in which a stale cache may stand in for it.
func unreachable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.StatusCode >= 500 || se.StatusCode == http.StatusTooManyRequests
	}
	var ne *networkError
	return errors.As(err, &ne)
}

// networkError is a request that got no HTTP response at all.
type networkError struct{ err error }

func (e *networkError) Error() string { return "rulesets API unreachable: " + e.err.Error() }
func (e *networkError) Unwrap() error { return e.err }

func unavailable(name, version string, err error) error {
	return fmt.Errorf("%w: %s@%s: %w", ErrUnavailable, name, version, err)
}
