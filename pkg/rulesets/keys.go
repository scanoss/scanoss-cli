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
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// PubKeysEnv adds trusted lease signing keys, or replaces built-in ones of the
// same id: "id:base64pub[,id:base64pub...]".
const PubKeysEnv = "SCANOSS_RULESET_PUBKEYS"

// builtinKeys are the API's lease signing public keys (raw Ed25519, base64) by
// key id. The production key is added here once it is published.
var builtinKeys = map[string]string{}

// TrustedKeys returns the built-in keys plus those in PubKeysEnv.
func TrustedKeys() (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(builtinKeys))
	for id, b64 := range builtinKeys {
		pub, err := decodeKey(b64)
		if err != nil {
			return nil, fmt.Errorf("built-in ruleset key %q: %w", id, err)
		}
		keys[id] = pub
	}
	extra, err := ParsePublicKeys(os.Getenv(PubKeysEnv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", PubKeysEnv, err)
	}
	for id, pub := range extra {
		keys[id] = pub
	}
	return keys, nil
}

// ParsePublicKeys parses "id:base64pub[,id:base64pub...]"; empty yields none.
func ParsePublicKeys(s string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, b64, ok := strings.Cut(item, ":")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, fmt.Errorf("%q is not id:base64-public-key", item)
		}
		pub, err := decodeKey(strings.TrimSpace(b64))
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		keys[id] = pub
	}
	return keys, nil
}

func decodeKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
