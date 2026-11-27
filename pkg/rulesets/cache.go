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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cache freshness: how long a cached ruleset is used without asking the API,
// and how old it may be when the API is unreachable.
const (
	TTLLatest = 24 * time.Hour
	TTLPinned = 7 * 24 * time.Hour
	MaxStale  = 30 * 24 * time.Hour
)

// Files in <cache>/<host>/<name>/<version>/.
const (
	bundleFile = "bundle.enc"
	leaseFile  = "lease.json"
	metaFile   = ".cache-meta.json"

	metaFormat = "scanoss-cli-ruleset-cache/1"
	encMagic   = "SCRB\x01"
	saltSize   = 16
)

// cacheMeta is .cache-meta.json.
type cacheMeta struct {
	Format         string    `json:"format"`
	Name           string    `json:"name"`
	Requested      string    `json:"requested_version"`
	Version        string    `json:"version"`
	PayloadSHA256  string    `json:"payload_sha256"`
	BundleSHA256   string    `json:"bundle_sha256"`
	FetchedAt      time.Time `json:"fetched_at"`
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
	SigningKeyID   string    `json:"signing_key_id"`
}

// cacheEntry is a cached ruleset whose lease and bundle verified.
type cacheEntry struct {
	meta   cacheMeta
	lease  Lease
	bundle []byte
}

func ttl(version string) time.Duration {
	if version == latest {
		return TTLLatest
	}
	return TTLPinned
}

func (c *Client) cachePath(name, version string) string {
	host := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(c.base.Host)
	return filepath.Join(c.opts.CacheDir, host, name, version)
}

// readCache loads and fully verifies the cached name@version. A missing entry
// returns os.ErrNotExist; an expired lease returns ErrLeaseExpired.
func (c *Client) readCache(name, version string) (*cacheEntry, error) {
	dir := c.cachePath(name, version)
	metaJSON, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return nil, err
	}
	var meta cacheMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil || meta.Format != metaFormat {
		return nil, fmt.Errorf("cache metadata unreadable: %v", err)
	}
	envJSON, err := os.ReadFile(filepath.Join(dir, leaseFile))
	if err != nil {
		return nil, err
	}
	l, err := parseLease(envJSON, c.keys)
	if err != nil {
		return nil, err
	}
	sealed, err := os.ReadFile(filepath.Join(dir, bundleFile))
	if err != nil {
		return nil, err
	}
	bundle, err := c.decrypt(sealed, c.aad(name, version))
	if err != nil {
		return nil, err
	}
	if err := l.check(name, version, bundle, c.now()); err != nil {
		return nil, err
	}
	return &cacheEntry{meta: meta, lease: l, bundle: bundle}, nil
}

// writeCache stores a verified download; the metadata goes last so a partial
// write never looks complete.
func (c *Client) writeCache(name, version string, bundle, envJSON []byte, l Lease) error {
	dir := c.cachePath(name, version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sealed, err := c.encrypt(bundle, c.aad(name, version))
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, bundleFile), sealed); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, leaseFile), envJSON); err != nil {
		return err
	}
	return c.writeMeta(dir, cacheMeta{
		Format: metaFormat, Name: name, Requested: version, Version: l.Version,
		PayloadSHA256: l.PayloadSHA256, BundleSHA256: l.BundleSHA256,
		FetchedAt: c.now().UTC(), LeaseExpiresAt: l.ExpiresAt, SigningKeyID: l.SigningKeyID,
	})
}

func (c *Client) writeMeta(dir string, meta cacheMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, metaFile), data)
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// aad binds a sealed bundle to its API host, name and requested version.
func (c *Client) aad(name, version string) []byte {
	return []byte("scanoss-cli/rulesets/bundle/1\x00" + c.base.Host + "\x00" + c.opts.Domain + "\x00" + name + "\x00" + version)
}

// encrypt seals plain with AES-256-GCM under HKDF-SHA256(api key, salt, aad):
// magic | salt | nonce | ciphertext.
func (c *Client) encrypt(plain, aad []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	gcm, err := c.cipher(salt, aad)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(encMagic), salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, aad), nil
}

// errDecrypt covers a corrupt bundle.enc and one sealed under another API key.
var errDecrypt = errors.New("cached bundle cannot be decrypted (corrupt, or sealed with another API key)")

func (c *Client) decrypt(sealed, aad []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, []byte(encMagic)) || len(sealed) < len(encMagic)+saltSize {
		return nil, errDecrypt
	}
	rest := sealed[len(encMagic):]
	gcm, err := c.cipher(rest[:saltSize], aad)
	if err != nil {
		return nil, err
	}
	rest = rest[saltSize:]
	if len(rest) < gcm.NonceSize() {
		return nil, errDecrypt
	}
	plain, err := gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], aad)
	if err != nil {
		return nil, errDecrypt
	}
	return plain, nil
}

func (c *Client) cipher(salt, aad []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(c.opts.APIKey), salt, string(aad), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
