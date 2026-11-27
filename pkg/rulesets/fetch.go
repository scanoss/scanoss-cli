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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/scanoss/scanoss.go/internal/logging"
)

// Source says where a fetched ruleset came from.
type Source string

const (
	// SourceNetwork is a bundle downloaded in this call.
	SourceNetwork Source = "network"
	// SourceCache is a cached bundle within its TTL.
	SourceCache Source = "cache"
	// SourceRevalidated is a cached bundle past its TTL that the API confirmed current.
	SourceRevalidated Source = "revalidated"
	// SourceStale is a cached bundle past its TTL, used because the API was unreachable.
	SourceStale Source = "stale"
)

// Ruleset is a verified ruleset unpacked into Dir. Close removes Dir.
type Ruleset struct {
	Name      string
	Version   string // resolved, never "latest"
	Requested string // as asked for, e.g. "latest"
	Dir       string
	Lease     Lease
	Source    Source
	// FetchedAt is when the bundle was downloaded (now, or when it was cached).
	FetchedAt time.Time
}

// Close removes the run directory.
func (r *Ruleset) Close() error {
	if r == nil || r.Dir == "" {
		return nil
	}
	err := os.RemoveAll(r.Dir)
	r.Dir = ""
	return err
}

// Fetch returns name@version ("latest" or a semver version), from the cache
// when it is fresh, otherwise from the API, falling back to a cached copy up
// to MaxStale old when the API is unreachable. Every error matches
// ErrUnavailable.
func (c *Client) Fetch(ctx context.Context, name, version string) (*Ruleset, error) {
	if err := validateRef(name, version); err != nil {
		return nil, unavailable(name, version, err)
	}
	now := c.now()
	var cached *cacheEntry
	var cacheErr error
	if !c.opts.NoCache {
		cached, cacheErr = c.readCache(name, version)
		if cacheErr != nil && !errors.Is(cacheErr, fs.ErrNotExist) {
			logging.Debug("ruleset cache not usable", "ruleset", name+"@"+version, "err", cacheErr)
		}
	}
	if cached != nil {
		age := now.Sub(cached.meta.FetchedAt)
		if age >= 0 && age < ttl(version) {
			return c.open(name, version, cached.bundle, cached.lease, SourceCache, cached.meta.FetchedAt)
		}
		rs, err := c.revalidate(ctx, name, version, cached)
		if rs != nil || err == nil {
			return rs, err
		}
		if !unreachable(err) {
			return nil, unavailable(name, version, err)
		}
		return c.stale(name, version, cached, err)
	}

	bundle, envJSON, l, err := c.download(ctx, name, version)
	if err != nil {
		if errors.Is(cacheErr, ErrLeaseExpired) {
			err = fmt.Errorf("%w (cached copy: %w)", err, cacheErr)
		}
		return nil, unavailable(name, version, err)
	}
	if !c.opts.NoCache {
		if werr := c.writeCache(name, version, bundle, envJSON, l); werr != nil {
			logging.Warn("could not cache ruleset", "ruleset", name+"@"+version, "err", werr)
		}
	}
	return c.open(name, version, bundle, l, SourceNetwork, now)
}

// revalidate handles a cached entry past its TTL: if the API still serves
// the same release and the cached lease outlives another TTL, the cache is
// renewed without a download; otherwise the bundle is downloaded again. It
// returns (nil, err) when the API could not be asked.
func (c *Client) revalidate(ctx context.Context, name, version string, cached *cacheEntry) (*Ruleset, error) {
	now := c.now()
	rel, err := c.release(ctx, name, version)
	if err != nil {
		return nil, err
	}
	if rel.Version == cached.lease.Version && rel.PayloadSHA256 == cached.lease.PayloadSHA256 &&
		cached.lease.ExpiresAt.Sub(now) > ttl(version) {
		meta := cached.meta
		meta.FetchedAt = now.UTC()
		if werr := c.writeMeta(c.cachePath(name, version), meta); werr != nil {
			logging.Warn("could not update ruleset cache", "ruleset", name+"@"+version, "err", werr)
		}
		return c.open(name, version, cached.bundle, cached.lease, SourceRevalidated, now)
	}
	bundle, envJSON, l, err := c.download(ctx, name, version)
	if err != nil {
		return nil, err
	}
	if werr := c.writeCache(name, version, bundle, envJSON, l); werr != nil {
		logging.Warn("could not cache ruleset", "ruleset", name+"@"+version, "err", werr)
	}
	return c.open(name, version, bundle, l, SourceNetwork, now)
}

// stale uses a cached entry while the API is unreachable, up to MaxStale.
func (c *Client) stale(name, version string, cached *cacheEntry, apiErr error) (*Ruleset, error) {
	if age := c.now().Sub(cached.meta.FetchedAt); age > MaxStale {
		return nil, unavailable(name, version, fmt.Errorf("%w; cached copy is %s old, more than %s", apiErr, age.Round(time.Hour), MaxStale))
	}
	logging.Warn("rulesets API unreachable, using cached ruleset",
		"ruleset", name+"@"+cached.lease.Version, "fetched_at", cached.meta.FetchedAt.Format(time.RFC3339), "err", apiErr)
	return c.open(name, version, cached.bundle, cached.lease, SourceStale, cached.meta.FetchedAt)
}

// open unpacks a verified bundle into a new 0700 run-* directory.
func (c *Client) open(name, requested string, bundle []byte, l Lease, src Source, fetchedAt time.Time) (*Ruleset, error) {
	dir, err := os.MkdirTemp(c.opts.RunDir, "run-*")
	if err != nil {
		return nil, unavailable(name, requested, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, unavailable(name, requested, err)
	}
	if err := extractTarGz(bundle, dir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, unavailable(name, requested, err)
	}
	return &Ruleset{Name: name, Version: l.Version, Requested: requested, Dir: dir, Lease: l, Source: src, FetchedAt: fetchedAt}, nil
}

// extractTarGz writes the regular files and directories of a tar.gz under
// dir. Links, devices and names leaving dir are refused.
func extractTarGz(data []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("bundle is not gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("bundle is not a tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			// git archive writes one; it carries metadata, not a file.
			continue
		}
		rel := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if rel == "." {
			continue
		}
		if path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(hdr.Name, "\\") {
			return fmt.Errorf("bundle entry %q leaves the ruleset directory", hdr.Name)
		}
		target := filepath.Join(dir, filepath.FromSlash(rel))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			total += hdr.Size
			if hdr.Size < 0 || total > 4*maxBundleSize {
				return fmt.Errorf("bundle unpacks to more than %d bytes", 4*maxBundleSize)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			if err := writeEntry(target, tr, hdr.Size); err != nil {
				return err
			}
		default:
			return fmt.Errorf("bundle entry %q has unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
}

func writeEntry(target string, r io.Reader, size int64) error {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, cerr := io.CopyN(f, r, size)
	return errors.Join(cerr, f.Close())
}
