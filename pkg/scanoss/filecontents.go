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
	"net/url"
	"strconv"
)

// serviceFileContents is the raw source-content endpoint (v3). Unlike the decoration
// services it takes no components and returns plain text, not JSON: the file's bytes,
// optionally sliced to a line range. The content id is the file's MD5 — for a snippet
// match, the matched OSS file's hash (FileResult.FileHash).
var serviceFileContents = Service{Name: "file.contents", endpoint: "/v3/file-contents/"}

// ContentsAPI is the raw file-content surface. It serves the source of a matched OSS
// file by its MD5, which the snippet classifier needs to score a match.
type ContentsAPI interface {
	// File returns the raw text of the file with the given MD5. start and end are a
	// 1-based inclusive line range; pass 0 for either to leave it at the default (line
	// 1 / the last line), so File(ctx, md5, 0, 0) returns the whole file.
	File(ctx context.Context, md5 string, start, end int) ([]byte, error)
}

type contentsService struct{ c *Client }

var _ ContentsAPI = contentsService{}

// File fetches the raw content of the file identified by md5. See ContentsAPI.File.
func (s contentsService) File(ctx context.Context, md5 string, start, end int) ([]byte, error) {
	var q url.Values
	if start > 0 || end > 0 {
		q = url.Values{}
		if start > 0 {
			q.Set("start", strconv.Itoa(start))
		}
		if end > 0 {
			q.Set("end", strconv.Itoa(end))
		}
	}
	return s.c.get(ctx, serviceFileContents.endpoint+url.PathEscape(md5), q)
}
