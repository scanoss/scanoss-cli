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

package toolchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// output is what a run read from the tool before it exited or was stopped,
// whatever the outcome: some tools, such as mvn, log their errors on stdout.
type output struct {
	stdout []byte
	stderr []byte
	reason resolve.Reason
	detail string
}

type runFunc func(name string, args ...string) output

type runner struct {
	ctx       context.Context
	dir       string
	env       []string
	timeout   time.Duration
	maxOutput int64
}

// waitDelay bounds how long Wait waits for the pipes after the tool exits or
// is killed, in case something it started still holds them.
const waitDelay = 2 * time.Second

func (r runner) run(name string, args ...string) output {
	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = r.dir
	cmd.Env = r.env
	cmd.WaitDelay = waitDelay
	killGroup(cmd)
	stdout := &capped{max: r.maxOutput, overflow: cancel}
	stderr := &capped{max: r.maxOutput, overflow: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()

	label := strings.Join(append([]string{name}, args...), " ")
	out := output{stdout: stdout.buf, stderr: stderr.buf}
	switch {
	case stdout.over || stderr.over:
		out.reason, out.detail = resolve.ReasonTooLarge, fmt.Sprintf("%s: output exceeds %d bytes", label, r.maxOutput)
	case err == nil:
	case errors.Is(err, exec.ErrNotFound):
		out.reason, out.detail = resolve.ReasonToolMissing, fmt.Sprintf("%s: not found on PATH", name)
	case r.ctx.Err() != nil:
		out.reason, out.detail = resolve.ReasonTimeout, fmt.Sprintf("%s: cancelled", label)
	case ctx.Err() != nil:
		out.reason, out.detail = resolve.ReasonTimeout, fmt.Sprintf("%s: no result after %s", label, r.timeout)
	default:
		out = failed(label, err, stderr.buf)
		out.stdout = stdout.buf
	}
	return out
}

func failed(label string, err error, stderr []byte) output {
	prefix := fmt.Sprintf("%s: %v: ", label, err)
	return output{stderr: stderr, reason: resolve.ReasonToolFailed, detail: prefix + quoteEnd(stderr, build.MaxDetail-len(prefix))}
}

// unreachable reports whether text has any of a tool's messages for a
// registry it could not reach.
func unreachable(text string, messages []string) bool {
	for _, s := range messages {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

func quoteEnd(text []byte, n int) string {
	text = bytes.TrimSpace(text)
	if n < 0 {
		n = 0
	}
	if len(text) > n {
		text = text[len(text)-n:]
	}
	return strings.ToValidUTF8(string(text), "")
}

type capped struct {
	buf      []byte
	max      int64
	over     bool
	overflow func()
}

func (c *capped) Write(p []byte) (int, error) {
	if !c.over && int64(len(c.buf)+len(p)) <= c.max {
		c.buf = append(c.buf, p...)
		return len(p), nil
	}
	if !c.over {
		c.over = true
		c.overflow()
	}
	return len(p), nil
}
