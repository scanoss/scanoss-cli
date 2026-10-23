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
	"errors"
	"fmt"
	"strconv"
)

// maxComponentsParam is the scan endpoint's query parameter that caps how many components
// the server reports.
const maxComponentsParam = "max_components"

const allComponents = "all"

var errInvalidComponentLimit = errors.New(`must be a positive integer or "all"`)

// ComponentLimit says how many components the server reports for a scan: a positive number, or
// all of them. The zero value is unset: the scan request does not mention the limit
// and the server applies its own default.
type ComponentLimit struct {
	n   int
	all bool
}

// ComponentsUpTo limits each match to at most n components. n must be at least 1.
func ComponentsUpTo(n int) (ComponentLimit, error) {
	if n < 1 {
		return ComponentLimit{}, fmt.Errorf("component limit %d: %w", n, errInvalidComponentLimit)
	}
	return ComponentLimit{n: n}, nil
}

// AllComponents asks for every component, with no limit.
func AllComponents() ComponentLimit { return ComponentLimit{all: true} }

// ParseComponentLimit reads the text form: exactly "all", or a base-10 positive integer with no
// sign and no surrounding space.
func ParseComponentLimit(s string) (ComponentLimit, error) {
	if s == allComponents {
		return AllComponents(), nil
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ComponentLimit{}, fmt.Errorf("component limit %q: %w", s, errInvalidComponentLimit)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return ComponentLimit{}, fmt.Errorf("component limit %q: %w", s, errInvalidComponentLimit)
	}
	return ComponentsUpTo(n)
}

// IsSet reports whether a limit was chosen.
func (l ComponentLimit) IsSet() bool { return l.all || l.n > 0 }

// String is the value sent to the server, "all" or the number. It is empty when the limit is
// unset.
func (l ComponentLimit) String() string {
	switch {
	case l.all:
		return allComponents
	case l.n > 0:
		return strconv.Itoa(l.n)
	}
	return ""
}
