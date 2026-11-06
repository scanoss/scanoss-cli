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

package pyscope

import "testing"

func TestDevExtra(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"dev": true, "Dev": true, "tests": true, "test-integration": true, "Test_Integration": true,
		"docs.build": true, "lint": true, "typing": true,
		"socks": false, "devices": false, "testbed": false, "all": false, "postgres": false, "": false,
	} {
		if got := DevExtra(name); got != want {
			t.Errorf("DevExtra(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestDevPoetryGroup(t *testing.T) {
	t.Parallel()
	if DevPoetryGroup("main") {
		t.Error("main is the runtime group")
	}
	if !DevPoetryGroup("test") {
		t.Error("every group but main is for development")
	}
}
