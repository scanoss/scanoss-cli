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

package cmd

import (
	"errors"
	"maps"
	"testing"
)

func TestToolchainSet(t *testing.T) {
	goOnPath := func(string) (string, error) { return "/usr/bin/go", nil }
	noGo := func(string) (string, error) { return "", errors.New("not found") }
	goMod := map[string]bool{"go.mod": true}
	for _, tc := range []struct {
		name    string
		look    func(string) (string, error)
		values  []string
		changed bool
		want    map[string]bool
		wantErr string
	}{
		{name: "default with go on PATH resolves go.mod", look: goOnPath, want: goMod},
		{name: "default without go reads lockfiles only", look: noGo, want: nil},
		{name: "explicit go without go on PATH still asks for it", look: noGo, values: []string{"go"}, changed: true, want: goMod},
		{name: "none turns tools off", look: goOnPath, values: []string{"none"}, changed: true, want: nil},
		{name: "none with go is an error", look: goOnPath, values: []string{"none", "go"}, changed: true, wantErr: "--toolchain none cannot be combined with other values"},
		{name: "maven is not offered", look: goOnPath, values: []string{"maven"}, changed: true, wantErr: `unknown --toolchain value "maven" (valid: go, none)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := lookPath
			lookPath = tc.look
			t.Cleanup(func() { lookPath = saved })
			got, err := toolchainSet(tc.values, tc.changed)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
