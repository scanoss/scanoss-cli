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

package rulesets_test

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/scanoss/scanoss.go/pkg/rulesets"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
)

// A command resolves --ruleset name@version against the API it already
// talks to, and exits with rulesets.ExitCode when the rules are unavailable.
func ExampleClient_Fetch() {
	cfg := scanoss.Config{APIURL: "https://api.scanoss.com", APIKey: os.Getenv("SCANOSS_API_KEY")}
	hc, err := scanoss.NewHTTPClient(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	name, version, err := rulesets.ParseRef("ai@latest")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client, err := rulesets.New(rulesets.Options{
		Domain: "ai", APIURL: cfg.APIURL, APIKey: cfg.APIKey, HTTPClient: hc,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rs, err := client.Fetch(context.Background(), name, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, rulesets.ErrUnavailable) {
			os.Exit(rulesets.ExitCode)
		}
		os.Exit(1)
	}
	defer rs.Close()
	fmt.Printf("using %s@%s from %s (%s)\n", rs.Name, rs.Version, rs.Dir, rs.Source)
}
