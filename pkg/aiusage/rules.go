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

package aiusage

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// loadRuleMetadata reads the ai block of every rule in the card files under dir, by rule id.
// The matcher renders a non-string value (a cwe list, a boolean) as text; the rule's own value
// keeps its type.
func loadRuleMetadata(dir string) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".cards" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var file struct {
			Rules map[string]map[string]any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("aiusage: read %s: %w", path, err)
		}
		for id, rule := range file.Rules {
			if meta, ok := rule[MetadataKey].(map[string]any); ok {
				out[id] = meta
			}
		}
		return nil
	})
	return out, err
}

// typedMetadata returns filled with each value the rule declares as a non-string restored to
// the rule's typed value: only strings are templated, so the rule's value is the filled one.
func typedMetadata(filled, rule map[string]any) map[string]any {
	for k, v := range rule {
		if _, isString := v.(string); !isString {
			filled[k] = v
		}
	}
	return filled
}
