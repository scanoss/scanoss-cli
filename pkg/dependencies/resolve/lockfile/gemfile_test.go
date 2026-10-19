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

package lockfile

import (
	"maps"
	"testing"
)

func TestGemfileLockGolden(t *testing.T) { runGolden(t, "gemfile") }

func TestGemfileDev(t *testing.T) {
	tests := []struct {
		name    string
		gemfile string
		want    map[string]bool
		ok      bool
	}{
		{"outside any group", `gem "rails", "~> 7.0"`, map[string]bool{"rails": false}, true},
		{"group block of symbols", "group :development, :test do\n  gem 'rspec'\nend", map[string]bool{"rspec": true}, true},
		{"group block of strings with parentheses", "group(\"test\") do\n  gem \"capybara\"\nend", map[string]bool{"capybara": true}, true},
		{"group block with another group", "group :test, :ci do\n  gem \"rspec\"\nend", map[string]bool{"rspec": false}, true},
		{"group block with an option", "group :test, optional: true do\n  gem \"rspec\"\nend", map[string]bool{"rspec": true}, true},
		{"nested group blocks", "group :development do\n  group :test do\n    gem \"a\"\n  end\n  gem \"b\"\nend\ngem \"c\"", map[string]bool{"a": true, "b": true, "c": false}, true},
		{"group block inside a runtime group block", "group :production do\n  group :test do\n    gem \"a\"\n  end\nend", map[string]bool{"a": false}, true},
		{"group inside a runtime group", "group :default do\n  gem \"a\", group: :test\nend", map[string]bool{"a": false}, true},
		{"group option", `gem "rspec", group: :test`, map[string]bool{"rspec": true}, true},
		{"groups option", `gem "pry", groups: [:development, :test]`, map[string]bool{"pry": true}, true},
		{"group array option of strings", `gem "pry", group: ["development", "test"], require: false`, map[string]bool{"pry": true}, true},
		{"hash rocket option", `gem "pry", :group => :development`, map[string]bool{"pry": true}, true},
		{"group option with a runtime group", `gem "puma", groups: [:production, :test]`, map[string]bool{"puma": false}, true},
		{"declared twice, once at runtime", "gem \"json\"\ngroup :test do\n  gem \"json\"\nend", map[string]bool{"json": false}, true},
		{"other blocks keep the group", "group :test do\n  platforms :jruby do\n    gem \"a\"\n  end\n  if ENV[\"X\"]\n    gem \"b\"\n  end\nend\ngem \"c\"", map[string]bool{"a": true, "b": true, "c": false}, true},
		{"comments are ignored", "# group :test do\ngem \"a\" # group: :test", map[string]bool{"a": false}, true},
		{"unrecognised line", "source \"https://rubygems.org\"\ngemspec\neval_gemfile \"other\"\ngem \"a\"", map[string]bool{"a": false}, true},
		{"unrecognised gem form is not declared", "group :test do\n  gem(*names)\nend", map[string]bool{}, true},
		{"unclosed block", "group :test do\n  gem \"rspec\"", nil, false},
		{"stray end", "gem \"a\"\nend", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := gemfileDev(tt.gemfile)
			if ok != tt.ok || (ok && !maps.Equal(got, tt.want)) {
				t.Errorf("gemfileDev = %v, %v; want %v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func FuzzGemfileLock(f *testing.F) { fuzzFormat(f, "gemfile") }
