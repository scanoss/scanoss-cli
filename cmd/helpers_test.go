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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/scanoss.go/pkg/filter"
)

func TestValidateSizeBounds(t *testing.T) {
	tests := []struct {
		name    string
		min     int64
		max     int64
		wantErr string // substring the message must name; empty means no error
	}{
		{"both unset", 0, 0, ""},
		{"minimum only", 100, 0, ""},
		{"maximum only", 0, 1024, ""},
		{"minimum below maximum", 100, 1024, ""},
		{"minimum equal to maximum", 1024, 1024, ""},
		{"negative minimum", -1, 0, "--min-size"},
		{"negative maximum", 0, -1, "--max-size"},
		{"minimum above maximum", 2048, 1024, "--min-size"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSizeBounds(tc.min, tc.max)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSizeBounds(%d, %d) = %v, want nil", tc.min, tc.max, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateSizeBounds(%d, %d) = nil, want an error", tc.min, tc.max)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not name %q", err, tc.wantErr)
			}
		})
	}
}

// A minimum above an unlimited maximum (0) is not a contradiction: 0 means "no
// upper bound", so the pair is valid however large the minimum is.
func TestValidateSizeBoundsUnlimitedMax(t *testing.T) {
	if err := validateSizeBounds(1<<40, 0); err != nil {
		t.Fatalf("validateSizeBounds(large, 0) = %v, want nil", err)
	}
}

// The collection flags only ever remove rules. A flag sitting at its default must not
// switch something back on that a profile turned off on purpose — the manifest stage
// starts from filter.Dependencies, whose BuiltinFolderRules is false so that a manifest
// under examples/ or venv/ is still found.
func TestApplyCollectFlagsOnlyRemovesRules(t *testing.T) {
	o := filter.Dependencies(nil)
	if o.BuiltinFolderRules || o.GitIgnore {
		t.Fatalf("precondition: Dependencies() should start with both off, got %+v", o)
	}

	// Every flag at its default: nothing the profile decided may change.
	applyCollectFlags(&o, 0, 0, false, false, true, false)
	if o.BuiltinFolderRules {
		t.Error("BuiltinFolderRules was switched on by a flag left at its default")
	}
	if o.GitIgnore {
		t.Error("GitIgnore was switched on by a flag left at its default")
	}
	if len(o.SkipDirs) == 0 {
		t.Error("the profile's own directory list was cleared by a flag left at its default")
	}

	// And the flags still do their job where the profile left the rule on.
	s := filter.Scanning(nil)
	applyCollectFlags(&s, 0, 0, true, true, false, true)
	if s.BuiltinFileRules || s.BuiltinFolderRules || s.GitIgnore {
		t.Errorf("--all-extensions/--all-folders/--gitignore=false must switch their rules off, got %+v", s)
	}
	if !s.IncludeHidden {
		t.Error("--all-hidden must switch IncludeHidden on")
	}

	// --all-folders has to reach a profile's own directory list too, not only the built-in
	// switch. Dependencies keeps its rules in SkipDirs, so a caller asking for every folder
	// would otherwise still lose a manifest under dist/.
	d := filter.Dependencies(nil)
	if len(d.SkipDirs) == 0 || len(d.SkipDirExts) == 0 {
		t.Fatal("precondition: Dependencies() should carry its own directory lists")
	}
	applyCollectFlags(&d, 0, 0, false, true, true, false)
	if len(d.SkipDirs) != 0 || len(d.SkipDirExts) != 0 {
		t.Errorf("--all-folders must clear the profile's directory rules, got SkipDirs=%v SkipDirExts=%v",
			d.SkipDirs, d.SkipDirExts)
	}
}

// The dependency stage reads lockfiles the built-in extension list would drop (.lock, .yaml),
// so its collection runs with that list off and selects files by name afterwards. Without this
// a scan found package-lock.json but never Cargo.lock, pnpm-lock.yaml, poetry.lock or
// composer.lock.
func TestDependencyCollectOptionsKeepLockfiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Cargo.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock", "package-lock.json", "logo.png"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := filter.Collect(root, dependencyCollectOptions(nil))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Files {
		got = append(got, filepath.Base(f))
	}
	slices.Sort(got)
	for _, want := range []string{"Cargo.lock", "composer.lock", "package-lock.json", "pnpm-lock.yaml", "poetry.lock"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s was not collected for the dependency stage, got %v", want, got)
		}
	}
	// The profile's other decisions are untouched: it still prunes nothing by .gitignore and
	// keeps its own directory lists.
	o := dependencyCollectOptions(nil)
	if o.GitIgnore || o.BuiltinFolderRules || len(o.SkipDirs) == 0 || !o.KeepManifests {
		t.Errorf("dependencyCollectOptions changed more than the file rules: %+v", o)
	}
}

// resolveSettings carries the CLI's priority: --settings wins, autodetection fills in, and no
// file at all is not an error. It lives here rather than in pkg/settings because the priority is
// the CLI's, not the library's.
func TestResolveSettings(t *testing.T) {
	t.Run("explicit settings flag", func(t *testing.T) {
		dir := t.TempDir()
		settingsPath := filepath.Join(dir, "my-settings.json")
		content := `{"bom": {"identify": [{"purl": "pkg:npm/test@1.0.0"}]}}`
		os.WriteFile(settingsPath, []byte(content), 0644)

		s, err := resolveSettings(settingsPath, dir)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s == nil {
			t.Fatal("Expected settings, got nil")
		}
		if len(s.BOM.Identify) != 1 {
			t.Errorf("Expected 1 identify entry, got %d", len(s.BOM.Identify))
		}
	})

	t.Run("auto-detect", func(t *testing.T) {
		dir := t.TempDir()
		content := `{"bom": {"ignore": [{"purl": "pkg:npm/auto@*"}]}}`
		os.WriteFile(filepath.Join(dir, "scanoss.json"), []byte(content), 0644)

		s, err := resolveSettings("", dir)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s == nil {
			t.Fatal("Expected settings, got nil")
		}
		if len(s.BOM.Ignore) != 1 {
			t.Errorf("Expected 1 ignore entry, got %d", len(s.BOM.Ignore))
		}
	})

	t.Run("no settings", func(t *testing.T) {
		dir := t.TempDir()

		s, err := resolveSettings("", dir)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s != nil {
			t.Error("Expected nil settings, got non-nil")
		}
	})

	t.Run("explicit flag overrides auto-detect", func(t *testing.T) {
		dir := t.TempDir()
		// Auto-detect file in scan dir
		os.WriteFile(filepath.Join(dir, "scanoss.json"), []byte(`{"bom": {"identify": [{"purl": "pkg:npm/auto@1.0.0"}]}}`), 0644)

		// Explicit settings file elsewhere
		explicitDir := t.TempDir()
		explicitPath := filepath.Join(explicitDir, "custom.json")
		os.WriteFile(explicitPath, []byte(`{"bom": {"identify": [{"purl": "pkg:npm/explicit@2.0.0"}]}}`), 0644)

		s, err := resolveSettings(explicitPath, dir)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if s == nil {
			t.Fatal("Expected settings, got nil")
		}
		if s.BOM.Identify[0].Purl != "pkg:npm/explicit@2.0.0" {
			t.Errorf("Expected explicit settings to override, got purl '%s'", s.BOM.Identify[0].Purl)
		}
	})

	t.Run("non-existent explicit file", func(t *testing.T) {
		_, err := resolveSettings("/nonexistent/settings.json", t.TempDir())
		if err == nil {
			t.Error("Expected error for non-existent explicit file")
		}
	})
}

// An absolute --settings is passed through as given. filepath.Abs cleans as it goes, and
// cleaning resolves ".." lexically: through a symlinked directory that names a different file
// than the one the OS would open. The error naming a path the user never typed is the visible
// half of the same bug, and the one this pins without needing a symlink.
func TestResolveSettingsKeepsAnAbsolutePathAsGiven(t *testing.T) {
	dir := t.TempDir()
	// Built by concatenation on purpose: filepath.Join cleans too, so a path assembled with it
	// would arrive already normalised and prove nothing.
	sep := string(filepath.Separator)
	given := dir + sep + "sub" + sep + ".." + sep + "missing.json"

	_, err := resolveSettings(given, dir)
	if err == nil {
		t.Fatal("expected an error for a missing explicit settings file")
	}
	if !strings.Contains(err.Error(), given) {
		t.Errorf("error = %q, want it to name the path as given (%q)", err, given)
	}
}
