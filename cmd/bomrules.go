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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scanoss/scanoss.go/pkg/sbom"
	"github.com/scanoss/scanoss.go/pkg/scanoss"
	"github.com/scanoss/scanoss.go/pkg/settings"
)

// addBOMRuleFlags declares --identify and --ignore. They name a component list; scanoss.json's
// bom.identify / bom.ignore say the same thing with per-path scoping, and both sources are
// merged (see mergeBOMRuleFlags).
func addBOMRuleFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("identify", "i", "",
		"Component list (SBOM) declaring which components are present: matching PURLs are marked identified and lead their file's matches")
	cmd.Flags().StringP("ignore", "n", "",
		"Component list (SBOM) whose components are dropped from the scan results")
}

// mergeBOMRuleFlags folds the PURLs named by --identify and --ignore into the settings' BOM.
//
// Unlike scanoss.py, which rejects --identify alongside --settings, the two are merged: they say
// the same thing at different granularities, and a project with a scanoss.json has no reason to
// give up the flag. The flags contribute PURLs with no path, so they apply everywhere, and the
// more specific rules a settings file carries still win where both cover a file.
//
// It returns settings ready to hand to the scan, creating one if the project had none.
func mergeBOMRuleFlags(cmd *cobra.Command, s *settings.Settings) (*settings.Settings, error) {
	identifyPath, _ := cmd.Flags().GetString("identify")
	ignorePath, _ := cmd.Flags().GetString("ignore")
	if identifyPath == "" && ignorePath == "" {
		return s, nil
	}

	if s == nil {
		s = &settings.Settings{}
	}
	if identifyPath != "" {
		entries, err := readComponentList(identifyPath, "--identify")
		if err != nil {
			return nil, err
		}
		s.BOM.Identify = append(s.BOM.Identify, entries...)
	}
	if ignorePath != "" {
		entries, err := readComponentList(ignorePath, "--ignore")
		if err != nil {
			return nil, err
		}
		s.BOM.Ignore = append(s.BOM.Ignore, entries...)
	}
	return s, nil
}

// readComponentList reads the PURLs from a component list file as BOM entries.
//
// Four shapes are accepted. The legacy SCANOSS list ({"components":[{"purl":...}]}) is what
// scanoss.py takes here; CycloneDX, SPDX and this client's own raw output are accepted too,
// because the parsers already exist and refusing an SBOM the CLI itself produced would be a
// gratuitous limitation. The shape is detected from the content, not the file name.
func readComponentList(path, flag string) ([]settings.BOMEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading %s file: %w", flag, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("%s file %q is empty", flag, path)
	}

	purls, err := parseComponentList(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s file %q: %w", flag, path, err)
	}
	if len(purls) == 0 {
		return nil, fmt.Errorf("%s file %q declares no PURLs", flag, path)
	}

	entries := make([]settings.BOMEntry, 0, len(purls))
	for _, purl := range purls {
		entries = append(entries, settings.BOMEntry{Purl: purl})
	}
	return entries, nil
}

// parseComponentList extracts the PURLs from any of the accepted SBOM shapes, deduplicated and
// in the order they appear.
func parseComponentList(data []byte) ([]string, error) {
	// The legacy SCANOSS list first: it is the shape --identify has always taken, and its
	// "components" key is also present in CycloneDX, so it has to be tried before falling
	// through to a format that would parse it into nothing.
	var legacy struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &legacy); err == nil {
		if purls := dedupePurls(legacyPurls(legacy.Components)); len(purls) > 0 {
			return purls, nil
		}
	}

	for _, parse := range []func([]byte) (sbom.Inventory, error){
		sbom.ParseRaw, sbom.ParseCycloneDX, sbom.ParseSPDX,
	} {
		inv, err := parse(data)
		if err != nil {
			continue
		}
		var purls []string
		for _, c := range inv.Components {
			purls = append(purls, c.AllPurls()...)
		}
		if purls = dedupePurls(purls); len(purls) > 0 {
			return purls, nil
		}
	}
	return nil, fmt.Errorf("unrecognized format: expected a SCANOSS component list, CycloneDX, SPDX or scanoss raw output")
}

func legacyPurls(components []struct {
	Purl string `json:"purl"`
}) []string {
	purls := make([]string, 0, len(components))
	for _, c := range components {
		purls = append(purls, c.Purl)
	}
	return purls
}

func dedupePurls(purls []string) []string {
	seen := make(map[string]bool, len(purls))
	out := make([]string, 0, len(purls))
	for _, p := range purls {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// addRankingFlag declares --ranking-threshold. Default -1, matching scanoss.py, where it meant
// "defer to the server"; here there is no server to defer to, so it simply means off.
func addRankingFlag(cmd *cobra.Command) {
	cmd.Flags().Int("ranking-threshold", -1, fmt.Sprintf(
		"Drop matches whose component ranks worse than this (%d..%d; %d or 0 = no filtering)",
		settings.MinRankingThreshold, settings.MaxRankingThreshold, settings.MinRankingThreshold))
}

// resolveRankingThreshold settles the ranking filter from the flag and the settings file, and
// clamps it into range.
//
// As with the header filter, scanoss.json wins over the command line — see resolveSkipHeaders
// for why. Out-of-range values are clamped rather than rejected, with a warning naming what was
// used instead: scanoss.py behaves the same, and failing a whole scan over a mistyped bound
// would be worse than filtering slightly differently than asked.
func resolveRankingThreshold(cmd *cobra.Command, s *settings.Settings) int {
	threshold, _ := cmd.Flags().GetInt("ranking-threshold")
	source := "--ranking-threshold"
	if s != nil {
		if v, ok := s.Settings.RankingThreshold(); ok {
			threshold, source = v, "settings.file_snippet.ranking_threshold"
		}
	}

	switch {
	case threshold > settings.MaxRankingThreshold:
		warnf("%s %d exceeds the maximum of %d — using %d",
			source, threshold, settings.MaxRankingThreshold, settings.MaxRankingThreshold)
		return settings.MaxRankingThreshold
	case threshold < settings.MinRankingThreshold:
		warnf("%s %d is below the minimum of %d — no ranking filter applied",
			source, threshold, settings.MinRankingThreshold)
		return settings.MinRankingThreshold
	}
	return threshold
}

// addComponentFlag declares --max-components on the commands that upload a scan.
func addComponentFlag(cmd *cobra.Command) {
	cmd.Flags().String("max-components", "",
		`How many components the server reports: a positive integer or "all" (default: the server's own limit)`)
}

// resolveComponentLimit reads --max-components. A flag left off is an unset limit, which
// sends nothing. A flag that was passed is parsed whatever it holds, so an explicit empty value is
// refused rather than read as unset. A bad value is refused here so the command fails before it
// fingerprints or uploads.
func resolveComponentLimit(cmd *cobra.Command) (scanoss.ComponentLimit, error) {
	if !cmd.Flags().Changed("max-components") {
		return scanoss.ComponentLimit{}, nil
	}
	v, _ := cmd.Flags().GetString("max-components")
	l, err := scanoss.ParseComponentLimit(v)
	if err != nil {
		return scanoss.ComponentLimit{}, fmt.Errorf("--max-components: %w", err)
	}
	return l, nil
}

// addSkipHeaderFlags declares the fingerprinting header filter flags.
//
// The filter is on by default: a licence header is boilerplate shared by every file that carries
// it, so fingerprinting it makes unrelated files look alike. --skip-headers=false turns it off.
func addSkipHeaderFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("skip-headers", true,
		"Skip licence headers, comments and imports at the beginning of files when fingerprinting (--skip-headers=false to disable)")
	cmd.Flags().Int("skip-headers-limit", 0,
		"Maximum number of leading lines the header filter may drop (0 = no limit)")
}

// resolveSkipHeaders settles the header filter from the flags and the settings file.
//
// scanoss.json wins over the command line, which is the reverse of the usual convention and of
// what the collection flags do (see applyCollectFlags) — it is what scanoss.py does, and the two
// clients reading one settings file differently would be worse than the inconsistency. A user who
// needs the flag to win has to edit or drop the settings file. That holds for switching the filter
// off as much as on: skip_headers: false in the settings beats the on-by-default flag.
func resolveSkipHeaders(cmd *cobra.Command, s *settings.Settings) (enabled bool, limit int) {
	enabled, _ = cmd.Flags().GetBool("skip-headers")
	limit, _ = cmd.Flags().GetInt("skip-headers-limit")

	if s == nil {
		return enabled, limit
	}
	if v, ok := s.Settings.SkipHeaders(); ok {
		enabled = v
	}
	if v, ok := s.Settings.SkipHeadersLimit(); ok {
		limit = v
	}
	return enabled, limit
}
