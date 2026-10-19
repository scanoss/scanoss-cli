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

package sbom

import (
	"bytes"
	"fmt"
	"strings"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// ParseSPDX decodes an SPDX 2.3 JSON document into a neutral Inventory. It is the inverse
// of buildSPDXLite: packages, licenses and checksums are mapped back. SPDX 2.3 has no
// vulnerability model, so the Inventory carries no vulnerabilities. Fields outside the
// Inventory model are not preserved (best-effort).
//
// The dependency graph is not read back: the project and root packages the writer adds for
// it are skipped, by their comment, and the DEPENDS_ON relationships are ignored. Like
// match_index, the graph survives a round trip through the raw format only.
func ParseSPDX(data []byte) (Inventory, error) {
	doc, err := spdxjson.Read(bytes.NewReader(data))
	if err != nil {
		return Inventory{}, fmt.Errorf("error decoding SPDX: %w", err)
	}

	var inv Inventory
	for _, pkg := range doc.Packages {
		if pkg == nil || isGraphPlaceholder(pkg.PackageComment) {
			continue
		}
		inv.Components = append(inv.Components, spdxToComponent(pkg))
	}
	return inv, nil
}

// isGraphPlaceholder reports whether a package comment marks the project or a root package.
func isGraphPlaceholder(comment string) bool {
	return comment == scanossProjectComment || strings.HasPrefix(comment, scanossRootComment+" ")
}

// spdxToComponent maps one SPDX package back to a neutral Component.
func spdxToComponent(pkg *v2_3.Package) Component {
	comp := Component{Version: normalizeAssertion(pkg.PackageVersion), Local: pkg.PackageComment == scanossLocalComment}

	// PURLs live in the PACKAGE-MANAGER externalRefs (first is canonical, rest are aliases);
	// the scanoss url_hash is carried in an OTHER externalRef; PackageName is the canonical
	// PURL fallback.
	var purls []string
	for _, ref := range pkg.PackageExternalReferences {
		if ref == nil {
			continue
		}
		switch ref.RefType {
		case "purl":
			purls = append(purls, ref.Locator)
		case scanossURLHashRef:
			comp.URLHash = ref.Locator
		}
	}
	switch {
	case len(purls) > 1:
		comp.Purl, comp.AliasPurls = purls[0], purls[1:]
	case len(purls) == 1:
		comp.Purl = purls[0]
	default:
		comp.Purl = pkg.PackageName
	}

	if pkg.PackageSupplier != nil && pkg.PackageSupplier.Supplier != noAssertion {
		comp.Vendor = pkg.PackageSupplier.Supplier
	}
	if h := normalizeAssertion(pkg.PackageHomePage); h != "" {
		comp.URL = h
	}
	if d := normalizeAssertion(pkg.PackageDownloadLocation); d != "" {
		comp.DownloadLocation = d
	}

	comp.Licenses = append(comp.Licenses, spdxLicenses(pkg.PackageLicenseDeclared, AckDeclared)...)
	comp.Licenses = append(comp.Licenses, spdxLicenses(pkg.PackageLicenseConcluded, AckConcluded)...)
	return comp
}

// spdxLicenses splits an SPDX license expression (the writer joins IDs with " AND ") back
// into individual License entries with the given acknowledgement. NOASSERTION/NONE/empty
// yields none.
func spdxLicenses(expr string, ack LicenseAcknowledgement) []License {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == noAssertion || expr == "NONE" {
		return nil
	}
	var out []License
	for _, part := range strings.Split(expr, " AND ") {
		if id := strings.TrimSpace(part); id != "" {
			out = append(out, License{ID: id, Acknowledgement: ack})
		}
	}
	return out
}
