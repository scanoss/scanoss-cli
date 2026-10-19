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
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// spdxTimeFormat is the SPDX creation-timestamp layout (UTC, second precision).
const spdxTimeFormat = "2006-01-02T15:04:05Z"

// scanossURLHashRef is the SPDX OTHER external-reference type carrying the scanoss url_hash
// (a CRC64), which has no standard SPDX checksum algorithm.
const scanossURLHashRef = "scanoss-url-hash"

// SPDX has no property bag, so what CycloneDX carries as scanoss properties goes in the package
// comment, under the same namespace. A reader matches on the prefix.
const (
	scanossLocalComment   = "scanoss:local"
	scanossProjectComment = "scanoss:project"
	scanossRootComment    = "scanoss:root"
)

// buildSPDXLite renders the inventory as an SPDX 2.3 JSON document (restricted to the
// SPDX Lite field subset) via the official tools-golang library. Vulnerabilities and
// file evidence do not apply to SPDX.
//
// When the inventory carries a dependency graph, the document also describes a project package
// that DEPENDS_ON one package per root, each root DEPENDS_ON the members its manifest declares,
// and a package DEPENDS_ON its edges. The components keep their DESCRIBES relationship either
// way, so a package the graph does not reach (a scan match, a flat-parsed manifest entry) is
// still attached to the document.
func buildSPDXLite(inv Inventory, o options) (string, error) {
	doc := &v2_3.Document{
		SPDXVersion:       v2_3.Version,
		DataLicense:       v2_3.DataLicense,
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      fmt.Sprintf("SBOM for %s", o.projectName),
		DocumentNamespace: spdxNamespace(o.projectName, inv.Components),
		CreationInfo: &v2_3.CreationInfo{
			Creators: []common.Creator{
				{CreatorType: "Tool", Creator: o.toolIdentifier()},
				{CreatorType: "Organization", Creator: o.author},
			},
			Created: o.resolvedTimestamp().Format(spdxTimeFormat),
		},
	}

	seenLicenseRefs := make(map[string]bool)
	for _, comp := range inv.Components {
		pkg := spdxPackage(comp)
		doc.Packages = append(doc.Packages, pkg)
		// Each package is described by the document. SPDX requires at least one
		// DESCRIBES relationship when a document has multiple packages.
		doc.Relationships = append(doc.Relationships, spdxRelationship("DOCUMENT", pkg.PackageSPDXIdentifier, common.TypeRelationshipDescribe))
		doc.OtherLicenses = append(doc.OtherLicenses, extractedLicenses(comp.Licenses, seenLicenseRefs)...)
	}
	if len(inv.Dependencies) > 0 {
		spdxGraph(doc, inv, o.projectName)
	}

	var buf bytes.Buffer
	if err := spdxjson.Write(doc, &buf, spdxjson.Indent("  ")); err != nil {
		return "", fmt.Errorf("error serializing SPDX document: %w", err)
	}
	return buf.String(), nil
}

func spdxPackage(comp Component) *v2_3.Package {
	versionInfo := comp.Version
	if versionInfo == "" {
		versionInfo = noAssertion
	}

	downloadLocation := comp.DownloadLocation
	if downloadLocation == "" {
		downloadLocation = comp.URL
	}
	if downloadLocation == "" {
		downloadLocation = noAssertion
	}

	homepage := comp.URL
	if homepage == "" {
		homepage = noAssertion
	}

	pkg := &v2_3.Package{
		PackageName:               comp.DisplayName(),
		PackageSPDXIdentifier:     spdxPackageID(comp),
		PackageVersion:            versionInfo,
		PackageSupplier:           spdxSupplier(comp),
		PackageDownloadLocation:   downloadLocation,
		FilesAnalyzed:             false,
		PackageHomePage:           homepage,
		PackageLicenseDeclared:    joinLicenseIDs(comp.Licenses, AckDeclared),
		PackageLicenseConcluded:   joinLicenseIDs(comp.Licenses, AckConcluded),
		PackageCopyrightText:      noAssertion,
		PackageExternalReferences: purlExternalRefs(comp),
	}

	// The scanoss url_hash is a CRC64, which SPDX 2.3 has no checksum algorithm for, so it
	// is preserved as an OTHER external reference rather than emitted as an (invalid) MD5
	// checksum.
	if comp.URLHash != "" {
		pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, &v2_3.PackageExternalReference{
			Category: "OTHER",
			RefType:  scanossURLHashRef,
			Locator:  comp.URLHash,
		})
	}
	if comp.Local {
		pkg.PackageComment = scanossLocalComment
	}

	return pkg
}

// spdxGraph adds the project package, one package per root and the DEPENDS_ON relationships.
// A relationship is written once however many roots share the edge.
func spdxGraph(doc *v2_3.Document, inv Inventory, projectName string) {
	project := spdxPlaceholderPackage(projectName, md5Hash(projectName), scanossProjectComment)
	doc.Packages = append(doc.Packages, project)
	doc.Relationships = append(doc.Relationships, spdxRelationship("DOCUMENT", project.PackageSPDXIdentifier, common.TypeRelationshipDescribe))

	ids := make(map[string]common.ElementID, len(inv.Components))
	for _, c := range inv.Components {
		ids[c.Ref()] = spdxPackageID(c)
	}
	seen := map[string]bool{}
	depends := func(from, to common.ElementID) {
		key := string(from) + ">" + string(to)
		if !seen[key] {
			seen[key] = true
			doc.Relationships = append(doc.Relationships, spdxRelationship(from, to, common.TypeRelationshipDependsOn))
		}
	}
	dependsOn := inv.dependsOn()
	for _, r := range inv.Dependencies {
		comment := fmt.Sprintf("%s lockfile=%s status=%s", scanossRootComment, r.Lockfile, r.Status)
		if r.Reason != "" {
			comment += " reason=" + r.Reason
		}
		root := spdxPlaceholderPackage(r.Manifest, md5Hash(r.Ref()), comment)
		doc.Packages = append(doc.Packages, root)
		depends(project.PackageSPDXIdentifier, root.PackageSPDXIdentifier)
		for _, ref := range inv.DirectMembers(r) {
			depends(root.PackageSPDXIdentifier, ids[ref])
		}
	}
	for _, c := range inv.Components {
		for _, to := range dependsOn[c.Ref()] {
			depends(ids[c.Ref()], ids[to])
		}
	}
}

// spdxPlaceholderPackage is a package that stands for something other than a third-party
// component, the project or a manifest, so every field SPDX requires is NOASSERTION and the
// comment says what it is.
func spdxPlaceholderPackage(name, id, comment string) *v2_3.Package {
	return &v2_3.Package{
		PackageName:             name,
		PackageSPDXIdentifier:   common.ElementID(id),
		PackageVersion:          noAssertion,
		PackageSupplier:         &common.Supplier{Supplier: noAssertion},
		PackageDownloadLocation: noAssertion,
		FilesAnalyzed:           false,
		PackageHomePage:         noAssertion,
		PackageLicenseDeclared:  noAssertion,
		PackageLicenseConcluded: noAssertion,
		PackageCopyrightText:    noAssertion,
		PackageComment:          comment,
	}
}

func spdxRelationship(a, b common.ElementID, kind string) *v2_3.Relationship {
	return &v2_3.Relationship{
		RefA:         common.MakeDocElementID("", string(a)),
		RefB:         common.MakeDocElementID("", string(b)),
		Relationship: kind,
	}
}

// spdxPackageID is the one rule for a component's SPDX identifier, shared by the package and
// the relationships that point at it.
func spdxPackageID(comp Component) common.ElementID {
	return common.ElementID(md5Hash(comp.Purl + "@" + comp.Version))
}

// purlExternalRefs emits one PACKAGE-MANAGER purl reference per component PURL (SPDX
// supports multiple), so secondary PURLs are not lost.
func purlExternalRefs(comp Component) []*v2_3.PackageExternalReference {
	purls := comp.AllPurls()
	refs := make([]*v2_3.PackageExternalReference, 0, len(purls))
	for _, p := range purls {
		refs = append(refs, &v2_3.PackageExternalReference{Category: "PACKAGE-MANAGER", RefType: "purl", Locator: p})
	}
	return refs
}

func spdxSupplier(comp Component) *common.Supplier {
	if s := supplier(comp); s != noAssertion {
		return &common.Supplier{Supplier: s, SupplierType: "Organization"}
	}
	return &common.Supplier{Supplier: noAssertion}
}

// spdxNamespace builds a deterministic document namespace from the project name and the
// component set (a stable SHA-256), avoiding any time/random nondeterminism.
func spdxNamespace(projectName string, comps []Component) string {
	var b strings.Builder
	b.WriteString(projectName)
	for _, c := range comps {
		b.WriteString("\n")
		b.WriteString(c.Purl)
		b.WriteString("@")
		b.WriteString(c.Version)
	}
	clean := strings.ReplaceAll(projectName, " ", "")
	return fmt.Sprintf("https://spdx.org/spdxdocs/%s-%x", clean, sha256.Sum256([]byte(b.String())))
}

// joinLicenseIDs returns the component's license IDs for the given acknowledgement
// (an empty acknowledgement counts as declared), de-duplicated and joined with " AND ",
// or NOASSERTION when there are none.
func joinLicenseIDs(licenses []License, ack LicenseAcknowledgement) string {
	seen := make(map[string]bool)
	var ids []string
	for _, l := range licenses {
		if l.ID == "" || l.Acknowledgement.resolved() != ack || seen[l.ID] {
			continue
		}
		seen[l.ID] = true

		// Only identifiers SPDX recognises may appear bare; anything else becomes
		// a LicenseRef, declared alongside in hasExtractedLicensingInfos. Passing
		// an unrecognised identifier through produces an invalid document.
		term, ok := normalizeLicense(l.ID)
		if !ok {
			if ref := licenseRef(l.ID); ref != "" {
				ids = append(ids, ref)
			}
			continue
		}
		// An expression must be parenthesised before being joined: "A OR B" AND "C"
		// does not mean the same as "A OR (B AND C)".
		if isCompound(term) {
			term = "(" + term + ")"
		}
		ids = append(ids, term)
	}
	if len(ids) == 0 {
		return noAssertion
	}
	return strings.Join(ids, " AND ")
}

// licenseRefPattern matches LicenseRef-* identifiers.
var licenseRefPattern = regexp.MustCompile(`^LicenseRef-(scancode-|scanoss-|)(\S+)$`)

// extractedLicenses declares every LicenseRef the document will mention, which
// SPDX requires: a ref used in licenseDeclared but absent from
// hasExtractedLicensingInfos makes the document invalid.
//
// Refs come from three places, and all three have to be covered: an identifier
// that is itself a ref, refs nested inside an expression, and the ones minted
// here for identifiers SPDX does not recognise. seen carries across components so
// each ref is declared once per document.
func extractedLicenses(licenses []License, seen map[string]bool) []*v2_3.OtherLicense {
	var infos []*v2_3.OtherLicense
	for _, l := range licenses {
		refs := licenseRefsIn(l.ID)
		if _, ok := normalizeLicense(l.ID); !ok {
			if ref := licenseRef(l.ID); ref != "" {
				refs = append(refs, ref)
			}
		}
		for _, ref := range refs {
			if seen[ref] {
				continue
			}
			seen[ref] = true
			infos = append(infos, otherLicense(ref))
		}
	}
	return infos
}

// otherLicense builds the declaration for a single ref. A ref minted from a
// scanner's own vocabulary ("LicenseRef-scancode-foo") carries that source in the
// comment; the readable name is the idstring with its hyphens turned back into
// spaces.
func otherLicense(ref string) *v2_3.OtherLicense {
	name, sourceText := ref, "."
	if m := licenseRefPattern.FindStringSubmatch(ref); m != nil {
		name = strings.ReplaceAll(m[2], "-", " ")
		if source := strings.TrimSuffix(m[1], "-"); source != "" {
			sourceText = " by " + source + "."
		}
	}
	return &v2_3.OtherLicense{
		LicenseIdentifier: ref,
		LicenseName:       name,
		ExtractedText:     "Detected license, please review component source code.",
		LicenseComment:    "Detected license" + sourceText,
	}
}

func md5Hash(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}
