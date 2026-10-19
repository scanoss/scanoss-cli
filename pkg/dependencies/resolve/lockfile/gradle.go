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
	"fmt"
	"strings"

	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/internal/build"
)

// parseGradleLockfile reads gradle.lockfile, which has a line
// "group:artifact:version=configuration,..." per locked module and no
// edges. It does not say which modules the build file declares, so every
// module is a member that is not direct, and none is dev: the builder marks
// dev only what dev direct dependencies reach.
func parseGradleLockfile(b *build.Builder, data, _ []byte, members map[string][]byte) {
	b.NameRoot(members)
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coords, _, ok := strings.Cut(line, "=")
		if !ok {
			b.Flag(resolve.ReasonMalformed, fmt.Sprintf("line %q has no configurations", line))
			return
		}
		if coords == "empty" {
			continue
		}
		parts := strings.Split(coords, ":")
		if len(parts) != 3 || parts[0] == "" {
			b.Flag(resolve.ReasonInvalidEntry, fmt.Sprintf("%q is not group:artifact:version", coords))
			continue
		}
		b.Node(parts[0], parts[1], parts[2])
	}
	b.Flag(resolve.ReasonEdgesUnknown, "gradle.lockfile records no edges")
}

// isGradleBuild reports whether name is a Gradle build file, which sits
// beside its gradle.lockfile.
func isGradleBuild(name string) bool {
	return name == "build.gradle" || name == "build.gradle.kts"
}
