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

package parsers

import (
	"maps"
	"testing"
)

// TestDevDeclarations checks that each manifest's own way of declaring a
// development-only dependency sets Dev, and that a runtime one does not.
func TestDevDeclarations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		parse   ParserFunc
		file    string
		content string
		want    map[string]bool // purl -> Dev
	}{
		{
			name:    "package.json devDependencies",
			parse:   ParsePackageJSON,
			file:    "package.json",
			content: `{"dependencies": {"express": "^4.19.0"}, "devDependencies": {"jest": "^29.7.0"}}`,
			want:    map[string]bool{"pkg:npm/express@^4.19.0": false, "pkg:npm/jest@^29.7.0": true},
		},
		{
			name:  "package-lock.json dev entries",
			parse: ParsePackageLock,
			file:  "package-lock.json",
			content: `{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/express": {"version": "4.19.2"},
  "node_modules/jest": {"version": "29.7.0", "dev": true}
}}`,
			want: map[string]bool{"pkg:npm/express@4.19.2": false, "pkg:npm/jest@29.7.0": true},
		},
		{
			name:  "pom.xml test scope",
			parse: ParsePomXML,
			file:  "pom.xml",
			content: `<project><dependencies>
  <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency>
  <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
  <dependency><groupId>javax.servlet</groupId><artifactId>servlet-api</artifactId><version>2.5</version><scope>provided</scope></dependency>
</dependencies></project>`,
			want: map[string]bool{
				"pkg:maven/org.slf4j/slf4j-api@2.0.9":     false,
				"pkg:maven/junit/junit@4.13.2":            true,
				"pkg:maven/javax.servlet/servlet-api@2.5": false,
			},
		},
		{
			name:  "build.gradle test configurations",
			parse: ParseBuildGradle,
			file:  "build.gradle",
			content: `dependencies {
    implementation 'com.google.guava:guava:32.1.2-jre'
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation group: 'org.mockito', name: 'mockito-core', version: '5.5.0'
}
`,
			want: map[string]bool{
				"pkg:maven/com.google.guava/guava@32.1.2-jre": false,
				"pkg:maven/junit/junit@4.13.2":                true,
				"pkg:maven/org.mockito/mockito-core@5.5.0":    true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, err := tc.parse([]byte(tc.content), tc.file)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := map[string]bool{}
			for _, p := range result.Purls {
				got[p.Purl] = p.Dev
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("got purl -> Dev %v, want %v", got, tc.want)
			}
		})
	}
}
