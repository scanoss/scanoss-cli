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

package wfp2

// These two tables ARE the wfp2 normalization contract: the byte Normalizex emits
// for a token is looked up here, so every value must stay byte-identical to the miner
// (scanoss-go pkg/fingerprint/wfp2) and the engine port (engine src/wfp2.c). Changing
// a code, adding a word, or reordering nothing of consequence here still re-keys the
// fingerprint and makes it stop matching the mined KB. Do not "clean up" these maps.

// elementsMap maps a reserved word or punctuation token to the single byte that
// represents it in the normalized stream. The reserved byte values 0 (type-run marker),
// 0xff (any other identifier), and the skipped 1/9/10/32/255 never appear as values
// here. elementsMap is consulted before typesMap, so a token that is both (e.g. "true")
// takes its element code.
var elementsMap = map[string]uint8{ //0: variable type, skip: 0,1,9(\t),10(\n),32(space),255
	"alias": 2, "alignas": 3, "alignof": 4, "and": 5, "as": 6, "asm": 7,
	"assert": 8, "async": 11, "await": 12, "base": 13, "become": 14,
	"begin": 15, "bindattr": 16, "bindingattr": 17, "bitand": 18, "bitor": 19,
	"break": 20, "case": 21, "catch": 22, "cdecl": 23, "?": 24,
	"checked": 25, "compl": 26, "concept": 27, "continue": 28, "crate": 29, "debugger": 30,
	"declare": 31, "declspec": 33, "def": 34, "default": 35, "defer": 36,
	"defined": 37, "del": 38, "delete": 39, "deriving": 40, "do": 41,
	"@": 42, "dyn": 43, "dynamic": 44, "elif": 45, "else": 46, "elseif": 47, "elsif": 48,
	"end": 49, "endfor": 50, "endforeach": 51, "endif": 52, "endswitch": 53, "endwhile": 54,
	"eq": 55, "esac": 56, "except": 57, "explicit": 58, "export": 59,
	"extends": 60, "fallthrough": 61, "far": 62, "fastcall": 63,
	"feature": 64, "fi": 65, "finally": 66, "fixed": 67, "owns": 68, "fn": 69,
	"for": 70, "foreach": 71, "forever": 72, "forsome": 73, "friend": 74, "from": 75,
	"function": 76, "get": 77, "global": 78, "goto": 79, "has": 80, "id": 81,
	"if": 82, "impl": 83, "implements": 84, "implicit": 85, "import": 86, "in": 87,
	"include": 88, "infix": 89, "inherit": 90, "inout": 91,
	"instanceof": 92, "spawn": 93, "deref": 94, "offsetof": 95,
	"is": 96, "lambda": 97, "lateinit": 98,
	"lazy": 99, "leave": 100, "let": 101, "local": 102, "lock": 103,
	"loop": 104, "macro": 105, "match": 106, "me": 107, "module": 108,
	"namespace": 109, "new": 110, "next": 111, "nil": 112, "no": 113,
	"nocopy": 114, "none": 115, "nonlocal": 116, "not": 117,
	"of": 118, "on": 119, "open": 120, "operator": 121,
	"or": 122, "out": 123, "override": 124, "package": 125, "parallel": 126,
	"params": 127, "partial": 128, "pass": 129, "past": 130, "print": 131,
	"printf": 132, "procedure": 133, "pure": 134, "raise": 135, "rec": 136,
	"receiver": 137, "redim": 138, "reified": 139,
	"remove": 140, "repeat": 141, "require": 142, "required": 143, "resource": 144,
	"resume": 145, "return": 146, "safe": 147, "sealed": 148,
	"select": 149, "self": 150, "send": 151, "set": 152, "setparam": 153, "semaphore": 154,
	"sizeof": 155, "stdcall": 156, "step": 157,
	"sub": 158, "super": 159,
	"suspend": 160, "switch": 161, "tailrec": 162, "then": 163,
	"this": 164, "thread": 165, "throw": 166, "throws": 167, "to": 168,
	"true": 169, "try": 170,
	"unchecked": 171, "undef": 172,
	"unless": 173, "unsized": 174,
	"until": 175, "use": 176, "using": 177, "val": 178, "value": 179, "var": 180,
	"wasm": 181,
	"weak": 182, "when": 183, "where": 184, "while": 185, "with": 186, "xor": 187,
	"/": 188, "yield": 189, "yieldto": 190, "subroutine": 191, "ensure": 192, "behind": 193, "exec": 194,
	// Special characters (punctuation and symbols) - 195-255
	"!": 195, "\"": 196, "#": 197, "$": 198, "%": 199,
	"&": 200, "'": 201, "(": 202, ")": 203, "*": 204,
	"+": 205, ",": 206, "-": 207, ".": 208,
	":": 210, ";": 211, "<": 212, "=": 213, ">": 214,
	"[": 217, "\\": 218, "]": 219,
	"^": 220, "`": 221, "{": 222, "|": 223, "}": 224,
	"~": 225} //others:255

// typesMap is the set of type keywords. A maximal run of consecutive type tokens
// collapses to a single 0x00 in the normalized stream (see Normalizex), so "unsigned
// long int" and "int" look the same past the first type. Multi-character entries that
// a single [a-z0-9_] token can never equal (e.g. "interface{}", "&str", "real*4") are
// kept verbatim for fidelity with the reference tables.
var typesMap = map[string]bool{
	// C/C++ types
	"char": true, "short": true, "int": true, "long": true, "float": true, "double": true,
	"void": true, "signed": true, "unsigned": true, "bool": true, "true": true, "false": true,
	"wchar": true,

	// C/C++ modifiers and combinations
	"const": true, "volatile": true, "static": true, "extern": true, "auto": true, "register": true, "inline": true,
	"mutable": true, "restrict": true, "constexpr": true, "consteval": true, "constinit": true, "noexcept": true,

	// Type declarators
	"class": true, "struct": true, "union": true, "enum": true, "interface": true,
	"typedef": true, "typename": true, "typealias": true, "type": true, "typeid": true, "typeof": true, "decltype": true,
	"trait": true, "protocol": true, "delegate": true, "event": true,

	// Access modifiers
	"public": true, "private": true, "protected": true, "internal": true, "pub": true,
	"abstract": true, "virtual": true, "final": true, "sealed": true, "readonly": true,
	"synchronized": true, "transient": true, "strictfp": true, "native": true, "unsafe": true,

	// Pointer/Reference related
	"ptr": true, "ref": true,

	// Java types
	"byte": true, "boolean": true, "integer": true, "character": true,
	"string": true, "object": true,

	// C# types
	"sbyte": true, "ushort": true, "uint": true, "ulong": true, "decimal": true,
	"int16": true, "int32": true, "int64": true, "uint16": true, "uint32": true, "uint64": true,
	"single": true,

	// JavaScript types
	"number": true, "undefined": true, "null": true, "symbol": true, "bigint": true,

	// Python types
	"str": true, "list": true, "dict": true, "tuple": true, "set": true, "frozenset": true,
	"bytes": true, "bytearray": true,

	// Go types
	"int8":    true,
	"uint8":   true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
	"rune": true, "uintptr": true, "interface{}": true, "chan": true,
	"func": true, "map": true, "slice": true,

	// Rust types
	"i8": true, "i16": true, "i32": true, "i64": true, "i128": true, "isize": true,
	"u8": true, "u16": true, "u32": true, "u64": true, "u128": true, "usize": true,
	"f32": true, "f64": true, "&str": true,
	"vec": true, "option": true, "result": true, "box": true, "rc": true, "arc": true,

	// SQL types
	"varchar": true, "real": true, "text": true, "blob": true,
	"numeric": true, "timestamp": true, "datetime": true,
	"date": true, "time": true, "smallint": true,
	"tinyint": true, "mediumint": true, "binary": true, "varbinary": true,

	// Pascal/Delphi types
	"cardinal": true, "shortint": true, "longint": true, "comp": true,
	"currency": true, "extended": true, "real48": true,
	"ansichar": true, "widechar": true, "ansistring": true, "widestring": true,
	"shortstring": true, "pchar": true, "pwidechar": true,

	// FORTRAN types
	"logical": true, "complex": true, "real*4": true,
	"real*8": true, "integer*2": true, "integer*4": true,

	// COBOL types
	"pic": true, "picture": true, "comp-1": true, "comp-2": true, "comp-3": true,
	"comp-4": true, "comp-5": true, "packed-decimal": true, "display": true,

	// Swift types

	"array": true, "dictionary": true,

	// Kotlin types

	"shortarray": true, "intarray": true, "longarray": true,
	"floatarray": true, "doublearray": true, "booleanarray": true, "vhararray": true,
}
