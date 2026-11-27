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

// Package logging is where this module's logging is wired: the sink every package
// reports through, and the handler the CLI installs into it.
//
// Nothing takes a logger as a parameter or holds one in a field. Most of this module is
// local computation — filtering, fingerprinting, parsing manifests, rendering SBOMs —
// with no client to hang a logger off, so a per-instance logger would reach a fraction
// of it. A single sink with a global setter covers all of it in one call.
// Logs go to stderr so stdout stays reserved for results/SBOM/JSON output.
package logging

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

// sink receives every log this module emits. It discards until an application asks for
// logs: a library writing to its consumer's stderr uninvited is a bug, not a feature.
// The silence is paired with a global setter, so one call covers every package rather
// than one client.
var sink atomic.Pointer[slog.Logger]

func init() { Set(nil) }

// Set routes this module's logs to lg. A nil lg restores silence.
//
// The pointer swap is atomic, but a logger changed while calls are in flight can still
// split a run's output across two destinations. Call it during initialisation.
func Set(lg *slog.Logger) {
	if lg == nil {
		lg = slog.New(slog.DiscardHandler)
	}
	sink.Store(lg)
}

// Debug and Warn are what this module's packages call. There is no Info: a library has
// nothing to say about its normal operation that its consumer did not already ask for —
// that is Debug — and nothing between "working" and "something is wrong".
func Debug(msg string, args ...any) { sink.Load().Debug(msg, args...) }

// Warn reports something the caller may want to act on but that did not stop the work.
func Warn(msg string, args ...any) { sink.Load().Warn(msg, args...) }

// Enabled reports whether a record at level would be written. Use it to skip building
// arguments nobody will read — a per-file skip reason over a large tree, for one.
func Enabled(level slog.Level) bool {
	return sink.Load().Enabled(context.Background(), level)
}

// Configure builds the CLI's handler on stderr, installs it as both the process default
// and this module's sink, and returns it. Debug when verbose, Warn otherwise, so a normal
// run stays quiet and only surfaces warnings and errors.
func Configure(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger) // for cmd/ and internal/, which log through slog directly
	Set(logger)             // for pkg/, which logs through this sink
	// The analysis engine (reach) logs through zerolog's global logger, at info by default.
	zlevel := zerolog.WarnLevel
	if verbose {
		zlevel = zerolog.DebugLevel
	}
	zlog.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true}).Level(zlevel).With().Timestamp().Logger()
	return logger
}
