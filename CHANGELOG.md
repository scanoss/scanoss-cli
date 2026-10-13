# Changelog — SCANOSS CLI

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`server` block in `raw` output** (`sbom.RawDocument.Server`): the batchScanner report's
  run/server metadata — the Knowledge Base version the scan matched against (`knowledge_base`
  with `monthly_version`/`daily_version`), plus `api_version`, `hostname` and `elapsed_ms`. It is
  provenance for the match results, carried through the `scan`, `scan <path>` and `results` paths
  and placed between `metadata` and `components`, mirroring the batch report's own shape. Additive
  and `omitempty`: a scan whose report carries no `server` block leaves the output byte-for-byte
  unchanged. `raw`-only — CycloneDX and SPDX have no field for the engine/KB versions.
  `engine_version` and `knowledge_base_latest` fields are modeled on the document already and will
  populate once a scanoss.api-sdk release surfaces them (the current SDK's `ScanServer` does not).

- **`match_index` on each matched file's evidence** in `raw` output (`sbom.FileEvidence.MatchIndex`,
  with `IsPrimary()`): where the component stood among the candidates the scanner returned for that
  file, after the BOM rules — `0` is the component the file originates from. From batchScanner
  v0.0.10 the scanner lists a file's matches origin first, and grouping the result by component
  had lost that order: anyone rebuilding a file's candidates from `raw` got them by `url_hash`,
  which put a fork or mirror first in ~12,000 files across the self-scans of known projects (curl
  2,548, go 1,785, gstreamer 1,775, node 1,664). The field is additive and omitted on `declared`
  evidence; consumers that do not read it are unaffected. When two catalog entries of one PURL and
  version fold into one component and both matched a file, the better-placed one is kept. CycloneDX
  and SPDX have no field for it (`evidence.occurrences` admits no properties), so it is `raw`-only.

- **`--identify` / `--ignore`** on `scan` and `results`, and the matching `bom.identify`
  (alias `bom.include`) and `bom.ignore` (alias `bom.exclude`) rules in `scanoss.json`.
  Both are applied client-side, over the candidate matches the batch scanner returns for
  each file: `ignore` drops the components it names, `identify` marks them
  `"identified": true` and moves them to the front of their file's matches. Naming an
  exact version is a stronger claim than naming the component alone. The flags accept a
  SCANOSS component list, CycloneDX, SPDX, or this client's raw output.
- **`--skip-headers` is on by default** on `scan` and `wfp`. A licence header is boilerplate
  shared by every file that carries it, so fingerprinting it makes unrelated files look alike.
  `--skip-headers=false`, or `skip_headers: false` in `scanoss.json`, restores the old
  behaviour. **This changes the WFP every scan produces**: a fingerprint taken with the filter
  on does not match one taken with it off.
- **`--skip-headers` / `--skip-headers-limit`** on `scan` and `wfp`, and
  `settings.file_snippet.skip_headers` / `skip_headers_limit` in `scanoss.json`. Drops each
  file's leading licence header, documentation comments and imports from its fingerprint,
  emitting a `start_line=` marker. Verified against the live API: filtering a GNU-licensed
  source moved the reported match from `[4-414]` to `[21-414]` and its percentage from 77% to
  75%, so the shared licence boilerplate no longer contributes to the match.
- **`--ranking-threshold`** treats rank `999` as unranked, not as the worst possible rank. It is
  `COMPONENT_DEFAULT_RANK`, the engine's sentinel for a component it has no ranking information
  about, and the engine's own "accept everything" bound is that value plus one. Because 999
  exceeds every threshold, filtering it would have dropped those components under *every*
  setting: a live scan of rdkb-2024q4 returned 23 of its 552 components at 999, accounting for
  2027 matched files that a threshold of 1 would otherwise have discarded for missing data
  rather than for explaining a match poorly. Rank `0` (an absent field) was already exempt.
- **`--ranking-threshold`** on `scan` and `results`, and
  `settings.file_snippet.ranking_threshold` in `scanoss.json`: drops matches whose component
  ranks worse than the threshold (`-1`..`10`; `-1` or `0` = off, out-of-range clamped with a
  warning). Applied client-side over the ranks the batch scanner reports, so nothing is asked
  of the server — `scanoss.py` sent this setting to the engine instead. Also
  **`scanoss.WithRankingThreshold`** and **`postprocess.WithRankingThreshold`**.
- **`scanoss.WithBOMReport`** hands back what the BOM selection rules concluded, and
  **`scansource.WithIdentified`** writes it onto `sbom.FileEvidence.Identified` per matched
  file, with `sbom.Component.Identified` summarising it. Per-file is the granularity a
  `path`-scoped rule works at: it claims a component in the files it covers and not in the ones
  outside. In CycloneDX the component-level flag rides as a `scanoss:identified` property; the
  per-file detail is `raw`-only, and SPDX can represent neither.
  `postprocess.Report` carries both answers, and `Report.IsIdentified(path, urlHash)` is the
  shape `scansource.WithIdentified` takes — so the SBOM adapter needs no type in common with
  the package that reached the verdict.
- **`scanoss.WithFingerprintOptions`** and the `wfp.Option` set (`wfp.WithSkipHeaders`)
  tune fingerprinting through `Scan.Folder`/`Scan.Files` and every `pkg/wfp` entry point.

### Changed

- **Components are ordered by what they explain, not by `url_hash`** — in `raw`, CycloneDX and
  SPDX alike: first by how many files they are the primary match of, then by how many files they
  match, with `url_hash` only breaking ties. A self-scan now lists the project first and the forks
  and mirrors that redistribute its files last.
- **`bom.replace` re-points a file at its own candidate** when the replacement PURL is one of them
  (the earliest in the file's order), instead of the catalog entry carrying that PURL with the
  lowest `url_hash`, which could be another release matched by a different file.
- **Model weight files are skipped by the default scanning and fingerprinting filters.**
  `filter.Scanning` and `filter.Fingerprinting` now drop `.safetensors`, `.gguf`, `.ggml`,
  `.bin`, `.onnx`, `.pt`, `.pth`, `.ckpt`, `.h5`, `.hdf5`, `.keras`, `.tflite`, `.pb`, `.npy`,
  `.npz`, `.pkl`, `.joblib`, `.mlmodel`, `.msgpack`, `.ot`, `.caffemodel` and `.nemo`. Each
  such file was read whole into memory to be fingerprinted, so a repository holding a few
  hundred-megabyte weights drove memory into gigabytes, and their bytes never produced a
  useful snippet match. `.bin` is included, so any other `.bin` file is skipped too. Callers
  that need these files must collect them separately, or pass `--all-extensions`
  (`BuiltinFileRules: false`) to drop the built-in file rules altogether.
- **The library skips licence headers by default too**, matching the CLI. `pkg/wfp`
  (`Folder`, `Files`, `Stream`, `StreamFolder`), `pkg/scanoss` (`Scan.Folder`, `Scan.Files`),
  `pkg/scanpipeline` and the `libscanoss` C exports now drop each file's leading licence header,
  comments and imports when no `wfp.Option` is passed, with no limit. **This changes the WFP
  every library caller produces**: a fingerprint taken with the filter on does not match one
  taken with it off, so a caller comparing against WFPs it stored earlier will see them differ.
  To opt out, pass `wfp.WithoutSkipHeaders()` (through `scanoss.WithFingerprintOptions` or
  `scanpipeline.Options.WFPOptions` when scanning). `wfp.WithSkipHeaders(limit)` keeps its
  meaning, on with that limit, and of the two options the last one passed wins. The CLI is
  unchanged: `--skip-headers=false` and `skip_headers: false` still turn the filter off.

### Fixed

- **`results <id>` now applies the BOM rules**, via a new `--settings` flag: `Scan.Wait`
  post-processes its result like a full scan does, so resuming an interrupted scan reaches
  the same output rather than reporting components the project's settings dismissed.
- **`bom.remove` protection honors both spellings** of the identify rule: a settings file
  using `bom.identify` rather than `bom.include` used to lose its protection from removal.

### Notes

- **`bom.identify` and `bom.ignore` match a component's canonical PURL, not its aliases.** One
  upstream project mined from several registries yields catalog entries that each carry the
  others' PURLs: scanning zephyr's `west` returns three components whose alias lists all name
  `pkg:pypi/west`, `pkg:github/zephyrproject-rtos/west` and `pkg:conda/west`. Comparing against
  aliases made one rule claim every candidate at once — which defeats `identify`, whose job is
  to pick which candidate is right, and made `ignore` drop components the user never named.
  This is what the engine does too (`asset_declared` reads `comp->purls[0]`). `bom.remove` and
  `bom.replace` still match aliases, as they always have.
- **The header filter counts newlines only**, diverging from `scanoss.py`, whose
  `str.splitlines()` also breaks on `\f`, `\v`, `\x1c`-`\x1e`, `\x85`, U+2028 and U+2029. A form
  feed — the GNU section separator — makes the reference implementation report an offset one
  line too high per separator, in a coordinate system the WFP does not use (its minutiae are
  numbered by `\n`), so it strips a line of real code. Offsets agree on 6527 of 6531 real source
  files; the 4 that differ each hold one form feed above the first line of code. Worth
  reporting upstream.

- **`bom.identify` protects its components from every filter** — `bom.ignore`, `bom.remove`
  and the ranking threshold. This diverges from the engine, which applies the threshold last
  and lets it overwrite the identified flag (`url.c`): reproducing that would discard a
  component the user stated was present because of a rule that names no component at all.
- `settings.file_snippet` **overrides** the `--skip-headers` and `--ranking-threshold` flags,
  the reverse of every other flag in this CLI. It is what `scanoss.py` does, and is
  documented in `CLIENT_HELP.md`.

## [0.8.0] - 2026-08-10

### Added

- **`components releases`** — list a component's releases (version, date, notes, url) for a
  PURL; `--requirement` narrows to a version or semver range, `--limit`/`--offset` paginate.
- **`scanoss.SetLogger`** routes every SDK package's diagnostics through one logger;
  `pkg/filter` reports the rules applied and each exclusion at Debug.
- **`sbom.Inventory.Add`** keeps one entry per component, merging evidence; a detected
  component wins over a declared one (scope and metadata).
- **`wfp.Stream`** fingerprints into an `io.Writer`, writing each file's block as it
  completes instead of holding the whole WFP in memory. Block order is completion
  order — scan results are unaffected; use `Files` for byte-reproducible output.
  `wfp.StreamFolder` is `Folder`'s collection with `Stream`'s memory profile.
- **`Scan.WFPReader`** scans a WFP read from an `io.ReaderAt` — `Scan.WFP` without the
  in-memory requirement, for a caller whose WFP lives in a file.

### Fixed

- **The SDK is silent until `SetLogger` is called** — no uninvited writes to stderr.
- **`Options.SkipDirs` and friends** now add to the built-in lists instead of replacing
  them, and still apply when the built-in flags are off.
- **`scan --include deps`** no longer applies the scanning folder rules to the manifest stage.
- **`DecorationPipeline.Run`** skips a non-decoration service with a warning instead of
  discarding the run.
- **A scan that fingerprinted nothing fails**, naming the cause.
- **An unset `Scope` counts as detected** on a merge, as the field documents.
- **Fingerprint failures are reported** (directories handed to `wfp.Files` included) and
  advance the progress callback, so `done` reaches `total`.
- **`wfp.Files`/`Folder` output and `Result.Files` are sorted by path** — multi-threaded
  runs of the `wfp` command are byte-reproducible. (The scan path streams instead and
  keeps completion order — see Changed.)
- **Inverted size bounds (`min` > `max`) are warned about and ignored** instead of silently
  excluding every matching file.

### Changed

- **An enrichment failure no longer fails the command** — it warns and still emits the base
  inventory, exiting 0.
- **The combined WFP stream is built once, as bytes** — the string-to-bytes conversion that
  duplicated the whole WFP in memory at its peak is gone.
- **The scan upload reads the WFP from any positional source** (`io.ReaderAt`) instead of
  requiring it in memory. Chunk requests keep their explicit length and can be replayed
  on a retry. No public API change.
- **`Scan.Folder` and `Scan.Files` spill the WFP to a temporary file and upload from
  it** — the stream never sits in memory whole, so peak memory no longer grows with the
  tree scanned. The uploaded WFP's block order is completion order and varies between
  runs; scan results are unaffected. `Scan.WFP` still takes the bytes it is handed.
- **BREAKING — the filter profiles read the project's settings themselves:**
  `filter.Scanning(s)`, `Fingerprinting(s)`, `Dependencies(s)`; `DefaultOptions` is gone.
- **BREAKING — `filter.Options` renames:** `FolderDefaults`/`FileDefaults` →
  `BuiltinFolderRules`/`BuiltinFileRules`, `PreserveDependencyManifests` → `KeepManifests`,
  `SkipExtensions` → `SkipExts`; new `SkipDirExts`, `SkipPatterns`, `SizeRules`.
- **BREAKING — `pkg/scanner` and `pkg/fingerprint/wfp` merge into `pkg/wfp`:** `Folder`
  collects and fingerprints; `Files` fingerprints a list as-is.
- **BREAKING — `scanpipeline`:** `Build`/`Enrich` give way to `Enricher` (returns an error);
  `Options.Filter`/`DependencySettings` → `ScanFilters`/`DependencyFilters`;
  `Result.ProcessErrors` is `[]error`; new `EnrichError`.
- **BREAKING — `scanpipeline` streams the WFP through a temporary file:** peak memory no
  longer grows with the tree scanned. `Result.WFP` is gone — pass `Options.WFPWriter` to
  keep the stream as it is generated (a file to save it, a `bytes.Buffer` for the old
  behavior). Block order is completion order and varies between runs.
- **BREAKING — `DependencyParser.ParseFiles` returns the per-file errors**
  (`map[string]error`) instead of printing them.
- **BREAKING — the `Service` values `DecorationPipeline` rejects are unexported.**
- **BREAKING — `pkg/output` is now `internal/output`.**

### Removed

- **BREAKING —** `scanner.GenerateWFP`, `wfp.GenerateFingerprint`, `wfp.CombineFingerprints`
  and `WorkerPool` (use `wfp.Folder`/`Files`); `scanner.CollectFiles`(`WithOptions`) (use
  `filter.Collect` with a profile); the exported filter matcher machinery; `settings.Resolve`
  and the per-operation `*Filter` helpers (compose `Detect(dir)` then `Load(path)`); the
  manifest-format types and string helpers in `dependencies/parsers` (use `ParseFile`);
  `settings.GetSBOMData`/`SBOMData`/`FormatSBOMParam` (v3 applies BOM rules through
  `pkg/postprocess`); `Config.Logger` (use `scanoss.SetLogger`).
- `parsers.RemoveDuplicates`, `output.Writer.WriteFormat`, `DefaultPostSize`, `GRAM_WFP1`,
  `WINDOW_WFP1`.

## [0.7.0] - 2026-08-03
### Fixed

- **A transient network error no longer discards a whole scan.** Network errors, truncated
  responses and 429/5xx are retried with exponential backoff; a `Retry-After` still wins.
- **A chunk the server already holds no longer fails the scan.** `409 RANGE_CONFLICT` means the
  upload completed, so it counts as success.
- **A partial enrichment no longer passes for a complete one.** The components a failed request
  left without data are named on stderr.

### Added

- **`Config.RetryBackoffBase`** — the first backoff wait, doubled per attempt (default 250ms).

### Changed

- **`Config.MaxRetries` covers every transient failure**, not only a 429/503 with `Retry-After`.
  A negative value disables retries, as `Timeout` does.
- **BREAKING — `Config.MaxRetryAfter` is now `Config.MaxServerRetryWait`.**
- **BREAKING — the decoration pipeline result is typed per layer.** `PipelineResult.Services`
  gives way to `Licenses`, `Cryptography`, `Geoprovenance` and `Vulnerabilities`, each a
  `*Layer[T]`; an unreadable response lands in `Errors`.
- **BREAKING — `ChunkError.Index` is now `ChunkError.Purls`**, naming the components left
  without data.
- **BREAKING — the `scansource` adapters lose their `From` suffix**: `FromScanResult` →
  `Inventory`, `LicensesFrom` → `Licenses` and likewise the rest; `LicenseKey` → `Key`.

### Removed

- **`scanoss.As` and `scanoss.Result`** (with `Responses`, `Merged`, `Unmarshal` and `String`) —
  no exported function returned a `*Result`, so none of them could be reached from outside.

## [0.6.0] - 2026-07-31

### Fixed

- **A component's `rank`, `release_date` and `artifact_name` reach the inventory.** All three
  were dropped, so two components matching the same file looked equally strong.
- **A request is bounded by a 120s timeout** (`Config.Timeout`; negative disables it).
  Waiting for a server that accepted the request and went quiet had no bound before.
- **Any 2xx counts as success.** A `201` or `204` used to surface as an error.

### Removed

- **The `attributions` command** — `POST /sbom/attribution` is not in the v3 contract.
  Use `licenses attribution`.
- **`pkg/api` and `pkg/batch`** — a second transport stack with no context, retries or
  timeout, used only by the C bindings, which now go through `pkg/scanoss`.
- **`scanoss.NewHTTPClient` and `scanoss.HTTPClientOptions`** are now private.

### Changed

- **`scanoss.New(Config) (*Client, error)`** replaces `scanoss.Option` and the `With*`
  client options; `Proxy`, `CACertFile`, `InsecureTLS` and `Timeout` are now fields.
- **`WithScanIDNotify` is a `ScanOption`**, passed to the scan call, not to the client.

## [0.5.0] - 2026-07-30

### Added

- **`bom.replace` is applied.** A scan result whose match is covered by a replace rule is now
  re-pointed at the rule's `replace_with` component; previously the rule's PURL was sent to the API
  but the result was never rewritten, so the section did half its job in silence. Rules are scoped
  by `purl`, `path` or both, and where several cover one file the most specific wins. Applied after
  `bom.remove`, and only to matches that survived it. The `license` field of a replace rule is not
  supported yet.

### Fixed

- **The scan progress bar no longer runs backwards.** The server scans in passes that each restart
  their own counter, and the bar was fed those numbers directly: it reached 100%, dropped back, and
  finished a successful scan drawn near empty.
- **A scan whose session expired no longer hangs.** `expired` is terminal, but was treated as "still
  running", so the CLI polled a dead session until interrupted.
- **A command invoked without its required argument now fails.** It printed its help to stdout and
  exited `0`, so `scanoss-cli scan $DIR` with an unset variable reported success having scanned
  nothing and fed usage text to whatever consumed the results. Help now goes to stderr and the exit
  code is non-zero. A namespace command with no subcommand (`scanoss-cli config`) still succeeds:
  it was not asked to do anything.
- **`scanpipeline.Run` rejects a nil `Options.Client` instead of panicking.** The client was only
  reached inside the scan goroutine, so the panic could not be recovered by the caller and `Run`
  returned a nil error as the process was torn down.
- **Upload progress is reported once per block, in order.** Every upload worker reported
  concurrently, so `ScanReporter.Uploading` received duplicated and out-of-order counts: an upload
  bar ran backwards and settled below 100% because the last report was not the highest. Calls are
  now serialised, which also means a reporter needs no lock of its own.
- Enrichment layers appear when they start rather than when their first response arrives.

### Changed

- **BREAKING — progress is reported per stage.** `Progress`, `ProgressFunc`, `WithProgress`,
  `PipelineProgress`, `DecorationPipeline.OnProgress` and `.Snapshot` are removed. Use
  `ScanReporter` and `DecorationReporter`, registered per call with `WithScanReporter` and
  `WithDecorationReporter`; every decoration method takes `opts ...DecorateOption`.
- **BREAKING — `pkg/scanpipeline` reports every layer through `Options.OnProgress`**, replacing
  `OnCollect`, `OnFingerprint`, `OnDependencies` and the SDK's separate callback.
- **BREAKING — `pkg/scanpipeline` no longer parses `--include`.** `Layer`, `Set` and `ParseLayers`
  moved to the CLI; `Options` takes `Services` and `SourceDeclared`; `Build` and `Enrich` changed
  signature.
- **BREAKING — `--default-filters` is replaced by `--all-extensions` and `--all-folders`** on `scan`
  and `wfp`. In the library, `filter.Options.Defaults` splits into `FileDefaults` and
  `FolderDefaults`.
- The scan status is polled every 2 seconds rather than 5.

## [0.4.0] - 2026-07-29

### Added
- **`config`** — store `api-url`, `api-key`, `proxy` and `ca-cert` in
  `~/.scanoss/settings.json` instead of repeating flags: `config set`, `get`, `list`, `unset`,
  `path`. The API key is never displayed. Every setting resolves as
  **flag > `SCANOSS_<KEY>` > config file > default**.
- **`--proxy` and `--ca-cert`** on every command that reaches the API. `--proxy` overrides
  `HTTP_PROXY`/`HTTPS_PROXY` for one run and honours `NO_PROXY`; `--ca-cert` adds a PEM file's
  certificates to the system pool, verification still on. PAC is not supported.
- **`scanoss.NewHTTPClient`** builds an `*http.Client` with the same proxy and CA settings.
- **`--min-size` / `--max-size`** on `scan` and `wfp`, and **`--all-hidden`** to include dotfiles
  (version-control metadata stays excluded).
- **`--default-filters`, `--gitignore` and `--settings` on `wfp`**, so it collects files exactly
  the way `scan` does. **`--settings` on `dependencies`** likewise.
- **SDK:** `filter.FingerprintOptions`, `filter.DependencyOptions`, `filter.HiddenSource`,
  `settings.FingerprintFilter()`, `settings.DependencyFilter()`.

### Changed
- Files under 100 bytes are no longer skipped.
- **`pkg/filter` is the single source of filtering rules**, applied once during collection. The
  fingerprint layer no longer filters, so `GenerateWFP` and `GenerateFingerprint` fingerprint
  whatever they are given — a caller passing a list that did not come from collection now gets
  every file. **This is the only change here that fails silently rather than at compile time.**
- **SDK, breaking** — removed: `wfp.ShouldSkipFile`, `filter.NewMatcher`,
  `filter.DefaultSkippedDirs`, `filter.IngestOptions`, and `filter.Defaults`'
  `MinSize`/`MaxSize`. Use `filter.Build(filter.DefaultSource(filter.StdDefaults()))` plus
  `manifests.Is` to compose rules; `filter.CommonSkippedDirs` /`ScanOnlySkippedDirs`
  /`DependencyOnlySkippedDirs`; `filter.DependencyOptions`; and `filter.Options.MinSize`/`MaxSize`.
  Callers starting from `DefaultOptions`/`ScanOptions` need no change.

### Fixed
- **Version-control metadata is never collected.** `.git` could be fingerprinted and uploaded when
  the built-in filters and the hidden rule were both off — including `.git/config`, which can carry
  credentials.
- **License identifiers are validated against the SPDX list.** A non-canonical id is normalised;
  an unrecognised one, or a malformed expression, becomes a declared `LicenseRef` instead of
  producing an SBOM that fails validation.
- **SBOM packages carry the component name**, not the full PURL. CycloneDX gained a
  `serialNumber`, and the tool version moved to its own field.
- **`results` returns the same inventory as `scan`**, so a resumed scan can be rendered and
  converted. It accepts `--format` and `--include`.
- **`--default-filters=false` really disables them** — extension-skipped files were dropped anyway
  by a second, uncounted filter in the fingerprint layer.
- **`dependencies` honours `scanoss.json`** and reports what it filtered; `scan --include deps`
  and `dependencies` no longer disagree over `examples/`. A `skip` rule now also overrules the
  manifest exemption, so excluding a manifest by name works.
- `--min-size`/`--max-size` were ignored together with `--default-filters=false`.
- Zero-byte files and symbolic links are no longer fingerprinted, and the raw format emits
  `"components": []` rather than `null` when nothing matched.

## [0.3.0] - 2026-07-28

### Changed
- **BREAKING** — the raw inventory format now reports matched line ranges as structured objects
  (`{"start_line": 82, "end_line": 209}`) instead of `"82-209"` strings, matching the shape the scan
  engine already returns. `schema_version` is `2.0`; a `1.0` document carrying string ranges no
  longer parses. CycloneDX and SPDX output is unchanged.

## [0.2.0] - 2026-07-27

### Changed

- Renamed the CLI binary from `scanoss` to `scanoss-cli`. The `go install` path is now
  `go install github.com/scanoss/scanoss.go/cmd/scanoss-cli@latest`.

## [0.1.0] - 2026-07-16

Initial release of the SCANOSS Go CLI and SDK (`scanoss`).

### Added

- **`scan <path>`** — fingerprint a file or folder (WFP winnowing), upload to the SCANOSS v3 batch
  API in parallel chunks, and poll to completion; an interrupted scan resumes with
  `scanoss results <scan-id>`. `--format raw|spdx|cyclonedx` selects the output and
  `--include deps,vulns,licenses,crypto,geo` opts into extra layers, narrowed to what the chosen
  format can render (a layer it can't represent is skipped with an up-front notice).
  `scan wfp <file>` scans a pre-generated WFP.
- **`wfp <path>`** — generate WFP fingerprints only, without uploading.
- **`results <scan-id>`** — resume or poll a previous scan by its id.
- **`sbom <input>`** — offline: produce an SBOM from a scanoss raw inventory, or convert between
  CycloneDX 1.7 and SPDX 2.3 (input format detected from content). No API calls; best-effort (data
  a target can't represent — e.g. SPDX vulnerabilities — is dropped with a warning).
- **`enrich <input>`** — online: decorate an existing raw inventory, CycloneDX, or SPDX with the
  purl-keyed layers `vulns`/`licenses`/`crypto`/`geo`, with no source tree or re-scan (re-runnable
  to refresh). The output format defaults to the input's; `--format` converts in the same pass.
- **`dependencies [path]`** — parse local manifests, or query direct/transitive dependencies for a
  PURL.
- **`attributions [sbom]`** — attribution text from an SBOM file or a PURL.
- **Decoration commands** over the SCANOSS Services API v3: `vulnerabilities`, `licenses`,
  `cryptography`, `geoprovenance`, `copyright`, and `components`.
- **`raw` output** (default) — a neutral inventory in a versioned envelope (`schema_version` +
  `metadata` + `components` + `vulnerabilities`): detected and declared components in one
  `components` list tagged by `scope`, per-component layers (`licenses`, `cryptography`,
  `geoprovenance`) inline, and vulnerabilities as a flat top-level list. Each component records
  where it came from in `evidence` — scanned files that matched (`match_type` `file`/`snippet`) or
  the manifest that declared it (`match_type` `declared`). A bare scan (no `--include`) makes no
  decoration calls.
- **SBOM export** — SPDX 2.3 and CycloneDX 1.7, with the SCANOSS `url_hash` preserved (an SPDX
  `OTHER` external reference / a CycloneDX `scanoss:url_hash` property) and vulnerability detail
  (CVSS score/vector/method, CWE, EPSS).
- **Declared dependencies** (`--include deps`) are sourced directly from the project's manifests
  (`package.json`, `go.mod`, …) and decorated alongside the scan matches — no dependency-resolution
  round trip.
- **File filtering** — built-in defaults, `.gitignore`, and `scanoss.json` rules; client-side
  `bom.remove`.
- **Progress & status output** — live progress bars for every phase (fingerprint, upload, server,
  dependency parsing, each enrichment layer); status notices with icons and color (`⚠` warnings,
  `ℹ` info, `✓` success) on an interactive terminal (Windows 10+ included), disabled when
  piped/redirected or `NO_COLOR` is set; a `Results written to <path>` line for `--output`.
- **`-v, --verbose`** — structured `log/slog` debug output on stderr (the scan flow, each API
  request with method/URL/status/duration, fingerprinting, and decoration).
- **Go SDK** (`pkg/scanoss`) — scan and decoration services with a parallel decoration pipeline;
  `pkg/scanpipeline` assembles a neutral `sbom.Inventory`, and `pkg/sbom` reads and writes
  CycloneDX and SPDX (with `WithTool`/`WithAuthor`/`WithTimestamp` document-metadata options).
- **C shared library** (`libscanoss`) with Node.js and Python bindings.

[0.8.0]: https://github.com/scanoss/scanoss.go/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/scanoss/scanoss.go/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scanoss/scanoss.go/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/scanoss/scanoss.go/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/scanoss/scanoss.go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scanoss/scanoss.go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scanoss/scanoss.go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scanoss/scanoss.go/releases/tag/v0.1.0
