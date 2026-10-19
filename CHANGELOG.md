# Changelog — SCANOSS CLI

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`pkg/dependencies/resolve/toolchain`** builds the dependency graph by running the
  ecosystem's own tools on a manifest, for projects whose lockfile does not record the whole
  graph. It resolves `go.mod` with `go list -m all` and `go mod graph`: the members are the
  modules the build selects, the edges run between those selected versions, and `replace` is
  applied as for the `go.mod` lockfile. A tool problem never fails the call; it is reported on
  the root with the new reasons **`tool_missing`**, **`tool_failed`** and **`timeout`**
  (`unknown`), or **`registry_unreachable`** (`partial`, with the modules the tool resolved
  without the registry). The tools run on files the scanned repository controls, so callers
  run them in an isolated sandbox. They need no credentials, take the registry or mirror from
  `Options.Env`, and each run has a timeout and capped output. Only Go is resolved for now.

## [0.12.0] - 2026-10-19

### Added

- **`pkg/dependencies/resolve`**, a dependency graph with edges: nodes are `purl@version`, and
  each manifest is a root with its members, its edges and a status (`complete`, `partial` or
  `unknown`) with a reason. `Member.Direct` tells declared packages from those only in the
  lockfile. `Node.Local` marks the project's own packages, such as a workspace, path crate or
  `PATH` gem that another package depends on; they keep their edges, so consumers skip them to list third-party
  packages without losing what they pull in.
- **`Member.Dev` and `Root.DevKnown`** tell dev dependencies from runtime ones, per root: a
  member is dev when the root reaches it only through its dev dependencies, so it can be left
  out of an SBOM. `DevKnown` is false when the manifests do not say which direct dependencies
  are dev, and then no member is dev. `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml`
  read `devDependencies`, `Cargo.lock` the member manifests' `[dev-dependencies]`,
  `Gemfile.lock` the `development` and `test` groups of the `Gemfile`, which it now reads,
  `poetry.lock` the dev groups of `pyproject.toml`, `uv.lock` each root's `dev-dependencies`
  groups, and `composer.lock` `require-dev`.
- **`pkg/dependencies/resolve/lockfile`** builds that graph from `package-lock.json` (v2 and v3,
  including nested `node_modules` versions and workspaces), `yarn.lock` (v1 with `package.json`,
  and berry with workspaces), `pnpm-lock.yaml` (5.x, 6.x and 9.x), `Cargo.lock` (with a root
  per workspace member when the member manifests are available), `Gemfile.lock`, `poetry.lock`
  (with `pyproject.toml`) and `composer.lock` (with `composer.json`). It runs no process, and
  caps the bytes, nodes and edges it accepts from a lockfile.
- **`npm-shrinkwrap.json`, `uv.lock` and NuGet `packages.lock.json`** are resolved too. `uv.lock`
  gives a root per workspace member at its `pyproject.toml`. `packages.lock.json` merges every
  target framework into one root named after the project file beside it, with the solution's
  other projects as local nodes; it does not record dev dependencies.
- **`gradle.lockfile`, `Pipfile.lock` and `go.mod`** are resolved as module lists. They pin
  every package but record no edges, so their roots are `partial` with the new reason
  **`edges_unknown`**. `Pipfile.lock` reads the `Pipfile` for direct and dev dependencies, and
  `go.mod` marks requirements without `// indirect` as direct and applies `replace`.
- **`dependencies --extract-local --graph`** prints the dependency graph resolved from every
  lockfile under the path, merged into one JSON document, so the resolver can be tried on a
  real project.
- **`dependencies --extract-local --format raw|cyclonedx|spdx`** renders a project's dependencies
  as the same inventory `scan --include deps` writes, with no API call. Without `--format` the
  command prints the flat per-file list it always did.
- **The dependency graph in every output format.** `raw` (`schema_version` `2.1`) adds a
  `dependencies` list with one root per resolved manifest (lockfile, ecosystem, status, reason,
  `dev_known`, `direct`, edges), marks the components a root pulls in transitively with the `transitive`
  match type, and marks the project's own packages with `local`. CycloneDX adds an
  `application` component per root, a `dependencies`
  entry for every component and a `compositions` entry per root (`complete`, `incomplete` or
  `unknown`), and a `scanoss:local` property. SPDX adds a project package the document
  `DESCRIBES`, a package per root and `DEPENDS_ON` relationships, and a `scanoss:local` comment.
- **`pkg/sbom/depsource`** builds an `sbom.Inventory` from a project's dependency files: the
  lockfile graph with dev members pruned, plus the manifests no lockfile covers parsed flat. It
  is what `scan --include deps` and `dependencies --format` share.

### Changed

- **`scan --include deps` lists the lockfile-resolved versions in place of the manifests' range
  entries.** Where `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`,
  `Gemfile.lock`, `poetry.lock` or `composer.lock` covers a manifest, the output lists every
  runtime package the lockfile resolved, direct and transitive, with its edges, instead of
  entries such as `pkg:npm/left@^1.0.0`. Dev dependencies are left out of every format. A
  lockfile that cannot be read gives an `unknown` root with no packages. Manifests no lockfile
  covers (`pom.xml`, `go.mod`, `requirements.txt`, …) keep their flat declared entries.
- **`github.com/pelletier/go-toml/v2` updated to v2.4.3**; v2.2.4 panics on some malformed TOML.
- **CycloneDX `metadata.component` always carries a `bom-ref`** (the project name), so the
  dependency graph has something to hang from and a consumer can address the project.
- **`sbom` and `enrich` skip the project and root placeholders** when reading a CycloneDX or
  SPDX document, so an `application` component without a purl no longer becomes a component
  named after a manifest. The graph itself round-trips through `raw` only.

## [0.11.0] - 2026-10-14

### Changed

- **Direct dependencies updated to their latest releases**, including `scanoss.api-sdk` v0.31.0 and
  `cyclonedx-go` v0.12.0.

### Security

- **Binaries, the Docker image and libscanoss are now built with Go 1.27.2.** The module now
  requires Go 1.26 or later.

## [0.10.0] - 2026-10-07

### Added

- **`match_index`** on each matched file in `raw` output: the component's place among the file's
  candidates, `0` being the file's origin. Rebuilding a file's candidates from `raw` no longer puts
  a fork or mirror first.

### Changed

- **Components are ordered by the files they explain**, primary matches first, in every output
  format. A self-scan now lists the project first and its forks and mirrors last.
- **`bom.replace` re-points a file at its own candidate** with the replacement PURL, rather than
  any catalog entry with that PURL, which could be a different release.

## [0.9.0] - 2026-09-28

### Added

- **`confidence` on each matched file's evidence** (`LOW`, `MEDIUM` or `HIGH`), the reliability
  grade the scanner gives each match. It was previously dropped from the output.

## [0.8.3] - 2026-09-26

### Changed

- **Model weight files are skipped by default** when scanning and fingerprinting (`.safetensors`,
  `.gguf`, `.onnx`, `.pt`, `.bin` and similar). Any `.bin` file is now skipped; pass
  `--all-extensions` to include them.

## [0.8.2] - 2026-09-23

### Changed

- **Breaking: the library skips licence headers by default**, matching the CLI, so the WFPs library
  callers produce change. Pass `wfp.WithoutSkipHeaders()` to keep the old fingerprints; the CLI is
  unaffected.

## [0.8.1] - 2026-09-17

### Added

- **`--identify` / `--ignore`** on `scan` and `results`, and `bom.identify` / `bom.ignore` in
  `scanoss.json`: `ignore` drops the named components, `identify` marks them `"identified": true`
  and moves them first. Both match a component's canonical PURL, not its aliases.
- **`--skip-headers` / `--skip-headers-limit`** on `scan` and `wfp`, on by default: licence headers,
  comments and imports are left out of the fingerprint. This changes every WFP;
  `--skip-headers=false` restores the old ones.
- **`--ranking-threshold`** on `scan` and `results` drops matches from components ranked worse than
  the threshold. Unranked components are never dropped.
- **`scanoss.WithBOMReport`, `scanoss.WithRankingThreshold` and `scanoss.WithFingerprintOptions`**
  expose the same features to library callers.

### Fixed

- **`results <id>` applies the BOM rules** through a new `--settings` flag, so resuming a scan gives
  the same output as a full scan.
- **`bom.remove` protection honors `bom.identify`** as well as `bom.include`.

### Notes

- `bom.identify` protects its components from `bom.ignore`, `bom.remove` and the ranking threshold.
- `settings.file_snippet` in `scanoss.json` overrides the `--skip-headers` and `--ranking-threshold`
  flags, as in `scanoss.py`.

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

[Unreleased]: https://github.com/scanoss/scanoss.go/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/scanoss/scanoss.go/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/scanoss/scanoss.go/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/scanoss/scanoss.go/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/scanoss/scanoss.go/compare/v0.8.3...v0.9.0
[0.8.3]: https://github.com/scanoss/scanoss.go/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/scanoss/scanoss.go/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/scanoss/scanoss.go/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/scanoss/scanoss.go/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/scanoss/scanoss.go/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scanoss/scanoss.go/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/scanoss/scanoss.go/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/scanoss/scanoss.go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scanoss/scanoss.go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scanoss/scanoss.go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scanoss/scanoss.go/releases/tag/v0.1.0
