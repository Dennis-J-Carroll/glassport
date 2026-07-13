# Changelog

All notable changes to glassport. Generated from git history by
`scripts/gen_changelog.py` — edit that script, not this file.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

### Added
- SessionLog.file_mode/close for permission verification
- char-indexed normalization with origin map

### Fixed
- reviewed phonetic-extension manifest closes Kimi round-3 gaps
- close issue #64 combining-mark + small-capital normalization gap
- make unwritable-dir test cross-platform (Windows CI red)
- remove duplicate close(), widen file_mode() exception guard
- close renderer-boundary defensive gaps (Kimi pass 3)
- redact provenance fields in json + text renderers (ADJ-1/2)
- strict-redact + validate provenance fields (P0 evidence-safety)
- merge overlapping spans before redaction splice
- span-aware redaction removes obfuscated secrets

### Changed
- open_session_log verifies mode + degrades (HTTP like stdio)
- Update README.md
- reject empty/partial userinfo in remote URL
- drop Connection-nominated hop-by-hop headers both ways
- reject port 0 and whitespace hosts; accurate port error
- strict remote-URL validation + userinfo-free Host
- _scan_pii_spanned carries normalized spans

### Documentation
- 0.6.9 Security & Truthfulness implementation plan
- 0.6.9 Security & Truthfulness design

### Internal
- PR #67 round-3 closure verification cases
- document round-3 manifest resolution
- preserve PR #66 provenance red-team findings
- document issue #64 resolution + process note
- grill closes issue #64 (combining-mark + small-capital)
- byte-identical relay proof, logging on vs off
- pass-3 grill cases + findings classification
- mark ADJ-1/ADJ-2 fixed in findings
- preserve provenance renderer red-team findings
- permanent CI grill for redaction/artifact evidence-safety
- grill Connection-nominated hop leak both directions
- isolate redaction at report+SARIF boundary
- grill report+SARIF against obfuscated secrets

## [0.6.8] - 2026-07-10

### Fixed
- forward the upstream query string (H2)

### Changed
- refuse 101 upgrade; drop private stdlib symbols (H1)
- redaction fails closed in shareable artifacts (S2)
- create session log 0o600 / dir 0o700, umask-independent (S1)
- 0.6.8 — relay round-5 (bundles unreleased 0.6.7 round-4)
- SSE-log bound, all-1xx skip, CT/204/304/dup-CL framing
- 0.6.7 — relay round-4 SSE framing
- close-delimit SSE + match SSE media type, not substring

### Internal
- grill 101 upgrade refusal (H1)
- round-5 grill cases + SPEC write-up
- round-4 SSE grill cases + narrow the Kimi charge

## [0.6.6] - 2026-07-10

### Changed
- 0.6.6 — relay round-3 framing (lying-short Content-Length)
- close connection on lying-short response Content-Length

### Internal
- bump checkout@v5 + setup-python@v6 off the Node20 runtime
- round-3 grill surfaces + Kimi brief

## [0.6.5] - 2026-07-10

### Added
- GET SSE + DELETE + wrap --transport http CLI (H2.01 C+D)
- streamable-HTTP MITM proxy — JSON + SSE (H2.01 A+B)

### Changed
- reject comma-folded / non-numeric response Content-Length
- bound the relay path — R1 DoS, R2 smuggling, R3 slowloris
- land Kimi red-team fixes + close 3 gaps

### Documentation
- record 0.6.5 relay hardening; H2.01 merged; round-3 next
- H2.01 streamable-HTTP interception — phased TDD plan

### Internal
- grill the comma-folded Content-Length desync
- trace parity + fail-open; docs (H2.01 E)

## [0.6.4] - 2026-07-06

### Added
- render/sarif/CLI integration, byte-identical default
- module — discovery, urllib client, cache, rubric, enrich
- H1.08 — coverage gate + e2e integration test
- add opt-in PII pattern for Azure service principal client secrets
- differentiate severity-2 from severity-1 with 256-color palette
- tap self-metrics line + `glassport health`
- retention for the session log dir — dry-run by default
- typed public API — py.typed + lazy re-exports
- CHANGELOG.md generated from git history
- ? help overlay; drain KEY_RESIZE storms
- CRT frontend — single-file, air-gapped, hostile-data-safe
- web console server — stdlib HTTP + RFC 6455 WebSocket
- incremental ingest — _TraceBuilder fold + StreamingSession
- mouse support — click to select, wheel scroll, click closes overlay
- runtime gate control — opt-in on both ends, fail-closed
- audit & advisory overlay — a key, optional --audit PATH
- drift panel — d side panel, D full-screen, watch.py as engine
- incremental search — / opens bar, live jump, n/N cycle matches
- multi-session tabs — Ctrl+T cycle, Ctrl+W close, per-tab ingest cache

### Fixed
- 3.10 fallback ignores env-marker literals; docs
- improve error message when log directory is unwritable
- skip e2e on Windows (npx.cmd needs a shell the tap avoids)
- read files with explicit utf-8 so Windows cp1252 can't crash
- use explicit file context managers in _cmd_advise
- make Windows matrix jobs pass
- 0.6.3 — match main's released version
- surface tail_only everywhere + share the cap with batch
- sync __version__ with pyproject — 0.5.0 -> 0.6.2
- confine audit_server to allowed roots — default-deny cwd
- q/esc could never dismiss an accepted search — quit was trapped

### Changed
- v0.6.4 — bump __version__ + pyproject in lockstep
- rename azure_client_secret to high_entropy_token_30_40, add to _GENERIC_SECRETS, add hex charset boundary suppression tests
- glassport[tui] extra ships Windows curses shim

### Documentation
- H2.03 network-enriched audit — 10 TDD tasks
- H2.03 network-enriched audit design
- survey engine, Used-By section, measured perf, Show-HN draft
- SECURITY.md threat model + CONTRIBUTING.md doctrine clause
- serve --http usage in USAGE

### Internal
- 3-OS matrix, analysis benchmark, hardened release path

## [0.6.3] - 2026-07-03

### Fixed
- close renderer Unicode-deception gaps (Kimi round 2)

### Changed
- v0.6.3 — Kimi round-2 renderer hardening

### Documentation
- Kimi red-team spec for the report + sarif grills

### Internal
- unit-lock neutralize_text + stripe_key (Kimi round 2)
- grill rows for the round-2 renderer gaps (Kimi)

## [0.6.2] - 2026-07-02

### Fixed
- bound renderer output and collapse Zalgo runs
- redact credentials from finding path, fingerprint and message
- neutralize deceptive Unicode and redact secrets in session.html

### Changed
- v0.6.2 — renderer poisoning-resistance (report.py / sarif.py)

### Documentation
- red-team closeout & next steps (as of v0.6.1)

### Internal
- grill rows for renderer DoS + Zalgo bounds
- gate merges and releases on the poisoning-resistance grills
- sarif.py red-team grill
- report.py HTML-renderer red-team grill

## [0.6.1] - 2026-07-01

### Fixed
- exit run_tap via os._exit to avoid daemon-stdin shutdown abort

### Changed
- v0.6.1 — run_tap daemon-stdin shutdown-abort fix

## [0.6.0] - 2026-07-01

### Added
- glassport advise CLI verb
- pure fenced-block splice (append/replace/idempotent/refuse)
- static section with snippet omission
- render_advisory runtime section + verdict + clean-run
- surface tool name as structured metadata for advise
- _sanitize_inline anti-poisoning primitive
- severity folding reused from sarif
- base58check, JWT-structural, UUIDv4 validators (M2 recipe)
- M3 per-charset entropy validator (entropy_auto)
- M2 checksum validators — IBAN + ABA routing
- fill _NAMED_VALIDATORS — the JSON-path precision menu
- custom-PII-pattern plugin registry (register API + JSON loader + env autoload)

### Fixed
- redact backtick-homoglyph + identifier-shaped secrets; Armenian/Hangul normalization
- redact backtick-homoglyph + identifier-shaped secrets; Armenian/Hangul normalization
- quote-if-safe-else-redact in _sanitize_inline (closes fence-breakout + directive-survival)
- quote-if-safe-else-redact in _sanitize_inline (closes fence-breakout + directive-survival)
- sanitized severity, repo-relative base, fallback tests
- pristine test reads + guard trailing value-flag
- JWT→AWS false positive + Cyrillic-homoglyph evasion (Kimi R3)

### Changed
- v0.6.0 — advise + red-team grill + poisoning-resistance hardening
- ABA routing is opt-in, not a default pattern

### Documentation
- note the advise red-team grill in the roadmap
- Kimi adversarial brief for the advise grill
- advise red-team grill implementation plan
- advise red-team grill — steelman glassport against itself
- ship advise — STATUS, README
- advise — agent-md advisory implementation plan
- advise — agent-facing advisory output design
- sync roadmap to 0.5.0
- note Cyrillic/Greek homoglyph fold and structural-token suppression
- record M2 IBAN/ABA checksum validators
- document the custom-PII-pattern plugin registry

### Internal
- advise red-team grill — P1–P11 poisoning-resistance harness
- Kimi red-test rows P6–P11 (markdown-link, armenian, hangul, modifier-grave, secret-name, audit-path)
- drive real detector in result-leak test
- layer-2 result-side homoglyph leak row
- exempt glassport fence markers in no_live_directive; grill green
- advise grill runner (records P2 fence-breakout finding)
- pure oracle invariant checkers
- hostile fixtures for advise grill
- add glassport-runtime job (detect --sarif) to the GitLab template

## [0.5.0] - 2026-06-24

### Added
- descriptive rule text for pii_* and context-violation findings
- repo-relative location URIs for runtime SARIF (Security tab resolvability)
- add --sarif flag emitting runtime SARIF 2.1.0

### Fixed
- pass full session path to render_session_sarif so _seq_to_line keeps line numbers
- split tool_errors from protocol_errors; correct dogfood record

### Changed
- bump version to 0.5.0

### Documentation
- document detect --sarif and the glassport-runtime CI upload
- runtime-SARIF detect CLI + CI + coverage plan
- Kimi worktree workspace note + eval targets

### Internal
- lock detect --sarif line-number resolution; note why base is not threaded
- upload runtime-detector SARIF to the Security tab (glassport-runtime)
- hostile mock MCP server + eval + findings
- audit filesystem, github, fetch, exa MCP servers behind glassport

## [0.4.0] - 2026-06-23

### Added
- GitLab CI + pre-commit templates (roadmap #1) (#12)

### Changed
- bump version to 0.4.0

### Security
- harden ReDoS, symlink/path traversal, log-dir failure (Kimi) (#11)

### Documentation
- STATUS — 0.3.0 published, repo and PyPI in sync

## [0.3.0] - 2026-06-23

### Added
- runtime-annotation SARIF export (roadmap #1) (#8)

### Changed
- bump version to 0.3.0
- Feat/runtime annotation sarif (#10)
- 0.2.0 (version bump + release/status docs) (#5)
- Docs/document serve command (#6)
- Harden scanners against hostile input; rubric v0.3 capability-note tier (#3)
- Data-exfiltration detector, SARIF export, audit suppression (#2)
- Add agent-integration layer: gate hold, detect/serve CLI, summarize --json

### Documentation
- STATUS — runtime SARIF merged to main, awaiting 0.3.0 release
- document `glassport serve` queryable MCP server in README (#4)
- PyPI badge, console-script examples, src-layout structure

## [0.1.0] - 2026-06-11

### Changed
- drop ? help overlay — footer permanently shows all seven bindings
- survive file rotation; canonical server-request predicate; fast Esc
- curses shell — dashboard, picker, overlay, subcommand wiring
- clamp stale selection on re-ingest; findings can shrink
- clarify reduce() mutation contract; test overlay scroll clamp
- pure key-action reducer for focus/selection/follow/overlay
- session picker listing with LIVE detection
- findings feed and frame-detail overlay formatting
- timeline rows — clock, direction arrows, labels, severity
- view-model header — identity, counters, gate, declared surface
- Add TUI implementation plan
- Add TUI design spec: live session inspector
- Package for PyPI: src layout, console script, CI
- Update tagline in README
- Polish README: badges, TOC, architecture diagram, unified detection table
- Add MIT license, logo, and README header image
- Fold in static audit: source-level pre-deployment scan, AST + rubric
- M5: the gate — opt-in enforcement, blocking undeclared tools/call
- M4: watch mode — session fingerprints and cross-session drift alerts
- M3: static HTML session report (report.py + report subcommand)
- M2: context_violations() detector; model server-initiated traffic in the adapter
- Assemble repo layout; route summarize through the InteractionTrace adapter

### Documentation
- TUI status, roadmap, and quick-start mention

### Internal
- release workflow — tag-triggered PyPI publish via trusted publishing
