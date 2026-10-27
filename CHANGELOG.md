# Changelog

All notable changes to glassport. Generated from git history by
`scripts/gen_changelog.py` — edit that script, not this file.
Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [Unreleased]

### Changed
- Fix concurrent replay order and harden live detector limits (#124)
- Detect live surface mutation, declaration poisoning, and encoded secrets (#123)

### Internal
- attach dist to an existing GitHub release instead of failing (#122)

## [0.8.0] - 2026-10-26

### Added
- add opt-in strict HTTP evidence-gap blocking (#112)
- accept --port for http wrap and gate (#101)

### Fixed
- read only release tags and refuse shallow writes (#121)
- close Phase 3a review gaps in capture evidence (#115)
- make evidence claims and session diagnostics precise

### Changed
- 0.8.0 — provable decision bundles (#120)
- Phase 4: public gate hardening and acceptance matrix (#119)
- Phase 3b.1: secure public bundles and classify verify exits (#117)
- Phase 3b: replayable decision bundles and CI artifact (#116)
- Phase 3a: session provenance, bound journals, and stable finding IDs (#114)
- Phase 2: evidence-level claims across gate, journal, and reports (#113)

### Documentation
- define tested per-path enforcement contract
- move internal working notes out of the public tree (#109)
- correct Sem recipe and guide against a verified literal run (#105)
- add local code lookup capture recipe for Sem MCP (#103)
- add recipes policy (#104)
- add a Parallel Search MCP capture recipe (#99)

### Internal
- skip journal permission test when running as root (#108)
- skip journal permission test when running as root (#106)
- pin server-filesystem and wait for the tools/call reply (#102)

## [0.7.1] - 2026-10-15

### Fixed
- no catalog downgrade for tool files; scan shipped bundles >1 MB
- close comment-demotion bypasses in tool-poisoning scoring
- real --version, help and <verb> --help; refuse unknown commands
- scan shipped dist/, root identity, context-scored tool-poisoning

### Changed
- 0.7.1 — audit credibility floor

### Documentation
- correct stale gate claims and document audit context rules

## [0.7.0] - 2026-10-11

### Added
- add `glassport probe`, a one-command client with partial reports
- stateless 2026-07-28 declaration scopes for the HTTP gate
- gate mode checks 2026-07-28 header/body agreement and the declared era
- opt-in strict fault policy for the gate (`gate --strict`)
- optional Ed25519 attestation verification, off by default (glassport[attestation] extra)
- structural com.glassport/attestation _meta checks, detect-only
- OWASP ASI / CSA MAESTRO taxonomy tags on SARIF rule properties
- tool-shadowing and unbounded-schema audit across a session-log registry
- ttlMs/cacheScope temporal integrity + additive-vs-mutative schema drift classification
- Jensen-Shannon Divergence drift score over tool-call vocabulary
- quarantine tainted resources/read content before it reaches the client
- live-block severity-3 PII/secret exfiltration at the gate
- wire-level idempotency circuit breaker on repeated identical tools/call
- enum/nested schema checks, live-enforced at the gate before dispatch
- semantic taint detection, live-blocked at the gate and surfaced post-hoc
- extract Gate block-payload builder, add data.reason/data.suggestion
- explicit HTTP enforcement gate (Task 4)
- isolate HTTP observations in bounded session epochs
- separate event policy decisions from transport enforcement
- stream PII and egress analysis with full detector replay parity
- migrate context and schema checks to event-time state
- stream fabricated-call detection with batch replay parity
- add bounded incremental MCP session state

### Fixed
- stop echoing a secret prefix in secret-hardcoded detail
- probe leaves the server env untouched and only reads its own log
- an ambiguous id on the refused request itself waives no block
- a refused HTTP request never becomes a pending correlation
- stdio gate declaration follows the shared SessionState contract
- use a plain import for the header-token pattern
- long-lived HTTP scopes cannot be weakened by eviction, leaks or faults
- only a complete reply can supersede a tool declaration
- gate admission and the observer agree on what a JSON-RPC message is
- a caller can no longer switch HTTP gate enforcement off for a session
- gate mode refuses a tools/call without a valid request id
- a stale tool declaration stops being enforcement authority
- gate mode refuses HTTP requests it cannot read, and non-loopback Host/Origin
- refuse gate --strict over HTTP instead of silently ignoring it
- label JSON-RPC batch events and word tool-less gate replies
- reports state the real gate block reason and show quarantines and batches
- detect chat-template special tokens as role delimiters
- treat JSON with duplicate keys as uninspectable in the gate
- quarantine rewrites always emit strict JSON
- gate scans all tools/call params and refuses what it cannot fully read
- quarantine resources/read-shaped replies whatever their id
- surface-timeout fail-open no longer skips independent gate checks
- refuse JSON-RPC batches whole in the enforcing gate
- close gate parser differentials: inspect big integers, never forward unreadable frames
- gate override disables enforcement only for a literal false
- harden the server-to-client gate path against hostile frame shapes
- summarize and detect print lone surrogates escaped instead of crashing
- surface every skipped gate check in gate_skipped annotations
- close caller-triggerable gate exceptions that the relay guard would forward
- keep the relay alive on frames too deep to parse, without forwarding them unread
- treat malformed tools/call params and tool names as undeclared
- a faulting gate check no longer skips the checks after it
- block tools/call arguments nested past a fixed depth before scanning
- stop malformed schema fields from downgrading mutative drift
- block unsignable attested calls and keep boundary checks after attestation errors
- preserve temporal findings across tools list refreshes
- handle boolean and malformed property schemas during drift analysis
- canonicalize attestation signatures and preserve visible fail-open behavior
- skip mkdir-permission decision-journal test on non-POSIX
- final-review fix wave — coverage gate, stale HTTP docs, oversized-body regression test, doc mechanism fix
- stale HTTP-gate comment + dedupe bench_scanner --modes
- locate the decisive journal record by watermark, not by guessing
- make the candidate block verdict mode-independent
- make DecisionJournal fail-open guarantee structural, not caller-dependent
- align HTTP credential routing and capture sequence evidence
- distinguish scanner benchmark failures
- close HTTP upstream resources on every relay exit (#77)
- preserve metadata-limit diagnostics through event replay
- close HTTP upstream resources on every relay exit (#77)
- require observed call-time declarations for fabricated calls (#76)

### Changed
- 0.7.0 — probe, HTTP enforcement gate, audit redaction fix
- Record decisions and delivery outcomes in observation mode
- Quarantine ambiguous and evicted request IDs within session bounds
- Fix declaration correlation before policy enforcement
- 0.6.10 evidence pack — gates A–D, V1 verdict, owner-log guide
- Delete footer section from README

### Documentation
- record the probe GIF from probe.tape and put it above the report still
- probe report screenshots and the VHS tape for the README GIF
- reword probe docstring so the self-audit's runtime-install rule stays quiet
- rewrite README as a one-screen front door around probe
- move the full README to docs/guide.md and clear the repo root
- stateless routing design and phases for the HTTP gate
- attestation under gate --strict and without a declared surface
- README screenshots from a real gated session; refresh the gate section
- record exact-head CI result (18/18) in release notes
- add HTTP enforcement release and migration notes
- record benchmark diagnostics fix
- require declaration correlation repairs before HTTP integrity
- specify bounded HTTP integrity implementation stages
- define review and HTTP enforcement follow-up sequence

### Internal
- mark main as 0.6.11.dev0
- scope gate-override assertions to POSIX; lock fail-closed off POSIX
- regression-lock SARIF severity mapping and detail redaction
- keep local review ledger artifacts untracked
- stabilize coverage instrumentation with measured scanner benchmarks

## [0.6.10] - 2026-07-15

### Fixed
- preserve named-event SSE metadata without losing parseable JSON-RPC frame

### Changed
- 0.6.10 — HTTP tap named-event SSE framing fix
- HTTP tap loses tools/list + result correlation on named-event SSE

### Documentation
- HTTP-inclusive tagline + refresh STATUS 'Next action'
- correct stale 'remote HTTP interception' future-work claims
- clarify oracle independence + record perf-methodology follow-up

### Internal
- loosen incremental-poll wall-clock bound to 1.5s
- loosen incremental-poll wall-clock bound to 1.5s

## [0.6.9] - 2026-07-13

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
- 0.6.9 — version bump + truthfulness pass
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
