# glassport — project status

Living snapshot of what's built, what's built-but-unshipped, and what's next.
Update when a tier changes. Last updated: 2026-07-03 (0.6.3 — Kimi round-2 renderer hardening: shared `neutralize_text` folds NFKC/fullwidth + math-alphanumeric homoglyphs and exotic whitespace, two-pass Zalgo collapse survives ZWJ interleave, `stripe_key` credential, unit-locked. 0.6.2 was the initial report/sarif poisoning-resistance).

## Tier 1 — Built, tested, in the repo

Source is the truth; this is the index.

| Capability | Module | What it is |
|---|---|---|
| Passive tap (`wrap`) | `tap.py` | stdio man-in-the-middle; logs every JSON-RPC frame, never alters one |
| HTTP tap (H2.01) | `adapters/mcp_http.py` | `wrap --transport http --url <remote>`: local MITM proxy over MCP Streamable-HTTP (POST/GET/SSE); streams SSE to the client while framing each event, reuses `SessionLog` so the trace is identical to stdio; fail-open |
| Active gate (`gate`) | `tap.py` | blocks `tools/call` outside the declared surface; opt-in enforcement |
| Session summary | `tap.py` (`summarize`) | declared vs. called vs. fabricated delta |
| Detectors | `detectors.py` | annotations over a trace: fabricated calls, context/schema violations, **data exfiltration** (PII/credentials) |
| HTML report | `report.py` | self-contained static report, severity-colored |
| Drift watch | `watch.py` | fingerprints sessions, flags behavioral change over time |
| Static audit | `audit.py` | AST + pattern source scan, scored vs. published rubric (v0.3) |
| SARIF export (static) | `sarif.py` | audit findings → SARIF 2.1.0 → GitHub Security tab |
| SARIF export (runtime) | `sarif.py` / `tap.py` | detector annotations → SARIF 2.1.0 located into the session `.jsonl`; `summarize --sarif` |
| MCP query server (`serve`) | `server.py` | glassport itself as an MCP server; the agent queries its own history |
| TUI | `tui.py` | live curses session inspector |
| Custom-PII plugin registry | `detectors.py` | consumer-extensible patterns separate from built-ins: `register_pii_pattern()`, `load_pii_patterns_from_json()`, `GLASSPORT_PII_PATTERNS` env autoload |
| Named validators | `detectors.py` | precision menu: `luhn`/`ssn`/`entropy`/`entropy_high`/`entropy_auto` (per-charset) + checksum `iban`/`aba` + crypto `base58`/`jwt`/`uuid4` |
| Agent advisory (`advise`) | `advise.py` / `tap.py` | folds audit Report + runtime annotations into a fenced agent-md block; stdout or `--write` |
| Coverage gate + e2e (H1.08) | `.github/workflows/ci-coverage.yml` / `tests/test_e2e_filesystem.py` | opt-in `coverage` job (core pipeline `--fail-under=85`, whole-repo informational) + wire-reality test driving real `@modelcontextprotocol/server-filesystem` through `glassport wrap`; skips cleanly without node ≥18 |
| Network-enriched audit (H2.03) | `provenance.py` / `audit.py` | opt-in `audit --provenance` (npm+PyPI direct deps): not-in-registry/deprecated/stale/single-maintainer/unsigned. Separate channel — default audit byte-identical and unscored; stdlib urllib; never-expire `--provenance-cache` |

## Tier 2 — Built but NOT shipped to PyPI

**Empty — `pip install glassport` serves 0.6.3** (published via tag-triggered
trusted publishing, tag `v0.6.3`). 0.6.3 is the Kimi round-2 renderer hardening
(PR #33): shared `detectors.neutralize_text` NFKC-folds fullwidth + math-
alphanumeric homoglyphs, reveals exotic whitespace (Zs/Zl/Zp), collapses Zalgo
runs in two passes so a ZWJ interleave can't reset the counter, plus a
`stripe_key` credential pattern — all unit-locked. 0.6.2 was the initial
report/sarif poisoning-resistance: `report.py` (`session.html`) neutralizes
deceptive Unicode and redacts secrets; `sarif.py` redacts credentials from
finding path/fingerprint/message; both bound output against DoS; the report and
sarif grills join advise as CI merge gates (PRs #29, #30). 0.6.1 was the
`run_tap` shutdown-abort patch (PR #26); 0.6.0 shipped `advise` (PR #20) + its
quote-or-redact hardening (PR #21) + the P1–P11 grill (PR #22).

## Tier 3 — Roadmap (not built)

Roughly in dependency order — earlier unlocks later.

1. ~~**Network-enriched audit** *(medium)* — opt-in npm/PyPI provenance
   lookups; kept off the default path so the core audit stays offline/reproducible.~~
   ✅ Shipped (H2.03) — `audit --provenance` (npm+PyPI direct deps);
   `provenance.py` is the only network-touching module; separate
   `Report.provenance` channel keeps the default audit byte-identical and
   unscored; stdlib `urllib` (zero-dep); never-expire `--provenance-cache` for
   air-gapped re-runs. GitHub provenance deferred to a later increment.
2. ~~**Agent-advisory output (`advise`)** *(small)* — emit a `CLAUDE.md` /
   `AGENTS.md` / `GEMINI.md` "observations worth noting" section from a run's
   findings, so the next agent session inherits what the watchdog saw. A fourth
   renderer over existing data (audit `Report` + detector annotations); no new
   detection. **Security-load-bearing:** the output writes into an agent's
   instruction surface — the exact tool-poisoning vector glassport audits for —
   so it must emit glassport's own classification sentences + redacted tags,
   never echo attacker-controlled bytes. Fenced `glassport:begin/end` markers
   for idempotent, human-reversible writes.~~ ✅ Shipped
3. **Streaming detector path** *(large, architectural)* — detectors currently
   consume a *full in-memory trace* (batch). Streaming means processing frames as
   they arrive. This is the prerequisite for #4.
4. **Remote streamable-HTTP interception** *(large)* — today glassport is
   stdio-only. Remote MCP servers use a different transport (HTTP + SSE) that needs
   a different interception model. Depends on #3.
5. **Agent↔Agent (A2A) trace coverage** *(large)* — extend beyond Agent↔Tool to
   agent-to-agent protocols.

## Recently shipped

- **HTTP-relay round-4 SSE framing** (0.6.7, this PR) — a self-driven pre-probe
  of the SSE/connection surfaces before handing them to the Kimi loop. Two fixes:
  an **SSE response is now close-delimited** (`Connection: close` + `close_connection`)
  so the client gets a prompt EOF when the upstream ends the stream instead of
  hanging on a kept-alive socket (SSE has no Content-Length and the proxy strips
  the upstream's chunked TE); and the SSE trigger matches the **media type**, not
  any substring, so `application/json; note=text/event-stream` can't flip a normal
  body onto the SSE path and drop its Content-Length. Plus green safety-locks: a
  2 MB no-terminator SSE flood stays memory-bounded (relay sacred), and a pipelined
  request after an ambiguous body can't desync. 610 tests. Remaining SSE-event and
  header-path residue handed to Kimi in `dogfood/SPEC-http-relay-redteam.md`.
- **HTTP-relay round-3 framing** (0.6.6) — the least-grilled response
  path, continued. Fix: a **lying-short `Content-Length`** (declares more than it
  sends, then closes) used to hold the client on a kept-alive socket until its own
  timeout; the proxy now forces a connection close on the shortfall so the client
  gets a prompt EOF (can't verify pre-headers without buffering — that is the R1
  DoS). Plus green safety-locks proving two surfaces are already sound: a chunked
  upstream reaches the client cleanly de-chunked, and a bare-LF header smuggle is
  normalized so the CL-dedup catches it. New `dogfood/SPEC-http-relay-redteam.md`
  hands Kimi the open surfaces (SSE stream abuse, connection/hop-by-hop). 607 tests.
- **HTTP-relay hardening** (0.6.5, PR #53) — the Streamable-HTTP MITM relay
  (`adapters/mcp_http.py`) bounded against a hostile upstream/client: R1 chunked
  bounded request/response copy (memory + session-log DoS), R2 rejection of
  ambiguous request framing (Transfer-Encoding / duplicate Content-Length), R3 a
  30s handler socket timeout (slowloris). Response framing tightened so a duplicate
  **or comma-folded / non-numeric** `Content-Length` can't desync the client — CL
  is forwarded only when a single purely-numeric value with no Transfer-Encoding,
  else dropped and close-delimited. Relay stays sacred (every byte reaches the
  client). `dogfood/eval_http_relay_redteam.py` is a CI + release gate. 605 tests.
- **Agent advisory (`advise`)** — `advise.py` + `tap.py` CLI verb.
  `glassport advise [--audit <path>] [--session <s.jsonl>] [--write FILE] [--all]`
  folds a static audit `Report` and runtime detector `Annotation`s into a single
  ranked markdown block for agent-instruction files (`CLAUDE.md` / `AGENTS.md` /
  `GEMINI.md`). Default severity floor 2; `--all` lowers to 0. Output is wrapped in
  `<!-- glassport:begin -->`/`<!-- glassport:end -->` markers; `--write` splices
  the block in place (idempotent; append when absent, replace when present; refuses
  on malformed markers). Reporter-not-gate: exits 0 on success, 2 when neither
  `--audit` nor `--session` is given. Output is glassport's own sentences only —
  never raw server bytes; `_sanitize_inline` wraps every attacker-controlled value;
  matched source snippets are omitted. 344 tests.
- **Custom-PII plugin registry + validator menu** (0.5.0, PRs #15–#19) —
  `register_pii_pattern()` / `load_pii_patterns_from_json()` /
  `GLASSPORT_PII_PATTERNS` env autoload (registry kept separate from built-ins);
  M2 checksum validators (`iban` default, `aba` opt-in); crypto-token validators
  (`base58` opt-in, `jwt` wired onto the default pattern, `uuid4` menu-only);
  M3 per-charset `entropy_auto`; Kimi R3 fixes (JWT→AWS span suppression,
  Cyrillic-homoglyph fold). 317 tests.
- **Security hardening** (0.4.0) — email-regex ReDoS, audit symlink traversal,
  `serve` path traversal, unwritable-log-dir crash; adversarial tests in
  `tests/test_comprehensive_security.py`. Credit: Kimi session.
- **GitLab CI + pre-commit templates** (0.4.0) — `.pre-commit-hooks.yaml`,
  `examples/gitlab-ci.yml`, README CI-integration section, CI integration job.
  Zero `src/` change.

## Next action

**Released 0.6.5; 0.6.6 (relay round-3) in this PR.** `0.6.5` is live on PyPI
(relay hardening R1–R3 + response Content-Length framing, PR #53); `0.6.4` shipped
H1.08 coverage/e2e + H2.03 `audit --provenance`. **H2.01 streamable-HTTP tap**
(`wrap --transport http --url`) is **merged to main** (PR #51) — passive MITM over
Streamable-HTTP (POST/GET/SSE), trace-identical to stdio, fail-open — and now
hardened by the round-2/round-3 relay work above.

Next: the open relay surfaces are handed to the **Kimi loop** in
`dogfood/SPEC-http-relay-redteam.md` (SSE stream abuse, connection/hop-by-hop).
On the roadmap: **gate over HTTP**
(active c2s blocking on the HTTP path — H2.01 shipped passive only), the
**streaming-detector path** (frame-at-a-time analysis), **H2.06 property-based
validator tests** (`hypothesis` dev-dep already merged), and GitHub provenance
(follow-up to H2.03).
