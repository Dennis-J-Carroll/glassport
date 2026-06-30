# glassport — project status

Living snapshot of what's built, what's built-but-unshipped, and what's next.
Update when a tier changes. Last updated: 2026-06-29 (0.5.0 published — PII plugin registry + checksum/crypto/entropy validators).

## Tier 1 — Built, tested, in the repo

Source is the truth; this is the index.

| Capability | Module | What it is |
|---|---|---|
| Passive tap (`wrap`) | `tap.py` | stdio man-in-the-middle; logs every JSON-RPC frame, never alters one |
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

## Tier 2 — Built but NOT shipped to PyPI

**Empty — `pip install glassport` serves 0.5.0** (published via tag-triggered
trusted publishing, tag `v0.5.0`). Everything is released, including the 0.5.0
additions: the custom-PII plugin registry and the checksum/crypto/entropy
validator menu (PRs #15–#19).

## Tier 3 — Roadmap (not built)

Roughly in dependency order — earlier unlocks later.

1. **Network-enriched audit** *(medium)* — opt-in npm/PyPI/GitHub provenance
   lookups; kept off the default path so the core audit stays offline/reproducible.
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

Repo and PyPI in sync at **0.5.0**. Tier-3 #1 (plugin registry) and Tier-3 #2
(`advise`) shipped. Pick a Tier-3 item — recommended next: **#1 Network-enriched
audit** (independent, medium) before the large streaming rearchitecture (#3).
