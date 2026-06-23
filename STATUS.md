# glassport — project status

Living snapshot of what's built, what's built-but-unshipped, and what's next.
Update when a tier changes. Last updated: 2026-06-23 (0.3.0 published — runtime SARIF released).

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

## Tier 2 — Built but NOT shipped to PyPI

**Empty — `pip install glassport` serves 0.4.0** (published 2026-06-23 via
tag-triggered trusted publishing). Everything is released, including the 0.4.0
additions: security hardening (ReDoS / symlink / path-traversal / log-dir
fixes) and GitLab CI + pre-commit distribution templates.

## Tier 3 — Roadmap (not built)

Roughly in dependency order — earlier unlocks later.

1. **Plugin registry for custom PII patterns** *(medium)* — let users register
   their own detector patterns without forking.
2. **Network-enriched audit** *(medium)* — opt-in npm/PyPI/GitHub provenance
   lookups; kept off the default path so the core audit stays offline/reproducible.
3. **Streaming detector path** *(large, architectural)* — detectors currently
   consume a *full in-memory trace* (batch). Streaming means processing frames as
   they arrive. This is the prerequisite for #4.
4. **Remote streamable-HTTP interception** *(large)* — today glassport is
   stdio-only. Remote MCP servers use a different transport (HTTP + SSE) that needs
   a different interception model. Depends on #3.
5. **Agent↔Agent (A2A) trace coverage** *(large)* — extend beyond Agent↔Tool to
   agent-to-agent protocols.

## Recently shipped

- **Security hardening** (0.4.0) — email-regex ReDoS, audit symlink traversal,
  `serve` path traversal, unwritable-log-dir crash; adversarial tests in
  `tests/test_comprehensive_security.py`. Credit: Kimi session.
- **GitLab CI + pre-commit templates** (0.4.0) — `.pre-commit-hooks.yaml`,
  `examples/gitlab-ci.yml`, README CI-integration section, CI integration job.
  Zero `src/` change.

## Next action

Repo and PyPI in sync at **0.4.0**. Pick a Tier-3 item — recommended next:
**#1 Plugin registry for custom PII patterns**.
