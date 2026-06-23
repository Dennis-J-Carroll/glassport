# glassport — project status

Living snapshot of what's built, what's built-but-unshipped, and what's next.
Update when a tier changes. Last updated: 2026-06-23 (0.2.0 published; runtime-annotation SARIF landed).

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

**Empty — `pip install glassport` serves 0.2.0** (published 2026-06-23). `serve`,
SARIF export, rubric v0.3, scanner hardening, and the `data_exfiltration`
detector all shipped in it. Runtime-annotation SARIF (below, just landed on a
branch) will go out in the next release. See `RELEASING.md` for the cut process.

## Tier 3 — Roadmap (not built)

Roughly in dependency order — earlier unlocks later.

1. **GitLab CI + pre-commit templates** *(small)* — packaging/distribution, no
   core code change.
2. **Plugin registry for custom PII patterns** *(medium)* — let users register
   their own detector patterns without forking.
3. **Network-enriched audit** *(medium)* — opt-in npm/PyPI/GitHub provenance
   lookups; kept off the default path so the core audit stays offline/reproducible.
4. **Streaming detector path** *(large, architectural)* — detectors currently
   consume a *full in-memory trace* (batch). Streaming means processing frames as
   they arrive. This is the prerequisite for #5.
5. **Remote streamable-HTTP interception** *(large)* — today glassport is
   stdio-only. Remote MCP servers use a different transport (HTTP + SSE) that needs
   a different interception model. Depends on #4.
6. **Agent↔Agent (A2A) trace coverage** *(large)* — extend beyond Agent↔Tool to
   agent-to-agent protocols.

## Recently shipped

- **Runtime-annotation SARIF** — `summarize --sarif` exports detector
  annotations to SARIF 2.1.0 located into the session `.jsonl`. On branch
  `feat/runtime-annotation-sarif` (PR #8), pending merge + next release.

## Next action

Merge PR #8, then pick a Tier-3 item — recommended next: **#1 GitLab CI +
pre-commit templates** (small, distribution-only).
