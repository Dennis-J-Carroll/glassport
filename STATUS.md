# glassport — project status

Living snapshot of what's built, what's built-but-unshipped, and what's next.
Update when a tier changes. Last updated: 2026-06-23 (0.2.0 cut).

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
| SARIF export | `sarif.py` | audit findings → SARIF 2.1.0 → GitHub Security tab |
| MCP query server (`serve`) | `server.py` | glassport itself as an MCP server; the agent queries its own history |
| TUI | `tui.py` | live curses session inspector |

## Tier 2 — Built but NOT shipped to PyPI

**PyPI still serves 0.1.0.** Everything below exists in the repo + the built
0.2.0 artifacts, but `pip install glassport` does not get it until 0.2.0 is
published. See `RELEASING.md`.

- `serve` (MCP query server) and `sarif.py` (SARIF export)
- rubric v0.3 (capability-note tier — scores risk, not capability)
- scanner hardening: ReDoS-proof patterns, obfuscation-resistant scan,
  detector fault isolation, lazy pruning file walk
- `data_exfiltration` detector

## Tier 3 — Roadmap (not built)

Roughly in dependency order — earlier unlocks later.

1. **Runtime-annotation SARIF** *(small)* — bridge `Annotation` → the existing
   `_sarif_level` vocabulary so runtime detector findings also export to SARIF.
   The `note` tier is already in place to reuse. Lowest effort, scaffolding ready.
2. **GitLab CI + pre-commit templates** *(small)* — packaging/distribution, no
   core code change.
3. **Plugin registry for custom PII patterns** *(medium)* — let users register
   their own detector patterns without forking.
4. **Network-enriched audit** *(medium)* — opt-in npm/PyPI/GitHub provenance
   lookups; kept off the default path so the core audit stays offline/reproducible.
5. **Streaming detector path** *(large, architectural)* — detectors currently
   consume a *full in-memory trace* (batch). Streaming means processing frames as
   they arrive. This is the prerequisite for #6.
6. **Remote streamable-HTTP interception** *(large)* — today glassport is
   stdio-only. Remote MCP servers use a different transport (HTTP + SSE) that needs
   a different interception model. Depends on #5.
7. **Agent↔Agent (A2A) trace coverage** *(large)* — extend beyond Agent↔Tool to
   agent-to-agent protocols.

## Next action

Publish 0.2.0 (closes the Tier-1/Tier-2 gap), then pick a Tier-3 item.
Recommended first build: **#1 runtime-annotation SARIF** — small, scaffolding
exists, and it completes the SARIF story end-to-end.
