# P0 Sprint — Six Quick Wins (2026-07-03)

Scope confirmed by maintainer: implement the six P0 findings from the two
independent review documents (`glassport_roadmap.pdf` §03, TUI audit report
§7.2 Phase 1), on a branch off `feat/web-console` (streaming + TUI v2 live
only there). All designs follow the documents' own implementation sketches.

## P0.1 — Path confinement for `audit_server` (security)

`server.py`'s `audit_server` tool passes a client-supplied `path` straight
into `audit_mod.main`. A hostile MCP client can point it at `/etc` or
`~/.ssh` and exfiltrate file structure via findings. Fix mirrors the
existing `_resolve_session_path` pattern:

- `_resolve_audit_path(raw, allowed_roots)` — realpath + commonpath check,
  `ValueError` outside every root (default-deny).
- `serve` grows repeatable `--allow-audit-root <dir>`; default `[os.getcwd()]`.
- Rejection surfaces as a JSON-RPC error result, not a crash.
- Grill `dogfood/eval_server_redteam.py` drives the real dispatch with
  `../../etc/passwd`, `~/.ssh/id_rsa`, absolute escapes; exits non-zero on
  any escape. Wire as CI job later with the other grills.

## P0.2 — Version skew

`__init__.py` 0.5.0 vs pyproject 0.6.2. Roadmap Option B (explicit over
clever): set the literal to match pyproject; add
`tests/test_version_sync.py` that parses `pyproject.toml` and asserts
equality — the test is the real fix (prevents recurrence).

## P0.3 — Silent `tail_only`

`adapters/streaming.py` sets `trace.metadata["tail_only"]` but only the web
console surfaces it. Three surfaces, per roadmap:

1. `summarize`: `WARN` line to stderr when set; `--json` gains
   `"completeness": "partial_tail_only"` (else `"complete"`).
2. `report`: visible PARTIAL banner at top of HTML (static text, no
   attacker-controlled content).
3. `watch`: sessions with `tail_only` carry a printed low-confidence notice
   in drift rows (`partial: True` field).

## F-UX-1 — `?` help overlay (TUI)

`?` → action `help`; `overlay_mode = "help"`; pure `build_help_lines()`
returns all 18 bindings grouped Movement / Selection / Search / Overlays /
Gate / Quit at sev 0; rendered through the existing `_draw_overlay` path;
Esc/q closes; footer gains `?`. Pure-core only; reducer unit tests.

## F-UX-3 — Resize repaint

`KEY_RESIZE` currently shares the `(-1, KEY_RESIZE)` continue-branch with
the poll timeout, so the new size paints a tick late. Split it: on
KEY_RESIZE fall through to immediate re-render (no re-ingest).

## F-TECH-1 — Windows shim

`[project.optional-dependencies] tui = ["windows-curses; platform_system=='Windows'"]`
plus README Windows paragraph. Existing ImportError handler already
degrades gracefully.

## Exit criteria (from the docs)

- [ ] audit_server rejects paths outside --allow-audit-root; grill passes
- [ ] __version__ matches pyproject; sync test green
- [ ] summarize JSON completeness field; report PARTIAL banner; watch flags
- [ ] ? opens help; Esc/q closes; all 18 bindings listed; footer updated
- [ ] resize repaints immediately
- [ ] pyproject has tui extra; README has Windows subsection
- [ ] full suite green (467 baseline + new)
