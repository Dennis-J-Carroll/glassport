# Glassport TUI — live session inspector

**Date:** 2026-06-10
**Status:** approved
**Subcommand:** `glassport tui`

## Purpose

A curses TUI that attaches to a Glassport session log (JSONL) while the
tap writes it and shows frames, detector findings, and counters updating
in real time. Finished sessions replay through the identical code path —
a session that is no longer growing is simply a dashboard that stops
changing.

This works because `SessionLog` opens its file with `buffering=1`
(line-buffered): every frame hits disk the moment it is relayed, so
tailing the file is real-time observation.

## Constraints

- Zero dependencies. `curses` is stdlib on Linux/macOS/Termux. On
  platforms without curses (Windows), `glassport tui` exits with a
  one-line friendly message, never a traceback.
- The tap is not touched. The TUI is a pure consumer of the JSONL log.
- Adapter (`from_mcp_session_file`) and detectors (`annotate`) are used
  unchanged — one code path from wire to screen, same as summarize,
  report, and watch.
- Must be usable on a narrow Termux phone terminal and degrade
  gracefully: `KEY_RESIZE` handled; below a minimum size (40 cols × 10 rows), show a
  "terminal too small" notice instead of garbage.

## Architecture

New module `src/glassport/tui.py`, lazy-imported in `tap.py` `main()`
exactly like report/watch/audit (`from glassport import tui as tui_mod`).

**Stateless re-ingest loop.** The curses input timeout (~250 ms) doubles
as the poll tick:

1. `stat()` the session file.
2. If size changed since last tick: `from_mcp_session_file()` →
   `detectors.annotate()` → rebuild view model → render.
3. If unchanged: handle input only.

No incremental parser, no cache. The log file is the single source of
truth and derived state is always recomputed — the same philosophy
`watch.py` uses for baselines. Re-parsing is O(n) per change but n is
session-sized (a 10k-frame session parses in milliseconds, far under the
poll interval).

Rejected alternatives:
- *Incremental streaming adapter* — O(1) per frame but forks the
  pairing/orphan/gate-marker logic into a second code path that must
  stay bug-identical to the batch adapter. Not worth it.
- *Tap pushes events over a socket/pipe* — couples the tap to the TUI,
  violates the relay-is-sacred contract, and cannot replay finished
  sessions.

## Screens

### 1. Picker (`glassport tui` with no path)

Lists sessions from `~/.glassport/sessions` (`--log-dir DIR` honored),
newest first. Row: timestamp, server name, frame count, and a `LIVE`
marker when the file grew within the last 5 seconds. The list refreshes
on the poll tick. Enter attaches to the selected session.
`glassport tui <file.jsonl>` skips the picker entirely.

### 2. Dashboard (three zones)

```
 exa-search 1.2 · LIVE ▮ · declared: web_search · frames 9
 fabricated 1 · violations 1 · server-requests 0 · gate: off
 12:01:05 ← tools/list result
 12:01:09 → tools/call web_search
 12:01:12 → tools/call arxiv_lookup            ← selected, red
 12:01:13 ← result id=5
────────────────── findings ──────────────────
 sev 3  seq 7  fabricated call: arxiv_lookup
 sev 1  seq 4  call_before_declaration: web_search
 ── j/k move · enter expand · tab focus · q quit ──
```

- **Header (2 lines):** server name+version from `serverInfo`,
  LIVE/IDLE indicator (LIVE = file grew < 5 s ago), declared tool list,
  counters: frames · fabricated · violations · server-requests ·
  gate on/off.
- **Timeline (main zone):** one line per trace event — time, direction
  arrow, method/kind summary. Rows carrying annotations are colored by
  max severity (sev 3 red, sev 1–2 yellow; INFO green, consistent with
  the HTML report). Follow mode pins the view to the newest event and
  auto-disables when the user scrolls up (like `less +F`).
- **Findings feed (bottom ~5 lines):** annotations only,
  severity-colored. Enter on a finding jumps the timeline to its event.

### 3. Overlay

Enter on a timeline row opens a panel over the dashboard: pretty-printed
frame JSON plus that event's annotations, scrollable. Esc/q closes.

## Key bindings

| Key | Action |
|---|---|
| `j`/`k`, arrows | move selection |
| `g` / `G` | jump to first / last |
| `Enter` | timeline: open overlay · findings: jump to event |
| `Tab` | switch focus timeline ↔ findings |
| `f` | toggle follow mode |
| `q` / `Esc` | close overlay / back to picker / quit |

(No `?` help overlay: the footer line permanently shows every binding —
seven keys don't warrant a second screen. Revisit if the key count grows.)

## Colors

Curses color pairs mirroring the HTML report: green base, red sev 3,
yellow sev 1–2, dim for metadata. `has_colors()` checked; monochrome
fallback uses bold/reverse only.

## Error handling

- Nonexistent file: one-line stderr message, exit 1.
- Malformed log lines: already surface as raw events from the adapter;
  rendered dimmed, never crash.
- Entire UI inside `curses.wrapper()` so the terminal is restored on any
  exception.
- `ImportError` on curses: friendly message naming the platform
  limitation.

## Testing

All logic is curses-free and pure; the curses layer is a thin renderer
kept free of decisions. Unit-testable units:

- View-model builders: trace → header fields/counters, timeline rows,
  finding lines, overlay text.
- Picker listing + LIVE detection (mtime/size based, injectable clock).
- Selection/focus/follow state machine (key event → state transition).

Target ~20 tests in `tests/test_tui.py`, reusing the fixture-building
helpers from `tests/test_detectors.py` and the real session fixture in
`examples/`. The render layer is exercised only by an import smoke test.

## Non-goals (v1)

Search/filter, mouse support, multi-session tabs, gate control from the
TUI, Windows curses support.
