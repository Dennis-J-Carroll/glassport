"""
glassport tui — live curses inspector for Glassport session logs.

Attach to a session JSONL while the tap writes it (SessionLog is
line-buffered, so tailing the file is real-time observation) or replay
a finished one — same code path either way. Stateless re-ingest: each
time the file grows, the whole log is re-lifted through
from_mcp_session_file() and re-annotated. The log file is the single
source of truth; derived state is always recomputed, exactly like
watch.py does for baselines.

Layout (spec: docs/superpowers/specs/2026-06-10-tui-design.md):
  header    — server identity, LIVE/IDLE, declared surface, counters
  timeline  — one line per trace event, severity-colored
  findings  — annotations only; Enter jumps to the offending event
  overlay   — pretty-printed frame + annotations for selected event

Everything that decides is pure and curses-free (view-model builders,
picker listing, the key-action reducer). curses appears only in the
render layer and main loop, so the logic is unit-testable and the
module still imports on platforms without curses.

Zero dependencies. Pure stdlib.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from glassport.adapters.mcp_session import from_mcp_session_file
from glassport import detectors
from glassport.interaction_trace import (
    AnnotationKind,
    EventKind,
    InteractionTrace,
    PartKind,
)

LIVE_WINDOW_SECS = 5.0   # file growth within this window ⇒ LIVE
MIN_COLS, MIN_ROWS = 40, 10


# ─────────────────────────────────────────────────────────────────
# View model (pure)
# ─────────────────────────────────────────────────────────────────

@dataclass
class ViewModel:
    title: str
    live: bool
    declared: list[str]
    counters: dict[str, int]
    gate_on: bool
    rows: list["TimelineRow"] = field(default_factory=list)
    findings: list["FindingRow"] = field(default_factory=list)


@dataclass
class TimelineRow:
    text: str
    severity: int        # 0 = clean, 1-2 = warn, 3 = hot
    is_info: bool        # gate INFO annotations render green


@dataclass
class FindingRow:
    text: str
    severity: int
    is_info: bool
    row_index: int       # timeline row of the annotated event


def _clock(ts: str) -> str:
    """HH:MM:SS from an ISO timestamp; synthetic stamps pass through."""
    if "T" in ts and len(ts) >= 19:
        return ts[11:19]
    return ts


def _event_label(event) -> str:
    md = event.metadata
    if md.get("unparsed"):
        return "raw (unparsed line)"
    if event.kind == EventKind.TOOL_CALL:
        for p in event.parts:
            if p.kind == PartKind.TOOL_USE:
                return f"tools/call {p.content.get('name')}"
        return "tools/call"
    if event.kind == EventKind.TOOL_RESULT:
        rid = md.get("jsonrpc_id")
        return f"result id={rid}" if rid is not None else "result"
    if md.get("method"):
        return md["method"]
    if md.get("jsonrpc_id") is not None:
        return f"result id={md['jsonrpc_id']}"
    return event.kind.value


def build_view_model(trace: InteractionTrace, live: bool) -> ViewModel:
    server = next((a for a in trace.actors if a.name == "mcp_server"), None)

    info = (server.metadata.get("server_info") or {}) if server else {}
    name = info.get("name")
    version = info.get("version")
    title = f"{name} {version}" if name and version else (name or "unknown server")

    declared = [t.get("name") for t in (server.metadata.get("tools") or [])
                if t.get("name")] if server else []

    fabricated = sum(1 for a in trace.annotations
                     if a.subcategory == "fabricated_tool_call")
    violations = sum(1 for a in trace.annotations
                     if a.kind != AnnotationKind.INFO
                     and a.subcategory != "fabricated_tool_call")
    server_requests = sum(
        1 for e in trace.events
        if e.metadata.get("server_initiated")
        and not e.metadata.get("notification"))
    gate_on = any(isinstance(e.metadata.get("gate"), dict)
                  for e in trace.events)

    client = next((a for a in trace.actors if a.name == "mcp_client"), None)
    sev_by_event: dict[str, int] = {}
    info_by_event: dict[str, bool] = {}
    for a in trace.annotations:
        if a.kind == AnnotationKind.INFO:
            info_by_event[a.event_id] = True
        else:
            sev_by_event[a.event_id] = max(
                sev_by_event.get(a.event_id, 0), a.severity)

    rows: list[TimelineRow] = []
    for e in trace.events:
        arrow = "→" if (client and e.actor_id == client.id) else "←"
        rows.append(TimelineRow(
            text=f"{_clock(e.timestamp)} {arrow} {_event_label(e)}",
            severity=sev_by_event.get(e.id, 0),
            is_info=info_by_event.get(e.id, False)))

    row_by_event = {e.id: i for i, e in enumerate(trace.events)}
    findings: list[FindingRow] = []
    for a in sorted(trace.annotations,
                    key=lambda a: (-a.severity, row_by_event.get(a.event_id, 0))):
        findings.append(FindingRow(
            text=f"sev {a.severity}  {a.subcategory}: {a.explanation}",
            severity=a.severity,
            is_info=a.kind == AnnotationKind.INFO,
            row_index=row_by_event.get(a.event_id, 0)))

    return ViewModel(
        title=title, live=live, declared=declared,
        counters={"frames": len(trace.events),
                  "fabricated": fabricated,
                  "violations": violations,
                  "server_requests": server_requests},
        gate_on=gate_on,
        rows=rows,
        findings=findings)


def format_overlay(trace: InteractionTrace, row_index: int) -> list[str]:
    """Pretty-printed parts + annotations for one event, as plain lines."""
    e = trace.events[row_index]
    out = [f"event {row_index}  seq={e.metadata.get('seq')}  "
           f"kind={e.kind.value}  ts={e.timestamp}", ""]
    for p in e.parts:
        if isinstance(p.content, (dict, list)):
            out.extend(json.dumps(p.content, indent=2).splitlines())
        else:
            out.append(str(p.content))
    anns = [a for a in trace.annotations if a.event_id == e.id]
    out.append("")
    if anns:
        for a in anns:
            out.append(f"⚠ sev {a.severity} [{a.kind.value}] "
                       f"{a.subcategory}: {a.explanation}")
    else:
        out.append("no findings for this event")
    return out


@dataclass
class SessionEntry:
    path: Path
    mtime: float
    frames: int
    live: bool


@dataclass
class UIState:
    focus: str = "timeline"          # "timeline" | "findings"
    selected: int = 0
    follow: bool = True
    overlay_open: bool = False
    overlay_scroll: int = 0
    search_input: bool = False       # typing in the search bar
    search_query: str = ""           # persists after accept, for n/N
    drift_open: bool = False         # drift side panel visible
    overlay_mode: str = "frame"      # "frame" | "drift"


def search_matches(vm: ViewModel, query: str, focus: str) -> list[int]:
    """Indices of rows whose text contains `query`, case-insensitive.
    Operates on already-sanitized row text — never raw server bytes —
    so search adds no new attack surface. Empty query matches nothing."""
    if not query:
        return []
    q = query.lower()
    rows = vm.rows if focus == "timeline" else vm.findings
    return [i for i, r in enumerate(rows) if q in r.text.lower()]


# ─────────────────────────────────────────────────────────────────
# Tabs — one open session per tab, each with its own UIState and
# ingest cache so switching back is instant. Pure operations; the
# curses loop only reads tabs.active and fills the cache fields.
# ─────────────────────────────────────────────────────────────────

@dataclass
class Tab:
    path: Path
    state: UIState = field(default_factory=UIState)
    # ingest cache, owned by the dashboard loop:
    last_size: int = -1
    trace: InteractionTrace | None = None
    vm: ViewModel | None = None
    drift_lines: list[tuple[int, str]] | None = None   # lazy, per ingest
    audit_lines: list[tuple[int, str]] | None = None   # lazy, per ingest


@dataclass
class Tabs:
    tabs: list[Tab] = field(default_factory=list)
    active: int = 0


def open_tab(tabs: Tabs, path: Path) -> Tabs:
    """Activate the tab for `path`, appending it if not already open."""
    for i, t in enumerate(tabs.tabs):
        if t.path == path:
            tabs.active = i
            return tabs
    tabs.tabs.append(Tab(path=path))
    tabs.active = len(tabs.tabs) - 1
    return tabs


def format_tab_strip(tabs: Tabs) -> str:
    """One-line tab bar: `[n:name]` for the active tab, ` n:name ` else."""
    cells = []
    for i, t in enumerate(tabs.tabs):
        label = f"{i + 1}:{t.path.name}"
        cells.append(f"[{label}]" if i == tabs.active else f" {label} ")
    return " ".join(cells)


def cycle_tab(tabs: Tabs) -> Tabs:
    if tabs.tabs:
        tabs.active = (tabs.active + 1) % len(tabs.tabs)
    return tabs


def close_tab(tabs: Tabs) -> Tabs:
    """Close the active tab; active stays on the same position, clamped."""
    if tabs.tabs:
        tabs.tabs.pop(tabs.active)
        tabs.active = min(tabs.active, max(0, len(tabs.tabs) - 1))
    return tabs


def reduce(state: UIState, action: str, vm: ViewModel) -> UIState:
    """Apply one semantic action to state, in place (curses-free and
    deterministic; returns the same object for chaining)."""
    n = len(vm.rows) if state.focus == "timeline" else len(vm.findings)
    last = max(0, n - 1)

    # selected persists across re-ingests while lists change underneath:
    # rows only grow (append-only log) but findings can shrink AND
    # reorder (a later tools/list retroactively un-fabricates earlier
    # calls; sort is severity-first). Clamp every entry; positional
    # drift after a reorder is accepted for v1.
    state.selected = min(state.selected, last)

    if state.overlay_open:
        if action == "back":
            state.overlay_open = False
        elif action == "up":
            state.overlay_scroll = max(0, state.overlay_scroll - 1)
        elif action == "down":
            state.overlay_scroll += 1
        return state

    if action == "search_open":
        state.search_input = True
        state.search_query = ""
        return state
    if state.search_input:
        if action.startswith("input:"):
            state.search_query += action[len("input:"):]
            hits = search_matches(vm, state.search_query, state.focus)
            if hits:                     # jump live while typing
                state.selected = hits[0]
                if state.focus == "timeline":
                    state.follow = False
        elif action == "search_backspace":
            state.search_query = state.search_query[:-1]
        elif action == "search_accept":
            state.search_input = False
        elif action in ("search_cancel", "back"):
            state.search_input = False
            state.search_query = ""
        return state
    if action in ("search_next", "search_prev"):
        hits = search_matches(vm, state.search_query, state.focus)
        if hits:
            if action == "search_next":
                state.selected = next(
                    (i for i in hits if i > state.selected), hits[0])
            else:
                state.selected = next(
                    (i for i in reversed(hits) if i < state.selected),
                    hits[-1])
            if state.focus == "timeline":
                state.follow = False
        return state

    if action == "up":
        state.selected = max(0, state.selected - 1)
        if state.focus == "timeline":
            state.follow = False
    elif action == "down":
        state.selected = min(last, state.selected + 1)
    elif action == "top":
        state.selected = 0
        if state.focus == "timeline":
            state.follow = False
    elif action == "bottom":
        state.selected = last
    elif action == "follow":
        state.follow = not state.follow
        if state.follow:
            state.focus = "timeline"
            state.selected = max(0, len(vm.rows) - 1)
    elif action == "tab":
        state.focus = "findings" if state.focus == "timeline" else "timeline"
        state.selected = 0
    elif action == "drift":
        state.drift_open = not state.drift_open
    elif action == "drift_full":
        state.overlay_open = True
        state.overlay_mode = "drift"
        state.overlay_scroll = 0
    elif action == "audit":
        state.overlay_open = True
        state.overlay_mode = "audit"
        state.overlay_scroll = 0
    elif action == "enter":
        if state.focus == "timeline" and vm.rows:
            state.overlay_open = True
            state.overlay_mode = "frame"
            state.overlay_scroll = 0
        elif state.focus == "findings" and vm.findings:
            state.focus = "timeline"
            state.selected = vm.findings[state.selected].row_index
            state.follow = False
    return state


def build_drift_lines(path: Path, log_dir: Path) -> list[tuple[int, str]]:
    """Drift of the session at `path` vs the merged baseline of its
    server's other logs in `log_dir` — watch.py is the engine, this
    only renders its structured output as (severity, text) lines.
    Total: degrades to an explanatory line instead of raising, because
    it runs inside the live render tick."""
    from glassport import watch
    try:
        groups = watch.watch_dir(log_dir)
    except Exception as exc:                      # noqa: BLE001
        return [(0, f"drift unavailable: {type(exc).__name__}")]

    for rows in groups.values():
        for i, row in enumerate(rows):
            if row["source"] != path.name:
                continue
            fp = row["fingerprint"]
            out: list[tuple[int, str]] = [
                (0, f"drift · session {i + 1}/{len(rows)} of "
                    f"{fp['server_name'] or 'unknown server'}"),
                (0, f"declared {len(fp['declared_tools'])} · called "
                    f"{len(fp['called_tools'])} · hosts "
                    f"{len(fp['hosts'])}"),
                (0, ""),
            ]
            if i == 0:
                out.append((0, "baseline session — no history to "
                               "compare against"))
                return out
            findings = row["findings"]
            if not findings:
                out.append((0, f"no drift vs {i} prior session(s)"))
                return out
            hist = {3: 0, 2: 0, 1: 0}
            for f in findings:
                hist[f.severity] = hist.get(f.severity, 0) + 1
            out.append((0, f"sev3 ×{hist[3]} · sev2 ×{hist[2]} · "
                           f"sev1 ×{hist[1]}"))
            out.append((0, ""))
            for f in sorted(findings, key=lambda f: -f.severity):
                out.append((f.severity,
                            f"[sev {f.severity}] {f.kind}: {f.explanation}"))
            return out
    return [(0, f"session {path.name} not found in {log_dir}")]


def build_audit_lines(report, annotations) -> list[tuple[int, str]]:
    """Static audit verdict + runtime findings as (severity, text).

    Static lines render rule + location only — Finding.detail embeds the
    matched source, which is exactly what a poisoned server wants echoed,
    so it never reaches the screen (same policy as advise._static_line).
    Runtime explanations are glassport's own words with secrets already
    replaced by detectors._redact, so they are safe to show."""
    from glassport.advise import _severity_int

    out: list[tuple[int, str]] = []
    if report is not None:
        out.append((0, f"static audit — score {report.score}/100 · "
                       f"grade {report.grade} · rubric "
                       f"v{report.rubric_version}"))
        for f in sorted(report.findings,
                        key=lambda f: -_severity_int(f.severity)):
            mult = f" ×{f.count}" if f.count > 1 else ""
            out.append((_severity_int(f.severity),
                        f"[{f.severity}] {f.rule} — {f.path}:{f.line}"
                        f"{mult}"))
    else:
        out.append((0, "static audit skipped — launch with --audit PATH "
                       "to score the server's source"))
    out.append((0, ""))
    out.append((0, "runtime findings (this session)"))
    runtime = [a for a in (annotations or [])
               if _severity_int(a.severity) >= 1]
    if runtime:
        for a in sorted(runtime,
                        key=lambda a: -_severity_int(a.severity)):
            out.append((_severity_int(a.severity),
                        f"[sev {a.severity}] {a.subcategory}: "
                        f"{a.explanation}"))
    else:
        out.append((0, "none at/above severity 1"))
    return out


# ─────────────────────────────────────────────────────────────────
# Layout — the dashboard's vertical geometry as data, shared by the
# renderer and the mouse hit-test so they can never disagree.
# ─────────────────────────────────────────────────────────────────

@dataclass
class Layout:
    tl_top: int          # first timeline row
    tl_h: int            # timeline height
    findings_top: int    # y of the findings rule; entries start +1
    n_findings: int      # findings entries shown (<= 5)


def layout(h: int, vm: ViewModel, many_tabs: bool) -> Layout:
    strip_h = 1 if many_tabs else 0
    n_findings = min(len(vm.findings), 5)
    findings_h = (n_findings + 1) if n_findings else 0
    tl_top = 2 + strip_h
    tl_h = max(1, (h - 1) - findings_h - tl_top)
    return Layout(tl_top=tl_top, tl_h=tl_h,
                  findings_top=tl_top + tl_h, n_findings=n_findings)


def first_visible(state: UIState, vm: ViewModel, tl_h: int) -> int:
    """Index of the first timeline row on screen."""
    if state.follow:
        return max(0, len(vm.rows) - tl_h)
    sel = state.selected if state.focus == "timeline" else -1
    anchor = sel if sel >= 0 else len(vm.rows) - 1
    return max(0, min(anchor - tl_h // 2, len(vm.rows) - tl_h))


def hit_test(y: int, lo: Layout, first: int,
             vm: ViewModel) -> tuple[str, int] | None:
    """Map a screen row to ("timeline"|"findings", index), or None."""
    if lo.tl_top <= y < lo.tl_top + lo.tl_h:
        idx = first + (y - lo.tl_top)
        if idx < len(vm.rows):
            return ("timeline", idx)
        return None
    if lo.n_findings and \
            lo.findings_top < y <= lo.findings_top + lo.n_findings:
        return ("findings", y - lo.findings_top - 1)
    return None


# ─────────────────────────────────────────────────────────────────
# Gate override — the TUI end of `glassport gate --controllable`.
# The tap's reader is fail-closed (owner-only perms, well-formed
# JSON, or enforcement stays ON), so the writer here must produce
# exactly what that reader accepts.
# ─────────────────────────────────────────────────────────────────

def _gate_override_path(session_path: Path) -> Path:
    return session_path.with_name(session_path.name + ".gate")


def read_gate_override(session_path: Path) -> bool | None:
    """Current override for this session: True/False = file says
    enforce on/off, None = no (valid) override file."""
    try:
        data = json.loads(_gate_override_path(session_path)
                          .read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if isinstance(data, dict) and isinstance(data.get("enforce"), bool):
        return data["enforce"]
    return None


def toggle_gate_override(session_path: Path) -> bool:
    """Flip enforcement (no file counts as ON) and return the new
    state. Written atomically with owner-only permissions — anything
    looser and the tap's fail-closed reader ignores the file."""
    import os
    current = read_gate_override(session_path)
    new = not (True if current is None else current)
    target = _gate_override_path(session_path)
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({"enforce": new}).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, target)
    return new


def list_sessions(log_dir: Path, now: float | None = None) -> list[SessionEntry]:
    """Sessions newest-first; LIVE = grew within LIVE_WINDOW_SECS."""
    if now is None:
        now = time.time()
    if not log_dir.is_dir():
        return []
    entries = []
    for p in log_dir.glob("*.jsonl"):
        try:
            st = p.stat()
            with open(p, "rb") as fh:
                frames = sum(1 for _ in fh)
        except OSError:
            continue
        entries.append(SessionEntry(
            path=p, mtime=st.st_mtime, frames=frames,
            live=(now - st.st_mtime) < LIVE_WINDOW_SECS))
    entries.sort(key=lambda e: e.mtime, reverse=True)
    return entries


# ─────────────────────────────────────────────────────────────────
# Curses shell — everything below is dumb rendering + I/O. No
# decisions here: state changes go through reduce(), content through
# build_view_model()/format_overlay(). curses is imported inside
# main() so the pure core (and the test suite) works on platforms
# without curses.
# ─────────────────────────────────────────────────────────────────

KEYMAP = {
    ord("j"): "down", ord("k"): "up",
    ord("g"): "top", ord("G"): "bottom",
    ord("f"): "follow", ord("\t"): "tab",
    ord("\n"): "enter", ord("\r"): "enter",
    27: "back",                       # Esc
    20: "next_tab",                   # Ctrl+T
    23: "close_tab",                  # Ctrl+W
    ord("/"): "search_open",
    ord("n"): "search_next", ord("N"): "search_prev",
    ord("d"): "drift", ord("D"): "drift_full",
    ord("a"): "audit",
    ord("!"): "gate_toggle",
}

C_BASE, C_HOT, C_WARN, C_DIM, C_BAR, C_INFO = 1, 2, 3, 4, 5, 6


def _init_colors(curses):
    if not curses.has_colors():
        return
    curses.use_default_colors()
    curses.init_pair(C_BASE, curses.COLOR_GREEN, -1)
    curses.init_pair(C_HOT, curses.COLOR_RED, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
    curses.init_pair(C_BAR, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(C_INFO, curses.COLOR_GREEN, -1)


def _attr(curses, pair, bold=False, dim=False):
    a = curses.color_pair(pair) if curses.has_colors() else 0
    if bold:
        a |= curses.A_BOLD
    if dim:
        a |= curses.A_DIM
    return a


def _row_attr(curses, row):
    if row.severity >= 3:
        return _attr(curses, C_HOT, bold=True)
    if row.severity >= 1:
        return _attr(curses, C_WARN)
    if row.is_info:
        return _attr(curses, C_INFO, bold=True)
    return _attr(curses, C_BASE)


def _put(scr, y, x, text, attr=0):
    """addstr that never raises on the bottom-right cell or overflow."""
    h, w = scr.getmaxyx()
    if 0 <= y < h and x < w:
        try:
            scr.addstr(y, x, text[: w - x - 1], attr)
        except Exception:
            pass


def _drift_attr(curses, sev):
    if sev >= 3:
        return _attr(curses, C_HOT, bold=True)
    if sev >= 1:
        return _attr(curses, C_WARN)
    return _attr(curses, C_DIM, dim=True)


def _draw_drift_panel(curses, scr, drift_lines, top, height):
    """Right-hand side panel; drawn over the timeline columns."""
    _, w = scr.getmaxyx()
    pw = min(max(30, w * 2 // 5), w - 10)
    x0 = w - pw
    for i in range(height):
        _put(scr, top + i, x0 - 1, "│", _attr(curses, C_DIM, dim=True))
        _put(scr, top + i, x0, " " * (pw - 1))
    for i, (sev, text) in enumerate(drift_lines[: height]):
        _put(scr, top + i, x0 + 1, text[: pw - 2], _drift_attr(curses, sev))


def _draw_dashboard(curses, scr, vm, state, tabs=None, drift_lines=None,
                    gate_override=None):
    scr.erase()
    h, w = scr.getmaxyx()
    if w < MIN_COLS or h < MIN_ROWS:
        _put(scr, 0, 0, f"terminal too small (need {MIN_COLS}x{MIN_ROWS})")
        scr.refresh()
        return

    bar = _attr(curses, C_BAR, bold=True)
    ind = "LIVE ▮" if vm.live else "IDLE"
    c = vm.counters
    _put(scr, 0, 0, f" {vm.title} · {ind} · declared: "
                    f"{', '.join(vm.declared) or '—'} · frames {c['frames']}"
                    .ljust(w - 1), bar)
    override = "" if gate_override is None else \
        f" · override: {'enforce' if gate_override else 'DISABLED'}"
    _put(scr, 1, 0, f" fabricated {c['fabricated']} · violations "
                    f"{c['violations']} · server-requests "
                    f"{c['server_requests']} · gate: "
                    f"{'on' if vm.gate_on else 'off'}{override}"
                    f"{'' if state.follow else ' · follow OFF'}"
                    .ljust(w - 1), bar)

    many_tabs = False
    if tabs is not None and len(tabs.tabs) > 1:
        many_tabs = True
        _put(scr, 2, 0, " " + format_tab_strip(tabs),
             _attr(curses, C_DIM, dim=True))

    lo = layout(h, vm, many_tabs)
    n_findings, tl_top, tl_h = lo.n_findings, lo.tl_top, lo.tl_h

    hits = set(search_matches(vm, state.search_query, "timeline")) \
        if state.search_query else set()

    sel = state.selected if state.focus == "timeline" else -1
    first = first_visible(state, vm, tl_h)
    for i in range(tl_h):
        idx = first + i
        if idx >= len(vm.rows):
            break
        row = vm.rows[idx]
        attr = _row_attr(curses, row)
        if idx in hits:
            attr |= curses.A_UNDERLINE
        if idx == sel:
            attr |= curses.A_REVERSE
        _put(scr, tl_top + i, 0, " " + row.text, attr)

    if state.drift_open and drift_lines is not None:
        _draw_drift_panel(curses, scr, drift_lines, tl_top, tl_h)

    if n_findings:
        fy = lo.findings_top
        _put(scr, fy, 0,
             "─" * 18 + " findings " + "─" * max(0, w - 30),
             _attr(curses, C_DIM, dim=True))
        for i in range(n_findings):
            f = vm.findings[i]
            attr = _row_attr(curses, f)
            if state.focus == "findings" and i == state.selected:
                attr |= curses.A_REVERSE
            _put(scr, fy + 1 + i, 0, " " + f.text, attr)

    if state.search_input or state.search_query:
        n = len(hits)
        cursor = "▏" if state.search_input else ""
        _put(scr, h - 1, 0,
             f" /{state.search_query}{cursor}  ({n} match"
             f"{'' if n == 1 else 'es'})"
             f"{'' if state.search_input else ' · n/N jump · / new'} ",
             _attr(curses, C_WARN, bold=True))
    else:
        _put(scr, h - 1, 0,
             " j/k move · enter expand · / search · tab focus · "
             "f follow · ^T/^W tabs · q quit ",
             _attr(curses, C_DIM, dim=True))
    scr.refresh()


def _draw_overlay(curses, scr, lines, state, title=" frame detail — esc "
                                                   "to close "):
    h, w = scr.getmaxyx()
    top = state.overlay_scroll
    scr.erase()
    _put(scr, 0, 0, title.ljust(w - 1), _attr(curses, C_BAR, bold=True))
    for i, line in enumerate(lines[top: top + h - 2]):
        if isinstance(line, tuple):
            sev, text = line
            _put(scr, 1 + i, 1, text, _drift_attr(curses, sev))
        else:
            _put(scr, 1 + i, 1, line, _attr(curses, C_BASE))
    scr.refresh()


def _ingest(path: Path) -> InteractionTrace:
    trace = from_mcp_session_file(path)
    detectors.annotate(trace)
    return trace


def _refresh_tab(tab: Tab) -> bool:
    """Re-ingest the tab's session if its file grew. Returns False when
    the file vanished before the first successful ingest (dead tab)."""
    try:
        st = tab.path.stat()
        size, mtime = st.st_size, st.st_mtime
    except OSError:
        size, mtime = tab.last_size, 0.0
    if size != tab.last_size or tab.vm is None:
        tab.last_size = size
        try:
            tab.trace = _ingest(tab.path)
        except OSError:
            # file vanished mid-rotation: keep showing the last
            # good trace; the next tick re-stats and recovers
            if tab.vm is None:
                return False
            tab.vm.live = False
        else:
            tab.vm = build_view_model(
                tab.trace, live=(time.time() - mtime) < LIVE_WINDOW_SECS)
            tab.drift_lines = None      # history moved; recompute lazily
            tab.audit_lines = None      # annotations changed too
            if tab.state.follow:
                tab.state.selected = max(0, len(tab.vm.rows) - 1)
    else:
        tab.vm.live = (time.time() - mtime) < LIVE_WINDOW_SECS
    return True


def _dashboard_loop(curses, scr, tabs: Tabs,
                    audit_dir: Path | None = None,
                    gate_control: bool = False) -> None:
    scr.timeout(250)          # input poll doubles as the re-ingest tick
    audit_report = None
    audit_ran = False         # audit the source once per TUI run
    while True:
        if not tabs.tabs:
            return            # every tab closed -> back to the picker
        tab = tabs.tabs[tabs.active]
        if not _refresh_tab(tab):
            close_tab(tabs)
            continue
        state, vm = tab.state, tab.vm
        # _refresh_tab(True) guarantees both were ingested at least once
        assert vm is not None and tab.trace is not None

        needs_drift = state.drift_open or (
            state.overlay_open and state.overlay_mode == "drift")
        if needs_drift and tab.drift_lines is None:
            tab.drift_lines = build_drift_lines(tab.path, tab.path.parent)

        if state.overlay_open and state.overlay_mode == "audit" \
                and tab.audit_lines is None:
            if audit_dir is not None and not audit_ran:
                audit_ran = True
                try:
                    from glassport.audit import audit_path
                    audit_report = audit_path(audit_dir)
                except Exception:            # noqa: BLE001 — render tick
                    audit_report = None
            tab.audit_lines = build_audit_lines(
                audit_report, tab.trace.annotations)

        if state.overlay_open:
            if state.overlay_mode == "drift":
                _draw_overlay(curses, scr, tab.drift_lines, state,
                              title=" drift vs baseline — esc to close ")
            elif state.overlay_mode == "audit":
                _draw_overlay(curses, scr, tab.audit_lines, state,
                              title=" audit & advisory — esc to close ")
            else:
                _draw_overlay(curses, scr,
                              format_overlay(tab.trace, state.selected),
                              state)
        else:
            _draw_dashboard(curses, scr, vm, state, tabs, tab.drift_lines,
                            read_gate_override(tab.path))

        key = scr.getch()
        if key in (-1, curses.KEY_RESIZE):
            continue
        if key == getattr(curses, "KEY_MOUSE", None):
            try:
                _, _mx, my, _, bstate = curses.getmouse()
            except Exception:       # spurious event; keyboard still works
                continue
            if state.overlay_open:
                if bstate & (curses.BUTTON1_CLICKED
                             | curses.BUTTON1_PRESSED):
                    reduce(state, "back", vm)
                continue
            if bstate & getattr(curses, "BUTTON4_PRESSED", 0):
                reduce(state, "up", vm)
            elif bstate & getattr(curses, "BUTTON5_PRESSED", 0):
                reduce(state, "down", vm)
            elif bstate & (curses.BUTTON1_CLICKED
                           | curses.BUTTON1_PRESSED):
                h, _w = scr.getmaxyx()
                lo = layout(h, vm, len(tabs.tabs) > 1)
                first = first_visible(state, vm, lo.tl_h)
                hit = hit_test(my, lo, first, vm)
                if hit is not None:
                    state.focus, state.selected = hit
                    if state.focus == "timeline":
                        state.follow = False
            continue
        if state.search_input:
            if key in (ord("\n"), ord("\r")):
                reduce(state, "search_accept", vm)
            elif key == 27:
                reduce(state, "search_cancel", vm)
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                reduce(state, "search_backspace", vm)
            elif 32 <= key < 127:
                reduce(state, f"input:{chr(key)}", vm)
            continue
        if key == ord("q"):
            if state.overlay_open:
                reduce(state, "back", vm)
                continue
            if state.search_query:      # q clears a lingering search first
                reduce(state, "search_cancel", vm)
                continue
            return
        action = KEYMAP.get(key)
        if key == curses.KEY_UP:
            action = "up"
        elif key == curses.KEY_DOWN:
            action = "down"
        if action == "next_tab":
            cycle_tab(tabs)
        elif action == "close_tab":
            close_tab(tabs)
        elif action == "gate_toggle":
            # I/O, deliberate, and opt-in: only with --gate-control,
            # and only meaningful for taps started as
            # `gate --controllable` (otherwise the file is inert)
            if gate_control:
                toggle_gate_override(tab.path)
        elif action:
            reduce(state, action, vm)


def _picker_loop(curses, scr, log_dir: Path) -> Path | None:
    scr.timeout(500)
    selected = 0
    while True:
        entries = list_sessions(log_dir)
        selected = min(selected, max(0, len(entries) - 1))
        scr.erase()
        h, w = scr.getmaxyx()
        _put(scr, 0, 0, f" glassport · sessions in {log_dir} ".ljust(w - 1),
             _attr(curses, C_BAR, bold=True))
        if not entries:
            _put(scr, 2, 1, "no sessions found — wrap a server first",
                 _attr(curses, C_DIM, dim=True))
        for i, e in enumerate(entries[: h - 3]):
            mark = "LIVE ▮ " if e.live else "       "
            attr = _attr(curses, C_HOT if e.live else C_BASE, bold=e.live)
            if i == selected:
                attr |= curses.A_REVERSE
            _put(scr, 2 + i, 0,
                 f" {mark}{e.path.name}  ({e.frames} frames)", attr)
        _put(scr, h - 1, 0, " j/k move · enter attach · q quit ",
             _attr(curses, C_DIM, dim=True))
        scr.refresh()

        key = scr.getch()
        if key == ord("q"):
            return None
        if key in (ord("\n"), ord("\r")) and entries:
            return entries[selected].path
        if key in (ord("k"), curses.KEY_UP):
            selected = max(0, selected - 1)
        if key in (ord("j"), curses.KEY_DOWN):
            selected = min(max(0, len(entries) - 1), selected + 1)


def _parse_args(argv: list[str]) -> tuple[Path | None, Path,
                                          Path | None, bool, bool]:
    """(session path, log dir, audit dir, gate control, wants help)."""
    log_dir = Path.home() / ".glassport" / "sessions"
    path: Path | None = None
    audit_dir: Path | None = None
    gate_control = False
    i = 0
    while i < len(argv):
        if argv[i] == "--log-dir" and i + 1 < len(argv):
            log_dir = Path(argv[i + 1])
            i += 2
        elif argv[i] == "--audit" and i + 1 < len(argv):
            audit_dir = Path(argv[i + 1])
            i += 2
        elif argv[i] == "--gate-control":
            gate_control = True
            i += 1
        elif argv[i] in ("-h", "--help"):
            return path, log_dir, audit_dir, gate_control, True
        else:
            path = Path(argv[i])
            i += 1
    return path, log_dir, audit_dir, gate_control, False


def main(argv: list[str]) -> int:
    path, log_dir, audit_dir, gate_control, want_help = _parse_args(argv)
    if want_help:
        print("usage: glassport tui [session.jsonl] [--log-dir DIR] "
              "[--audit PATH] [--gate-control]")
        return 0

    if path is not None and not path.is_file():
        print(f"[glassport] no such session log: {path}", file=sys.stderr)
        return 1

    try:
        import curses
    except ImportError:
        print("[glassport] tui needs the stdlib curses module, which is "
              "not available on this platform", file=sys.stderr)
        return 1

    def _run(scr):
        _init_colors(curses)
        curses.curs_set(0)
        try:
            curses.set_escdelay(25)   # Esc should feel instant
        except AttributeError:
            pass                       # not on all curses builds
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS)
        except Exception:
            pass                       # no mouse: keyboard fallback
        tabs = Tabs()                  # persists across picker round-trips
        if path is not None:
            open_tab(tabs, path)
            _dashboard_loop(curses, scr, tabs, audit_dir, gate_control)
            return
        while True:
            chosen = _picker_loop(curses, scr, log_dir)
            if chosen is None:
                return
            open_tab(tabs, chosen)
            _dashboard_loop(curses, scr, tabs, audit_dir, gate_control)

    curses.wrapper(_run)
    return 0
