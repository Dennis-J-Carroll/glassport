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
        if server and e.actor_id == server.id
        and e.metadata.get("method") is not None
        and e.metadata.get("jsonrpc_id") is not None)
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
    elif action == "enter":
        if state.focus == "timeline" and vm.rows:
            state.overlay_open = True
            state.overlay_scroll = 0
        elif state.focus == "findings" and vm.findings:
            state.focus = "timeline"
            state.selected = vm.findings[state.selected].row_index
            state.follow = False
    return state


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


def _draw_dashboard(curses, scr, vm, state):
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
    _put(scr, 1, 0, f" fabricated {c['fabricated']} · violations "
                    f"{c['violations']} · server-requests "
                    f"{c['server_requests']} · gate: "
                    f"{'on' if vm.gate_on else 'off'}"
                    f"{'' if state.follow else ' · follow OFF'}"
                    .ljust(w - 1), bar)

    n_findings = min(len(vm.findings), 5)
    findings_h = (n_findings + 1) if n_findings else 0
    tl_top = 2
    tl_h = max(1, (h - 1) - findings_h - tl_top)

    sel = state.selected if state.focus == "timeline" else -1
    anchor = sel if sel >= 0 else len(vm.rows) - 1
    first = max(0, min(anchor - tl_h // 2, len(vm.rows) - tl_h))
    if state.follow:
        first = max(0, len(vm.rows) - tl_h)
    for i in range(tl_h):
        idx = first + i
        if idx >= len(vm.rows):
            break
        row = vm.rows[idx]
        attr = _row_attr(curses, row)
        if idx == sel:
            attr |= curses.A_REVERSE
        _put(scr, tl_top + i, 0, " " + row.text, attr)

    if n_findings:
        fy = tl_top + tl_h
        _put(scr, fy, 0,
             "─" * 18 + " findings " + "─" * max(0, w - 30),
             _attr(curses, C_DIM, dim=True))
        for i in range(n_findings):
            f = vm.findings[i]
            attr = _row_attr(curses, f)
            if state.focus == "findings" and i == state.selected:
                attr |= curses.A_REVERSE
            _put(scr, fy + 1 + i, 0, " " + f.text, attr)

    _put(scr, h - 1, 0,
         " j/k move · enter expand · tab focus · f follow · q quit ",
         _attr(curses, C_DIM, dim=True))
    scr.refresh()


def _draw_overlay(curses, scr, trace, state):
    lines = format_overlay(trace, state.selected)
    h, w = scr.getmaxyx()
    top = state.overlay_scroll
    scr.erase()
    _put(scr, 0, 0, " frame detail — esc to close ".ljust(w - 1),
         _attr(curses, C_BAR, bold=True))
    for i, line in enumerate(lines[top: top + h - 2]):
        _put(scr, 1 + i, 1, line, _attr(curses, C_BASE))
    scr.refresh()


def _ingest(path: Path) -> InteractionTrace:
    trace = from_mcp_session_file(path)
    detectors.annotate(trace)
    return trace


def _dashboard_loop(curses, scr, path: Path) -> None:
    scr.timeout(250)          # input poll doubles as the re-ingest tick
    last_size = -1
    trace = None
    vm = None
    state = UIState()
    while True:
        try:
            st = path.stat()
            size, mtime = st.st_size, st.st_mtime
        except OSError:
            size, mtime = last_size, 0.0
        if size != last_size or vm is None:
            last_size = size
            trace = _ingest(path)
            vm = build_view_model(
                trace, live=(time.time() - mtime) < LIVE_WINDOW_SECS)
            if state.follow:
                state.selected = max(0, len(vm.rows) - 1)
        else:
            vm.live = (time.time() - mtime) < LIVE_WINDOW_SECS

        if state.overlay_open:
            _draw_overlay(curses, scr, trace, state)
        else:
            _draw_dashboard(curses, scr, vm, state)

        key = scr.getch()
        if key in (-1, curses.KEY_RESIZE):
            continue
        if key == ord("q"):
            if state.overlay_open:
                reduce(state, "back", vm)
                continue
            return
        action = KEYMAP.get(key)
        if key == curses.KEY_UP:
            action = "up"
        elif key == curses.KEY_DOWN:
            action = "down"
        if action:
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


def main(argv: list[str]) -> int:
    log_dir = Path.home() / ".glassport" / "sessions"
    path: Path | None = None
    i = 0
    while i < len(argv):
        if argv[i] == "--log-dir" and i + 1 < len(argv):
            log_dir = Path(argv[i + 1])
            i += 2
        elif argv[i] in ("-h", "--help"):
            print("usage: glassport tui [session.jsonl] [--log-dir DIR]")
            return 0
        else:
            path = Path(argv[i])
            i += 1

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
        if path is not None:
            _dashboard_loop(curses, scr, path)
            return
        while True:
            chosen = _picker_loop(curses, scr, log_dir)
            if chosen is None:
                return
            _dashboard_loop(curses, scr, chosen)

    curses.wrapper(_run)
    return 0
