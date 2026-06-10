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
