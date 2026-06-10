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

    return ViewModel(
        title=title, live=live, declared=declared,
        counters={"frames": len(trace.events),
                  "fabricated": fabricated,
                  "violations": violations,
                  "server_requests": server_requests},
        gate_on=gate_on)
