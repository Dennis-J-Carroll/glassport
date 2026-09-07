"""Bounded, replayable session facts. No annotations or forwarding decisions."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
from typing import Any

from glassport.interaction_trace import Event, EventKind, PartKind, tool_declaration


@dataclass(frozen=True)
class SessionLimits:
    max_pending: int = 4096
    max_tools: int = 4096
    max_state_bytes: int = 1_000_000
    max_name_chars: int = 1024

    def __post_init__(self):
        if any(type(v) is not int or v < 1 for v in asdict(self).values()):
            raise ValueError("session limits must be positive integers")


def bounded_copy(value: Any, limit: int):
    """Copy JSON-compatible state only when its serialized size fits the budget."""
    size = 0
    try:
        for chunk in json.JSONEncoder(ensure_ascii=True).iterencode(value):
            size += len(chunk)
            if size > limit:
                return None
        return deepcopy(value)
    except (TypeError, ValueError, RecursionError):
        return None


def event_frame(event: Event) -> dict:
    for part in event.parts:
        if part.kind == PartKind.JSON and isinstance(part.content, dict):
            return part.content
    return {}


class SessionState:
    """Facts after the most recently observed event; never retains event history.

    ``surface is None`` includes missing, malformed, incomplete, and oversized
    declarations. None must never be compared as an empty exclusion set.
    ``limit_reasons`` contains fixed diagnostic codes, not attacker-controlled
    values. Correlation remains in the protocol builder; normalized responses
    carry their request method and pagination cursor for deterministic replay.
    """

    def __init__(self, limits: SessionLimits | None = None):
        self.limits = limits or SessionLimits()
        self.initialized = False
        self.initialize_seen = False
        self.tools_list_requested = False
        self.client_capabilities: dict | None = None
        self.server_capabilities: dict | None = None
        self.server_info: dict | None = None
        self.surface: frozenset[str] | None = None
        self.first_surface: frozenset[str] | None = None
        self.tool_defs: dict[str, dict] = {}
        self.surface_event_id: str | None = None
        self.surface_seq: Any = None
        self.surface_updated = False
        self.surface_delta: list[str] = []
        self.limit_reasons: set[str] = set()
        self._pages: list[dict] | None = None
        self._next_cursor: str | None = None

    @classmethod
    def from_trace(cls, trace):
        state = cls(SessionLimits(**trace.metadata.get("session_limits", {})))
        # Generic traces may declare a static actor surface. MCP metadata is
        # a final snapshot: only replayed events establish prior knowledge.
        initial = trace._initial_surface()
        if initial is not None:
            if len(initial) <= state.limits.max_tools and all(
                isinstance(n, str) and len(n) <= state.limits.max_name_chars for n in initial
            ):
                state.surface = state.first_surface = frozenset(initial)
            else:
                state.limit_reasons.add("tool_declaration")
        if trace.metadata.get("source") != "glassport_tap":
            for actor in trace.actors:
                if actor.kind.value == "agent" and "capabilities" in actor.metadata:
                    state.client_capabilities = state._dict(actor.metadata["capabilities"])
                if "server_info" in actor.metadata:
                    state.server_info = state._dict(actor.metadata["server_info"])
                for tool in actor.metadata.get("tools") or []:
                    if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                        state.tool_defs[tool["name"]] = tool
            tools = state._bounded_tools(list(state.tool_defs.values()))
            state.tool_defs = {t["name"]: t for t in tools} if tools is not None else {}
        return state

    def _dict(self, value) -> dict | None:
        if not isinstance(value, dict):
            return None
        result = bounded_copy(value, self.limits.max_state_bytes)
        if result is None:
            self.limit_reasons.add("session_metadata")
        return result

    def _bounded_tools(self, tools: list[dict]) -> list[dict] | None:
        if len(tools) > self.limits.max_tools or any(
            len(t["name"]) > self.limits.max_name_chars for t in tools
        ):
            self.limit_reasons.add("tool_declaration")
            return None
        result = bounded_copy(tools, self.limits.max_state_bytes)
        if result is None:
            self.limit_reasons.add("tool_declaration")
        return result

    def _unknown_surface(self):
        self.surface = None
        self.tool_defs = {}
        self.surface_event_id = self.surface_seq = None

    def observe(self, event: Event) -> None:
        """Fold one normalized event in wire order, without modifying evidence."""
        self.surface_updated = False
        self.surface_delta = []
        md = event.metadata
        frame = event_frame(event)
        if event.kind == EventKind.MESSAGE and not md.get("server_initiated"):
            method = md.get("method")
            if method == "notifications/initialized":
                self.initialized = True
            elif method == "initialize":
                self.initialize_seen = True
                params = frame.get("params")
                self.client_capabilities = self._dict(params.get("capabilities", {})) \
                    if isinstance(params, dict) else None
            elif method == "tools/list":
                self.tools_list_requested = True
        if md.get("method_replied_to") == "<initialize>":
            result = frame.get("result")
            if isinstance(result, dict) and "error" not in frame:
                self.server_capabilities = self._dict(result.get("capabilities", {}))
                self.server_info = self._dict(result.get("serverInfo"))

        if md.get("method_replied_to") != "<tools/list>":
            return
        self.surface_updated = True
        tools = tool_declaration(event)
        request_cursor = md.get("request_cursor")
        result = frame.get("result")
        next_cursor = result.get("nextCursor") if isinstance(result, dict) else None
        if tools is None or (request_cursor is not None and (
            self._pages is None or request_cursor != self._next_cursor
        )):
            self._pages = self._next_cursor = None
            self._unknown_surface()
            return
        if request_cursor is None:
            self._pages = []
        combined = (self._pages or []) + tools
        tools = self._bounded_tools(combined)
        if tools is None or (next_cursor is not None and (
            not isinstance(next_cursor, str) or not next_cursor
            or len(next_cursor) > self.limits.max_name_chars or next_cursor == request_cursor
        )):
            self._pages = self._next_cursor = None
            self._unknown_surface()
            return
        if next_cursor is not None:
            self._pages, self._next_cursor = tools, next_cursor
            self._unknown_surface()
            return
        self._pages = self._next_cursor = None
        self.tool_defs = {t["name"]: t for t in tools}
        self.surface = frozenset(self.tool_defs)
        self.surface_event_id = event.id
        self.surface_seq = md.get("seq")
        if self.first_surface is None:
            self.first_surface = self.surface
        else:
            self.surface_delta = sorted(self.first_surface ^ self.surface)
