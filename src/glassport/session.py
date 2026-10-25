"""Bounded, replayable session facts. No annotations or forwarding decisions.

PLAY-BY-PLAY
------------
`SessionState` is what the session believes right now, and it is the only
thing that does: detectors read it, the gate reads it, replay rebuilds
it. It holds no event history, so the answer to "what is true" never
depends on how long the process has been running.

The single fact everything else depends on is the declared tool surface:
the set of tools the server said it offers. It is three-valued, and this
file is where that is enforced.

    None       unknown -- no usable declaration has been observed
    set()      known to be empty -- the server declared nothing
    frozenset  the declared names

Collapsing None into set() would turn "nobody told us" into "the server
offers nothing", which is how an innocent call becomes a fabricated one.
Nothing in this file compares None as a set.

The fold, per event:

1. `asdict()`-style limits and `bounded_copy()` keep state inside fixed
   budgets, so a hostile session cannot make the fold grow without bound.
2. `observe()` applies exactly one event, in wire order. Declaration
   freshness is measured on the wire clock (`_wire_seconds`), so a live
   pass and a replay reach the same verdict.
3. A listing that spans pages is held as pending pages; the current
   surface stays authority until the chain completes.

WHAT THIS FILE DOES NOT DO
--------------------------
It emits no annotations and makes no forwarding decision. It never
retains event history, never reads a file, and never raises on
attacker-shaped input -- an unreadable fact becomes a limit reason.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
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
        # PLAY: `type(v) is not int` rejects bools as well as strings --
        # True is an int subclass, and a limit of True would read as 1
        # while looking like a deliberate setting. v < 1 rejects zero,
        # which would otherwise mean "bound everything at nothing".
        if any(type(v) is not int or v < 1 for v in asdict(self).values()):
            raise ValueError("session limits must be positive integers")


def bounded_copy(value: Any, limit: int):
    """Copy JSON-compatible state only when its serialized size fits the budget."""
    # PLAY: iterencode streams the JSON in chunks, so the size is measured
    # while encoding instead of materializing a copy first. Crossing the
    # limit returns None -- never a truncated dict -- because a partial
    # copy of a declaration would be a wrong answer, not a smaller one.
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


_LIST_CHANGED = "notifications/tools/list_changed"


def _wire_seconds(timestamp) -> float | None:
    """Epoch seconds of an ISO 8601 wire timestamp with a zone, else None.

    Declaration freshness is measured on the wire clock, never the local one,
    so a live pass and a replay of the same log reach the same answer.
    """
    # PLAY: A naive timestamp returns None, which callers treat as stale.
    # Without a zone there is no way to compare it to anything, and
    # guessing the local zone is how replay stops matching the live run.
    if not isinstance(timestamp, str):
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.timestamp() if parsed.tzinfo is not None else None


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
        self.declaration_generation: int | None = None
        self._page_pending = False
        # Wire-clock second after which the surface stops being authority
        # (from ttlMs), and the earliest such bound across pending pages.
        self.surface_expires_at: float | None = None
        self._pages_expire_at: float | None = None

    @classmethod
    def from_trace(cls, trace):
        state = cls(SessionLimits(**trace.metadata.get("session_limits", {})))
        # Generic traces may declare a static actor surface. MCP metadata is
        # a final snapshot: only replayed events establish prior knowledge.
        # PLAY: This is the temporal rule again, now applied at construction.
        # A tap trace's actor metadata describes the END of the session; a
        # generic trace's actor card is a declaration of intent. Only the
        # latter may seed the starting surface.
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
        # PLAY: Every dict that enters state passes through here, so the
        # size budget is enforced in one place. A value that does not fit
        # becomes None plus a named limit -- the caller says "unknown"
        # rather than "here is the part that fit".
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
        # PLAY: Four things are cleared together, and the pairing matters.
        # A surface of None with stale tool_defs still in place would let a
        # schema check run against tools the server no longer declares.
        self.surface = None
        self.tool_defs = {}
        self.surface_event_id = self.surface_seq = None
        self.surface_expires_at = None

    def current_at(self, timestamp) -> bool:
        """Whether the surface's ttlMs promise still holds at this wire time.

        Stale strictly after the bound; an unreadable clock is stale. Pure:
        an enforcer may ask between events, and the next observed event is
        what retires the surface.
        """
        # PLAY: No ttlMs means no expiry. An unreadable clock means stale,
        # because a promise we cannot evaluate cannot be relied on -- that
        # is the fail-closed direction, and it is the only one that does
        # not invent a fact.
        if self.surface_expires_at is None:
            return True
        now = _wire_seconds(timestamp)
        return now is not None and now <= self.surface_expires_at

    @property
    def listing_in_flight(self) -> bool:
        """A correlated tools/list request is awaiting its reply."""
        return self._page_pending

    def can_continue(self, cursor) -> bool:
        return (self.declaration_generation is not None and self._pages is not None
                and not self._page_pending and cursor == self._next_cursor)

    def _cancel_pending_declaration(self):
        """Abandon an in-progress listing without touching the current surface.

        Client-side events (a relist, a malformed cursor, a duplicated or
        evicted request id) only ever affect the *pending* declaration: the
        current one stays authority until a complete, correlated reply
        replaces it. Otherwise any caller could switch enforcement off by
        relisting and never finishing.
        """
        # PLAY: Note what is NOT cleared here: surface, tool_defs, and the
        # expiry. That is the point. A caller who starts a listing and
        # never finishes it has changed nothing about what the server
        # currently offers.
        self._pages = self._next_cursor = self.declaration_generation = None
        self._page_pending = False
        self._pages_expire_at = None

    def _invalidate_declaration(self):
        self._unknown_surface()
        self._pages = self._next_cursor = self.declaration_generation = None
        self._page_pending = False
        self._pages_expire_at = None

    def observe(self, event: Event) -> None:
        """Fold one normalized event in wire order, without modifying evidence."""
        # PLAY: Two flags are reset at the top of every event. They report
        # what THIS event changed, so a consumer that looks after every
        # observation never sees a stale true from an earlier frame.
        self.surface_updated = False
        self.surface_delta = []
        md = event.metadata
        # PLAY: A lost observation epoch (HTTP reinitialize) is not "the
        # server undeclared itself"; it is "we stopped being able to
        # tell". Rebuilding the state from scratch is the only honest
        # answer, and the reason it is a reset rather than a merge.
        if md.get("http_observation_loss") is True:
            self.__init__(self.limits)
            return
        if md.get("session_metadata_limited"):
            self.limit_reasons.add("session_metadata")
        if md.get("correlation_saturated"):
            self.limit_reasons.add("request_correlation_saturated")
        frame = event_frame(event)
        if md.get("declaration_correlation_lost"):
            self._cancel_pending_declaration()
        if not self.current_at(event.timestamp):
            # Stale: unknown, never empty. Retire only the current surface;
            # a refresh already requested may still land and restore it.
            self._unknown_surface()
        if (event.kind == EventKind.MESSAGE and md.get("server_initiated")
                and md.get("method") == _LIST_CHANGED):
            # Only the server can retract its declaration. Any reply still in
            # flight carries the old generation and is then ignored.
            # PLAY: Server-side, so the verdict is the strong one: unknown.
            # Contrast _cancel_pending_declaration above, which a client
            # can trigger and which therefore must not erase anything.
            self._invalidate_declaration()
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
                params = frame.get("params")
                cursor = params.get("cursor") if isinstance(params, dict) else None
                generation = md.get("declaration_generation")
                if cursor is None:
                    # PLAY: A cursorless tools/list starts a fresh chain. The
                    # pending state from any earlier listing is abandoned
                    # first, so two overlapping listings cannot interleave
                    # their pages into one surface.
                    self._cancel_pending_declaration()
                    self.declaration_generation = generation
                    self._page_pending = generation is not None
                elif (generation is not None
                      and generation == self.declaration_generation
                      and self.can_continue(cursor)):
                    self._page_pending = True
                else:
                    self._cancel_pending_declaration()
        if md.get("method_replied_to") == "<initialize>":
            result = frame.get("result")
            if isinstance(result, dict) and "error" not in frame:
                self.server_capabilities = self._dict(result.get("capabilities", {}))
                self.server_info = self._dict(result.get("serverInfo"))

        if md.get("method_replied_to") != "<tools/list>":
            return
        generation = md.get("declaration_generation")
        if generation is None or generation != self.declaration_generation:
            return  # Superseded or ambiguous responses cannot establish facts.
        self.surface_updated = True
        self._page_pending = False
        tools = tool_declaration(event)
        request_cursor = md.get("request_cursor")
        result = frame.get("result")
        next_cursor = result.get("nextCursor") if isinstance(result, dict) else None
        if tools is None or (request_cursor is not None and (
            self._pages is None or request_cursor != self._next_cursor
        )):
            self._invalidate_declaration()
            return
        if request_cursor is None:
            self._pages = []
            self._pages_expire_at = None
        if isinstance(result, dict) and "ttlMs" in result:
            ttl, sent = result["ttlMs"], _wire_seconds(event.timestamp)
            if type(ttl) is not int or ttl < 0 or sent is None:
                # PLAY: A ttlMs that is negative, a float, a bool, or
                # attached to a timestamp we cannot read is not a shorter
                # promise -- it is no promise, so the declaration cannot
                # be trusted at all.
                self._invalidate_declaration()   # an unreadable promise proves nothing
                return
            expires = sent + ttl / 1000
            if self._pages_expire_at is None or expires < self._pages_expire_at:
                self._pages_expire_at = expires
        combined = (self._pages or []) + tools
        tools = self._bounded_tools(combined)
        if tools is None or (next_cursor is not None and (
            not isinstance(next_cursor, str) or not next_cursor
            or len(next_cursor) > self.limits.max_name_chars or next_cursor == request_cursor
        )):
            # PLAY: Every condition rejects a cursor that could loop. Equal
            # to the request cursor means the page would be fetched twice;
            # not a bounded string means we cannot even store it safely. An
            # invalid cursor leaves the surface unknown rather than guessing
            # that the page we have is the whole list.
            self._invalidate_declaration()
            return
        if next_cursor is not None:
            # An intermediate page: the current surface stays authority until
            # the chain completes (a client may never fetch the next page).
            self._pages, self._next_cursor = tools, next_cursor
            return
        self._pages = self._next_cursor = None
        self.tool_defs = {t["name"]: t for t in tools}
        self.surface = frozenset(self.tool_defs)
        # PLAY: This is the only place the surface is established, and it
        # is reached only by a complete, correlated, size-checked chain.
        # Anything short of that ends in invalidation, never in a partial
        # surface that would look authoritative.
        self.surface_expires_at, self._pages_expire_at = self._pages_expire_at, None
        self.surface_event_id = event.id
        self.surface_seq = md.get("seq")
        if self.first_surface is None:
            self.first_surface = self.surface
        else:
            # PLAY: The delta is measured against the FIRST surface, not
            # the previous one, so a server that removes a tool and adds
            # it back is reported as a change from where the session
            # started -- which is what a reader comparing reports wants.
            self.surface_delta = sorted(self.first_surface ^ self.surface)
