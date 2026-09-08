"""
adapters/mcp_session.py — turn a glassport_tap session log into an
InteractionTrace.

The tap log is the contract (see glassport_tap.py header). Each line:

    {schema_version, seq, ts, dir: "c2s"|"s2c", frame: dict|null, raw: str|null}

What a tap sees and what it does NOT see
----------------------------------------
The tap sits on the stdio wire between an MCP *client* and an MCP
*server*. It never sees the model's reasoning, the user's prompt, or the
agent's internal plan — only JSON-RPC frames crossing the pipe. So the
mapping is deliberately modest and honest about its blind spots:

  * The CLIENT is modeled as an AGENT actor. It is the thing that emits
    tool calls, so for the purposes of called_tools() it plays the agent.
  * The SERVER is modeled as an EXTERNAL actor hosting tools. Its surface
    comes from correlated tools/list results, published in actor metadata
    and reconstructed in wire order by SessionState.
  * tools/call (c2s)      -> TOOL_CALL event
  * the matching result (s2c) -> TOOL_RESULT event, parent = the call
  * JSON-RPC errors (s2c) -> TOOL_RESULT event flagged is_error, OR a
    STATE_CHANGE if the error is not tied to a call.
  * tools/list result     -> populates the server actor's declared tools;
    also emitted as an INFO-ish STATE_CHANGE so the handshake is visible
    in the timeline.
  * notifications (no id)  -> MESSAGE events; they carry no request/response
    pairing and that distinction is preserved in metadata.

Correlation is by JSON-RPC `id`. A request and its response share an id;
that is how a TOOL_RESULT finds its parent TOOL_CALL. Responses whose id
never matched a request are still emitted, parented to None, and flagged
in metadata as orphaned — that orphaning is itself a signal worth seeing.

This adapter intentionally does NOT detect hallucinations. It produces the
faithful trace; detectors (fabricated_tool_calls, context_violations, …)
run on top. Keep the ingest dumb and the analysis separate.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from glassport.interaction_trace import (
    Actor, Event, Part, InteractionTrace,
    ProtocolKind, ActorKind, EventKind, PartKind, TaskState,
    _new_id,
)

from glassport.session import SessionLimits, SessionState, bounded_copy


def _iter_entries(source: Iterable[str]) -> Iterable[dict]:
    """Yield parsed log entries; bare non-JSON lines become synthetic entries."""
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            # bare wire line — wrap it so the main loop can emit an event
            yield {"schema_version": "0.1", "seq": None, "ts": "",
                   "dir": None, "frame": None, "raw": line}
            continue
        if isinstance(entry, dict) and \
                str(entry.get("type", "")).startswith("glassport."):
            # tap self-observation (e.g. glassport.metrics) — not wire
            # traffic; it must never appear in any analysis view
            continue
        yield entry


@dataclass(frozen=True)
class _PendingRequest:
    event_id: str | None
    method: str | None
    tool_name: str | None = None
    cursor: str | None = None
    generation: int | None = None


class MCPTraceBuilder:
    """Incremental MCP evidence normalization and bounded session facts.

    ingest_frame() returns the newly observed event; snapshot() keeps the
    same InteractionTrace object. History retention defaults on for existing
    file/report consumers. Use retain_events=False for bounded live analysis.
    """

    def __init__(self,
                 server_name: str = "mcp_server",
                 client_name: str = "mcp_client",
                 user_intent: Optional[str] = None, *,
                 retain_events: bool = True,
                 limits: SessionLimits | None = None) -> None:
        self.state = SessionState(limits)
        self.retain_events = retain_events
        self.correlation_evictions = 0
        self.client = Actor.agent(client_name)  # the caller == agent surface
        # The server HOSTS tools; it is not itself a callable tool. Modeling
        # it as TOOL would leak its name into declared_tools(). EXTERNAL is
        # honest: the declared surface lives on the client's AgentCard.
        self.server = Actor(id=_new_id("ext"), kind=ActorKind.EXTERNAL,
                            name=server_name,
                            metadata={"role": "mcp_server"})
        self.events: list[Event] = []
        # JSON-RPC ids are per-sender: the client and the server each run
        # their own id sequence over the same pipe, so id 1 from the client
        # and id 1 from the server are different requests. Two pending maps,
        # one per direction, keep them from cross-pairing.
        # request id -> typed request facts (None method marks ambiguous reuse)
        self.pending: OrderedDict = OrderedDict()      # client-initiated
        self.pending_s2c: OrderedDict = OrderedDict()  # server-initiated
        self._quarantined = {"c2s": set(), "s2c": set()}
        self._correlation_saturated: set[str] = set()
        self._generation_counter = 0
        self.error_seen = False
        self.last_event_id: Optional[str] = None    # rough causal spine
        self._client_name = client_name
        self._user_intent = user_intent
        self._trace: Optional[InteractionTrace] = None

    def _lost(self, request, event):
        if (request is not None and request.method == "tools/list"
                and request.generation is not None
                and request.generation == self.state.declaration_generation):
            event.metadata["declaration_correlation_lost"] = True

    def _quarantine(self, direction, key, event):
        quarantine = self._quarantined[direction]
        if key in quarantine:
            return
        if len(quarantine) < self.state.limits.max_pending:
            quarantine.add(key)
        else:
            # Forgetting ambiguous IDs would permit a delayed old response to
            # impersonate a new request. Once this bounded set fills, stop
            # establishing new correlations in this direction for this session.
            self._correlation_saturated.add(direction)
            event.metadata["correlation_saturated"] = direction

    def _remember(self, pending, rid, event, method, tool_name=None, cursor=None):
        direction = "c2s" if pending is self.pending else "s2c"
        key = (type(rid), rid) if self._valid_id(rid) else None
        prior = pending.pop(key, None) if key is not None else None
        if prior is not None:
            self._quarantine(direction, key, event)
        if pending is self.pending:
            self._lost(prior, event)
        if key is not None and len(pending) >= self.state.limits.max_pending:
            evicted_key, evicted = pending.popitem(last=False)
            self._quarantine(direction, evicted_key, event)
            if pending is self.pending:
                self._lost(evicted, event)
            self.correlation_evictions += 1
            event.metadata["correlation_limited"] = True
        valid = (key is not None and prior is None
                 and key not in self._quarantined[direction]
                 and direction not in self._correlation_saturated
                 and isinstance(method, str) and bool(method)
                 and len(method) <= self.state.limits.max_name_chars
                 and (method != "tools/call" or (isinstance(tool_name, str)
                      and len(tool_name) <= self.state.limits.max_name_chars))
                 and (cursor is None or (isinstance(cursor, str)
                      and 0 < len(cursor) <= self.state.limits.max_name_chars)))
        if method == "tools/list":
            params = event.parts[0].content.get("params")
            valid = valid and (params is None or isinstance(params, dict))
        generation = None
        if pending is self.pending and method == "tools/list":
            if cursor is None:
                # Fixed-size, deterministic identity also survives raw replay.
                # Exhaustion fails to unknown instead of wrapping into old IDs.
                if self._generation_counter < (1 << 128) - 1:
                    self._generation_counter += 1
                    generation = self._generation_counter
            elif self.state.can_continue(cursor):
                generation = self.state.declaration_generation
            if not valid:
                generation = None
            event.metadata["declaration_generation"] = generation
        if not valid:
            event.metadata["correlation_limited"] = True
            if key is not None:
                self._quarantine(direction, key, event)
        if key is None:
            return
        pending[key] = (_PendingRequest(event.id, method, tool_name, cursor, generation)
                        if valid else _PendingRequest(None, None))

    def _valid_id(self, rid):
        return ((type(rid) is int and rid.bit_length() <= 128)
                or (type(rid) is str and len(rid) <= self.state.limits.max_name_chars))

    def _reply(self, pending, rid):
        return pending.pop((type(rid), rid), _PendingRequest(None, None)) \
            if self._valid_id(rid) else _PendingRequest(None, None)

    def ingest_frame(self, entry: dict) -> Optional[Event]:
        """Normalize one tap entry, update session facts, return its event.

        Set retain_events=False for a bounded live fold. Persist input entries
        separately; snapshot() then contains current actors/state, not history.
        """
        if not isinstance(entry, dict):
            raise ValueError("tap entry must be an object")
        before = len(self.events)
        self._feed_entry(entry)
        if len(self.events) == before:
            return None
        event = self.events[-1]
        if isinstance(entry.get("gate"), dict):
            event.metadata["gate"] = entry["gate"]
        # Actor metadata is a bounded materialized view; events remain faithful.
        changed_actors = (self.client, self.server) if (
            event.metadata.get("method") == "initialize"
            or event.metadata.get("method_replied_to") == "<initialize>"
        ) else ()
        for actor in changed_actors:
            for key, value in list(actor.metadata.items()):
                copied = bounded_copy(value, self.state.limits.max_state_bytes)
                if copied is None and value is not None:
                    actor.metadata.pop(key, None)
                    event.metadata["session_metadata_limited"] = True
        self.state.observe(event)
        if not self.retain_events:
            self.events.clear()
        return event

    def feed(self, entry: dict) -> Optional[Event]:
        """Compatibility spelling for ingest_frame()."""
        return self.ingest_frame(entry)

    def _feed_entry(self, entry: dict) -> None:
        client, server = self.client, self.server
        events = self.events
        pending, pending_s2c = self.pending, self.pending_s2c
        last_event_id = self.last_event_id
        frame = entry.get("frame")
        if not isinstance(frame, dict):
            # raw/unparseable wire line — preserve it as a MESSAGE so no
            # data is lost on import (Open design Q #2: don't drop on ingest)
            raw = entry.get("raw")
            if raw is None:
                return
            ev = Event(
                id=_new_id("evt"), timestamp=entry.get("ts", ""),
                actor_id=(client.id if entry.get("dir") == "c2s" else server.id),
                kind=EventKind.MESSAGE,
                parts=[Part(kind=PartKind.TEXT, content=raw)],
                parent_event_id=last_event_id,
                metadata={"seq": entry.get("seq"), "unparsed": True,
                          "dir": entry.get("dir")},
            )
            events.append(ev)
            self.last_event_id = ev.id
            return

        direction = entry.get("dir")
        ts = entry.get("ts", "")
        seq = entry.get("seq")
        method = frame.get("method")
        rid = frame.get("id")
        is_notification = method is not None and "id" not in frame

        # ── client → server ─────────────────────────────────────────
        if direction == "c2s":
            # the initialize request carries the client's granted
            # capabilities — the context the server is allowed to use
            if method == "initialize":
                params = frame.get("params") or {}
                client.metadata["capabilities"] = params.get("capabilities") or {}
                client.metadata["client_info"] = params.get("clientInfo")
                client.metadata["protocol_version"] = params.get("protocolVersion")

            if method == "tools/call":
                params = frame.get("params") or {}
                name = params.get("name", "?")
                args = params.get("arguments", {})
                ev = Event.tool_call(
                    client.id, name, args,
                    target_id=server.id, parent_event_id=last_event_id,
                    metadata={"seq": seq, "jsonrpc_id": rid},
                )
                ev.timestamp = ts
                events.append(ev)
                self.last_event_id = ev.id
                if rid is not None:
                    self._remember(pending, rid, ev, "tools/call", tool_name=name)

            elif is_notification:
                ev = Event(
                    id=_new_id("evt"), timestamp=ts, actor_id=client.id,
                    kind=EventKind.MESSAGE, target_id=server.id,
                    parts=[Part(kind=PartKind.JSON, content=frame)],
                    parent_event_id=last_event_id,
                    metadata={"seq": seq, "method": method,
                              "notification": True},
                )
                events.append(ev)
                self.last_event_id = ev.id

            elif method is None and ("result" in frame or "error" in frame):
                # client's reply to a server-initiated request
                request = self._reply(pending_s2c, rid)
                parent_eid = request.event_id
                req_method = f"<{request.method}>" if request.method else None
                ev = Event(
                    id=_new_id("evt"), timestamp=ts, actor_id=client.id,
                    kind=EventKind.MESSAGE, target_id=server.id,
                    parts=[Part(kind=PartKind.JSON, content=frame)],
                    parent_event_id=parent_eid or last_event_id,
                    metadata={"seq": seq, "jsonrpc_id": rid,
                              "responds_to": req_method,
                              "orphaned": parent_eid is None and rid is not None},
                )
                events.append(ev)
                self.last_event_id = ev.id

            else:
                # other request methods (initialize, tools/list, ping…)
                ev = Event(
                    id=_new_id("evt"), timestamp=ts, actor_id=client.id,
                    kind=EventKind.MESSAGE, target_id=server.id,
                    parts=[Part(kind=PartKind.JSON, content=frame)],
                    parent_event_id=last_event_id,
                    metadata={"seq": seq, "method": method, "jsonrpc_id": rid},
                )
                events.append(ev)
                self.last_event_id = ev.id
                if rid is not None and "method" in frame:
                    # remember non-call requests so their results can pair too
                    params = frame.get("params")
                    cursor = params.get("cursor") if isinstance(params, dict) else None
                    self._remember(pending, rid, ev, method, cursor=cursor if method == "tools/list" else None)

        # ── server → client ─────────────────────────────────────────
        elif direction == "s2c":
            if method is not None:
                # server-initiated traffic: a request (sampling/createMessage,
                # roots/list, ping, …) or a notification. Never a response,
                # so it must not consume the client's pending map.
                ev = Event(
                    id=_new_id("evt"), timestamp=ts, actor_id=server.id,
                    kind=EventKind.MESSAGE, target_id=client.id,
                    parts=[Part(kind=PartKind.JSON, content=frame)],
                    parent_event_id=last_event_id,
                    metadata={"seq": seq, "method": method,
                              "server_initiated": True,
                              "notification": is_notification,
                              "jsonrpc_id": rid},
                )
                events.append(ev)
                self.last_event_id = ev.id
                if rid is not None:
                    self._remember(pending_s2c, rid, ev, method)
                return

            result = frame.get("result")
            error = frame.get("error")

            request = self._reply(pending, rid)
            parent_eid, call_name = request.event_id, request.tool_name
            reply_method = f"<{request.method}>" if request.method else None

            # the initialize result carries the server's declared
            # capabilities and identity — stamp them on the server actor
            if request.method == "initialize" and isinstance(result, dict):
                server.metadata["capabilities"] = result.get("capabilities") or {}
                server.metadata["server_info"] = result.get("serverInfo")
                server.metadata["protocol_version"] = result.get("protocolVersion")

            if error is not None:
                msg = (error or {}).get("message", str(error))
                if parent_eid is not None and request.method == "tools/call":
                    # error responding to a real tools/call
                    ev = Event.tool_result(
                        server.id, tool_use_id=str(rid), output=error,
                        is_error=True, target_id=client.id,
                        parent_event_id=parent_eid,
                        metadata={"seq": seq, "jsonrpc_id": rid,
                                  "tool_name": call_name},
                    )
                else:
                    # protocol-level error not tied to a tool call
                    ev = Event(
                        id=_new_id("evt"), timestamp=ts, actor_id=server.id,
                        kind=EventKind.STATE_CHANGE, target_id=client.id,
                        parts=[Part(kind=PartKind.ERROR, content=error)],
                        parent_event_id=parent_eid or last_event_id,
                        metadata={"seq": seq, "jsonrpc_id": rid,
                                  "error_message": msg,
                                  "orphaned": parent_eid is None and rid is not None},
                    )
                ev.timestamp = ts
                events.append(ev)
                self.last_event_id = ev.id
                self.error_seen = True

            elif parent_eid is not None and request.method == "tools/call":
                # successful result to a tools/call
                ev = Event.tool_result(
                    server.id, tool_use_id=str(rid), output=result,
                    is_error=bool(isinstance(result, dict)
                                  and result.get("isError")),
                    target_id=client.id, parent_event_id=parent_eid,
                    metadata={"seq": seq, "jsonrpc_id": rid,
                              "tool_name": call_name},
                )
                ev.timestamp = ts
                events.append(ev)
                self.last_event_id = ev.id

            else:
                # result to a non-call request (initialize, tools/list, …)
                # or an orphaned response with no matching request
                ev = Event(
                    id=_new_id("evt"), timestamp=ts, actor_id=server.id,
                    kind=EventKind.STATE_CHANGE, target_id=client.id,
                    parts=[Part(kind=PartKind.JSON, content=frame)],
                    parent_event_id=parent_eid or last_event_id,
                    metadata={"seq": seq, "jsonrpc_id": rid,
                              "method_replied_to": reply_method,
                              "orphaned": parent_eid is None and rid is not None},
                )
                events.append(ev)
                self.last_event_id = ev.id

            if request.method == "tools/list":
                ev.metadata["method_replied_to"] = "<tools/list>"
                ev.metadata["declaration_generation"] = request.generation
                if request.cursor is not None:
                    ev.metadata["request_cursor"] = request.cursor

    def snapshot(self) -> InteractionTrace:
        """Materialize the current state. Re-runnable after more feed()
        calls: finalization is idempotent, and the same trace object is
        returned every time (events list shared, updated in place)."""
        declared = list(self.state.tool_defs.values())
        if self.state.surface is not None:
            self.server.metadata["tools"] = declared
            self.client.metadata["agent_card"] = {
                "name": self._client_name,
                "skills": [{"name": name} for name in self.state.tool_defs],
            }
        else:
            self.server.metadata.pop("tools", None)
            self.client.metadata.pop("agent_card", None)

        final_state: Optional[TaskState] = None
        if self.error_seen:
            final_state = TaskState.FAILED
        elif self.last_event_id is not None:
            final_state = TaskState.COMPLETED

        if self._trace is None:
            self._trace = InteractionTrace(
                id=_new_id("trace"),
                protocol=ProtocolKind.AGENT_TOOL,
                actors=[self.client, self.server],
                events=self.events,
                intent=self._user_intent,
                final_state=final_state,
                metadata={"source": "glassport_tap",
                          "declared_tool_count": len(declared),
                          "declaration_known": self.state.surface is not None},
            )
        else:
            self._trace.final_state = final_state
            self._trace.metadata["declared_tool_count"] = len(declared)
            self._trace.metadata["declaration_known"] = self.state.surface is not None
        self._trace.metadata["session_limits"] = asdict(self.state.limits)
        self._trace.metadata["correlation_evictions"] = self.correlation_evictions
        self._trace.metadata["history_retained"] = self.retain_events
        if not self.retain_events:
            self._trace.metadata["current_surface"] = (
                sorted(self.state.surface) if self.state.surface is not None else None)
        return self._trace


# Existing file-poll consumers keep their private import during migration.
_TraceBuilder = MCPTraceBuilder


def from_mcp_session(
    log_lines: Iterable[str],
    server_name: str = "mcp_server",
    client_name: str = "mcp_client",
    user_intent: Optional[str] = None,
) -> InteractionTrace:
    """
    Build an InteractionTrace from glassport_tap JSONL lines.

    `log_lines` is any iterable of strings (open file, list, generator).
    Order is taken from the log as written; `seq` is preserved in event
    metadata so timeline ordering is reconstructable even if timestamps
    collide.
    """
    builder = _TraceBuilder(server_name=server_name,
                            client_name=client_name,
                            user_intent=user_intent)
    for entry in _iter_entries(log_lines):
        builder.feed(entry)
    return builder.snapshot()


# Beyond this, only the trailing tail_cap_bytes are parsed and the trace
# carries metadata["tail_only"] = True so every consumer can say so.
# Shared with adapters/streaming.py — batch and streaming must agree on
# what a large file means, or their test-locked equality breaks at 50MB.
TAIL_CAP_BYTES = 50_000_000

_USE_DEFAULT = -1


def from_mcp_session_file(path: str | Path,
                          tail_cap_bytes: int | None = _USE_DEFAULT,
                          **kw) -> InteractionTrace:
    """Read a .jsonl session file from disk.

    Files larger than tail_cap_bytes (default TAIL_CAP_BYTES; None
    disables) are ingested tail-only from a line boundary, mirroring
    StreamingSession: metadata["tail_only"] = True marks the trace as
    partial — doctrine says a dropped head must never look complete."""
    cap = TAIL_CAP_BYTES if tail_cap_bytes == _USE_DEFAULT else tail_cap_bytes
    p = Path(path)
    if cap is not None and p.stat().st_size > cap:
        with open(p, "rb") as fh:
            fh.seek(p.stat().st_size - cap)
            fh.readline()                    # drop the cut-off line
            data = fh.read()
        lines = (raw.decode("utf-8", errors="replace")
                 for raw in data.split(b"\n"))
        trace = from_mcp_session(lines, **kw)
        trace.metadata["tail_only"] = True
        return trace
    with open(p, encoding="utf-8") as fh:
        return from_mcp_session(fh, **kw)
