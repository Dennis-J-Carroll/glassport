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
  * The SERVER is modeled as a TOOL actor. Its declared surface comes
    from the tools/list response, stored on the actor so declared_tools()
    works with no AgentCard present.
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
from pathlib import Path
from typing import Any, Iterable, Optional

from interaction_trace import (
    Actor, Event, Part, InteractionTrace,
    ProtocolKind, ActorKind, EventKind, PartKind, TaskState,
    _new_id,
)


def _iter_entries(source: Iterable[str]) -> Iterable[dict]:
    """Yield parsed log entries, skipping unparseable lines."""
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


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
    client = Actor.agent(client_name)          # the caller == agent surface
    # The server HOSTS tools; it is not itself a callable tool. Modeling it
    # as TOOL would leak its name into declared_tools(). EXTERNAL is honest:
    # the declared surface lives on the client's reconstructed AgentCard.
    server = Actor(id=_new_id("ext"), kind=ActorKind.EXTERNAL, name=server_name,
                   metadata={"role": "mcp_server"})

    events: list[Event] = []
    # request id -> (event_id of the TOOL_CALL, tool name)
    pending: dict[Any, tuple[str, str]] = {}
    declared: list[dict] = []                   # accumulates tools/list tools
    final_state: Optional[TaskState] = None
    last_event_id: Optional[str] = None         # rough causal spine

    for entry in _iter_entries(log_lines):
        frame = entry.get("frame")
        if not isinstance(frame, dict):
            # raw/unparseable wire line — preserve it as a MESSAGE so no
            # data is lost on import (Open design Q #2: don't drop on ingest)
            raw = entry.get("raw")
            if raw is None:
                continue
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
            last_event_id = ev.id
            continue

        direction = entry.get("dir")
        ts = entry.get("ts", "")
        seq = entry.get("seq")
        method = frame.get("method")
        rid = frame.get("id")
        is_notification = method is not None and "id" not in frame

        # ── client → server ─────────────────────────────────────────
        if direction == "c2s":
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
                last_event_id = ev.id
                if rid is not None:
                    pending[rid] = (ev.id, name)

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
                last_event_id = ev.id

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
                last_event_id = ev.id
                if rid is not None and method:
                    # remember non-call requests so their results can pair too
                    pending[rid] = (ev.id, f"<{method}>")

        # ── server → client ─────────────────────────────────────────
        elif direction == "s2c":
            result = frame.get("result")
            error = frame.get("error")

            # capture declared surface from any tools/list result
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                for t in result["tools"]:
                    if isinstance(t, dict) and "name" in t:
                        declared.append(t)

            parent_eid, call_name = pending.pop(rid, (None, None)) \
                if rid is not None else (None, None)

            if error is not None:
                msg = (error or {}).get("message", str(error))
                if parent_eid is not None and call_name and \
                        not call_name.startswith("<"):
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
                last_event_id = ev.id
                final_state = TaskState.FAILED

            elif parent_eid is not None and call_name and \
                    not call_name.startswith("<"):
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
                last_event_id = ev.id

            else:
                # result to a non-call request (initialize, tools/list, …)
                # or an orphaned response with no matching request
                ev = Event(
                    id=_new_id("evt"), timestamp=ts, actor_id=server.id,
                    kind=EventKind.STATE_CHANGE, target_id=client.id,
                    parts=[Part(kind=PartKind.JSON, content=frame)],
                    parent_event_id=parent_eid or last_event_id,
                    metadata={"seq": seq, "jsonrpc_id": rid,
                              "method_replied_to": call_name,
                              "orphaned": parent_eid is None and rid is not None},
                )
                events.append(ev)
                last_event_id = ev.id

    # stamp the server's declared tool surface. declared_tools() reads the
    # AGENT's agent_card.skills, so we expose the observed tools there. The
    # server actor keeps the raw tool defs for reference/inspection.
    server.metadata["tools"] = declared
    client.metadata["agent_card"] = {
        "name": client_name,
        "skills": [{"name": t["name"]} for t in declared if "name" in t],
    }

    if final_state is None and events:
        final_state = TaskState.COMPLETED

    return InteractionTrace(
        id=_new_id("trace"),
        protocol=ProtocolKind.AGENT_TOOL,
        actors=[client, server],
        events=events,
        intent=user_intent,
        final_state=final_state,
        metadata={"source": "glassport_tap", "declared_tool_count": len(declared)},
    )


def from_mcp_session_file(path: str | Path, **kw) -> InteractionTrace:
    """Convenience: read a .jsonl session file from disk."""
    with open(path, encoding="utf-8") as fh:
        return from_mcp_session(fh, **kw)
