"""
detectors.py — M2 analysis passes over an InteractionTrace.

The adapter (adapters/mcp_session.py) produces the faithful trace and
nothing else; everything judgmental lives here. Each detector takes a
trace and returns Annotation objects — it never mutates events, so the
record of what crossed the wire stays separate from what we think of it.

Detectors only assert what the wire proves. If no initialize frame was
captured, no capability claim is made; if no tools/list was seen, a
schema can't be violated. Absence of evidence is reported as absence,
not as guilt.

Severity scale: 1 = worth a look, 2 = should not happen, 3 = hostile
or hallucinated unless proven otherwise.

    from detectors import annotate
    trace = from_mcp_session_file(path)
    annotate(trace)            # trace.annotations now populated
"""
from __future__ import annotations

from typing import Iterator, Optional

from interaction_trace import (
    Annotation, AnnotationKind, HallucinationCategory,
    ActorKind, EventKind, Event, InteractionTrace, PartKind,
    _new_id,
)

ANNOTATOR = "glassport.detectors"

# Server-initiated requests and the client capability that must have been
# granted in the initialize handshake for the server to send them.
SERVER_REQUEST_CAPABILITY = {
    "sampling/createMessage": "sampling",
    "roots/list": "roots",
    "elicitation/create": "elicitation",
}
ALWAYS_ALLOWED_SERVER_REQUESTS = {"ping"}

_JSON_TYPES = {
    "string": str,
    "boolean": bool,
    "object": dict,
    "array": list,
    "null": type(None),
}


def _ann(event: Event, kind: AnnotationKind, subcategory: str,
         explanation: str, severity: int,
         category: Optional[HallucinationCategory] = None,
         **md) -> Annotation:
    return Annotation(
        id=_new_id("ann"), event_id=event.id, kind=kind, category=category,
        subcategory=subcategory, severity=severity, explanation=explanation,
        annotator=ANNOTATOR,
        metadata={"seq": event.metadata.get("seq"), **md},
    )


def _matches_type(value, type_name: str) -> bool:
    # bool is a subclass of int in Python; JSON Schema keeps them distinct
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = _JSON_TYPES.get(type_name)
    return True if py is None else isinstance(value, py)


def _schema_problems(args, schema) -> Iterator[str]:
    """
    Top-level check of tools/call arguments against a declared inputSchema.
    Deliberately a subset of JSON Schema (required, top-level property
    types, additionalProperties: false) — enough to catch an agent
    inventing arguments, with zero dependencies.
    """
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        return
    if not isinstance(args, dict):
        yield f"arguments are {type(args).__name__}, schema expects object"
        return
    props = schema.get("properties") or {}
    for req in schema.get("required") or []:
        if req not in args:
            yield f"missing required argument '{req}'"
    if schema.get("additionalProperties") is False:
        for key in args:
            if key not in props:
                yield (f"unexpected argument '{key}' "
                       f"(additionalProperties: false)")
    for key, value in args.items():
        spec = props.get(key)
        if not isinstance(spec, dict):
            continue
        declared_type = spec.get("type")
        types = (declared_type if isinstance(declared_type, list)
                 else [declared_type] if isinstance(declared_type, str)
                 else [])
        if types and not any(_matches_type(value, t) for t in types):
            yield (f"argument '{key}' is {type(value).__name__}, "
                   f"schema expects {declared_type}")


def _tool_call_parts(event: Event):
    for p in event.parts:
        if p.kind == PartKind.TOOL_USE:
            yield p.content.get("name", "?"), p.content.get("arguments")


def _list_result_names(event: Event) -> Optional[set[str]]:
    """Tool names in a tools/list response event, or None if not one."""
    if event.metadata.get("method_replied_to") != "<tools/list>":
        return None
    for p in event.parts:
        frame = p.content if isinstance(p.content, dict) else {}
        tools = (frame.get("result") or {}).get("tools")
        if isinstance(tools, list):
            return {t["name"] for t in tools
                    if isinstance(t, dict) and "name" in t}
    return None


def context_violations(trace: InteractionTrace) -> list[Annotation]:
    """
    Wire-provable violations of the session's negotiated context:

      schema_violation        call arguments break the declared inputSchema
      capability_violation    server-initiated request the client never granted
      unknown_server_request  server-initiated request outside the MCP set
      premature_call          tools/call before notifications/initialized
      call_before_declaration tools/call before any tools/list response
      orphaned_response       response whose id matched no request
      surface_change          tools/list result changed mid-session
    """
    out: list[Annotation] = []

    client_caps: Optional[dict] = None
    tool_defs: dict[str, dict] = {}
    for actor in trace.actors:
        if actor.kind == ActorKind.AGENT and "capabilities" in actor.metadata:
            client_caps = actor.metadata["capabilities"]
        for t in actor.metadata.get("tools") or []:
            if isinstance(t, dict) and "name" in t:
                tool_defs.setdefault(t["name"], t)

    initialized_seen = False
    first_surface: Optional[set[str]] = None

    for e in trace.events:
        md = e.metadata

        if e.kind == EventKind.MESSAGE and \
                md.get("method") == "notifications/initialized":
            initialized_seen = True

        names = _list_result_names(e)
        if names is not None:
            if first_surface is None:
                first_surface = names
            elif names != first_surface:
                delta = sorted(names ^ first_surface)
                out.append(_ann(
                    e, AnnotationKind.DIVERGENCE, "surface_change",
                    f"tools/list surface changed mid-session; delta: {delta}",
                    severity=2, delta=delta))

        if e.kind == EventKind.TOOL_CALL:
            for name, args in _tool_call_parts(e):
                if not initialized_seen:
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "premature_call",
                        f"tools/call '{name}' before notifications/initialized",
                        severity=2))
                elif first_surface is None:
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "call_before_declaration",
                        f"tools/call '{name}' before any tools/list response",
                        severity=1))
                schema = (tool_defs.get(name) or {}).get("inputSchema")
                for problem in _schema_problems(args, schema):
                    out.append(_ann(
                        e, AnnotationKind.DIVERGENCE, "schema_violation",
                        f"'{name}': {problem}", severity=2,
                        category=HallucinationCategory.TOOL_USE))

        if md.get("server_initiated") and not md.get("notification"):
            method = md.get("method")
            if method in ALWAYS_ALLOWED_SERVER_REQUESTS:
                pass
            elif method in SERVER_REQUEST_CAPABILITY:
                needed = SERVER_REQUEST_CAPABILITY[method]
                # no initialize captured -> no claim either way
                if client_caps is not None and needed not in client_caps:
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "capability_violation",
                        f"server requested '{method}' but the client never "
                        f"granted the '{needed}' capability", severity=3))
            else:
                out.append(_ann(
                    e, AnnotationKind.ANOMALY, "unknown_server_request",
                    f"server-initiated request '{method}' is not a known "
                    f"MCP client capability", severity=2))

        if md.get("orphaned"):
            out.append(_ann(
                e, AnnotationKind.ANOMALY, "orphaned_response",
                f"response id={md.get('jsonrpc_id')} matched no request",
                severity=1))

    return out


def fabricated_calls(trace: InteractionTrace) -> list[Annotation]:
    """trace.fabricated_tool_calls() lifted into annotations."""
    events_by_id = {e.id: e for e in trace.events}
    declared = trace.declared_tools()
    out = []
    for event_id, name in trace.fabricated_tool_calls():
        out.append(_ann(
            events_by_id[event_id], AnnotationKind.HALLUCINATION,
            "fabricated_tool_call",
            f"tools/call '{name}' is outside the declared surface",
            severity=3, category=HallucinationCategory.TOOL_USE,
            no_declaration_seen=not declared))
    return out


DETECTORS = [fabricated_calls, context_violations]


def annotate(trace: InteractionTrace) -> list[Annotation]:
    """Run every detector and attach the results to the trace."""
    found: list[Annotation] = []
    for detector in DETECTORS:
        found.extend(detector(trace))
    trace.annotations.extend(found)
    return found
