"""Incremental detection over session facts. No transport or enforcement code."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict

from glassport import detectors
from glassport.interaction_trace import Annotation, Event, EventKind, InteractionTrace, _new_id
from glassport.session import SessionState


class StreamingDetector:
    """One instance per session. Construction starts it; finish closes it.

    Implementations read evidence/state and return annotations. They must not
    mutate events, modify session facts, retain unbounded history, or forward
    or block traffic. Retrospective analysis remains outside this interface.
    """
    name = "streaming_detector"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        return []

    def finish(self, state: SessionState) -> list[Annotation]:
        return []


class FabricatedCallsDetector(StreamingDetector):
    name = "fabricated_calls"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        if event.kind != EventKind.TOOL_CALL or state.surface is None:
            return []
        return [detectors._ann(
            event, detectors.AnnotationKind.HALLUCINATION, "fabricated_tool_call",
            f"tools/call '{name}' is outside the declared surface",
            severity=3, category=detectors.HallucinationCategory.TOOL_USE,
            no_declaration_seen=False, tool=name,
            declaration_seq=state.surface_seq,
        ) for name, _ in detectors._tool_call_parts(event) if name not in state.surface]


class ContextDetector(StreamingDetector):
    name = "context_violations"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        out = []
        md = event.metadata
        if md.get("http_uninterpreted"):
            out.append(detectors._ann(
                event, detectors.AnnotationKind.ANOMALY, "http_observation_unavailable",
                "HTTP session evidence is incomplete; reinitialize for a fresh observation epoch",
                severity=1))
        if state.surface_delta:
            out.append(detectors._ann(
                event, detectors.AnnotationKind.DIVERGENCE, "surface_change",
                f"tools/list surface changed mid-session; delta: {state.surface_delta}",
                severity=2, delta=state.surface_delta))
        if event.kind == EventKind.TOOL_CALL:
            for name, args in detectors._tool_call_parts(event):
                if not state.initialized:
                    out.append(detectors._ann(
                        event, detectors.AnnotationKind.ANOMALY, "premature_call",
                        f"tools/call '{name}' before notifications/initialized", severity=2))
                elif state.first_surface is None and not state.tools_list_requested:
                    out.append(detectors._ann(
                        event, detectors.AnnotationKind.ANOMALY, "call_before_declaration",
                        f"tools/call '{name}' and no tools/list request was ever sent", severity=1))
                if state.surface is None and not (
                    state.initialized and state.first_surface is None
                    and not state.tools_list_requested
                ):
                    out.append(detectors._ann(
                        event, detectors.AnnotationKind.ANOMALY, "declaration_unavailable",
                        f"tools/call '{name}' cannot be checked against an available complete declaration",
                        severity=1))
                schema = (state.tool_defs.get(name) or {}).get("inputSchema")
                for problem in detectors._schema_problems(args, schema):
                    out.append(detectors._ann(
                        event, detectors.AnnotationKind.DIVERGENCE, "schema_violation",
                        f"'{name}': {problem}", severity=2,
                        category=detectors.HallucinationCategory.TOOL_USE))
        if md.get("server_initiated") and not md.get("notification"):
            method = md.get("method")
            if method in detectors.ALWAYS_ALLOWED_SERVER_REQUESTS:
                pass
            elif method in detectors.SERVER_REQUEST_CAPABILITY:
                needed = detectors.SERVER_REQUEST_CAPABILITY[method]
                if state.client_capabilities is not None and needed not in state.client_capabilities:
                    out.append(detectors._ann(
                        event, detectors.AnnotationKind.ANOMALY, "capability_violation",
                        f"server requested '{method}' but the client never granted the '{needed}' capability",
                        severity=3))
            else:
                out.append(detectors._ann(
                    event, detectors.AnnotationKind.ANOMALY, "unknown_server_request",
                    f"server-initiated request '{method}' is not a known MCP client capability", severity=2))
        if md.get("orphaned"):
            out.append(detectors._ann(
                event, detectors.AnnotationKind.ANOMALY, "orphaned_response",
                f"response id={md.get('jsonrpc_id')} matched no request", severity=1))
        return out


class GateRecordsDetector(StreamingDetector):
    name = "gate_actions"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        return detectors._gate_actions_for_event(event)


class DataExfiltrationDetector(StreamingDetector):
    name = "data_exfiltration"

    def __init__(self):
        self._tool_defs = self._server_info = None
        self._declared_hosts: set[str] = set()

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        if state.tool_defs is not self._tool_defs or state.server_info is not self._server_info:
            hosts: set[str] = set()
            detectors._extract_hosts_from_value(state.server_info, hosts)
            for tool in state.tool_defs.values():
                detectors._extract_hosts_from_value(tool.get("description", ""), hosts)
                detectors._extract_hosts_from_value(tool.get("inputSchema", {}), hosts)
            # Commit the cache only after successful extraction.
            self._tool_defs, self._server_info = state.tool_defs, state.server_info
            self._declared_hosts = hosts
        return detectors._exfiltration_for_event(event, self._declared_hosts)


class DetectorEngine:
    """Fault-isolated detector lifecycle; findings are returned, never accumulated.

    The caller supplies the state *after* observing each event. A builder and
    an engine therefore share one state fold instead of updating declarations
    twice. An engine binds to one SessionState; use a new pair for a new session.
    """

    def __init__(self, active: Iterable[StreamingDetector] | None = None):
        self.active = tuple(active) if active is not None else (
            FabricatedCallsDetector(), ContextDetector(), GateRecordsDetector(),
            DataExfiltrationDetector())
        self._state: SessionState | None = None
        self._finished = False
        self._reported_limits: set[str] = set()

    def _bind(self, state: SessionState):
        if self._state is None:
            self._state = state
        elif state is not self._state:
            raise ValueError("detector engine belongs to a different session")

    def _run(self, hook: str, state: SessionState, event: Event | None = None):
        out = []
        for detector in self.active:
            try:
                # Materialize before extending: a generator that fails halfway
                # must not leak partial findings from a failed detector pass.
                found = list(detector.on_event(event, state) if event is not None
                             else detector.finish(state))
                out.extend(found)
            except Exception as exc:
                # Exception messages can contain secrets from hostile payloads.
                # Keep only the type in streaming diagnostics.
                ann = Annotation(
                    id=_new_id("ann"), event_id="", kind=detectors.AnnotationKind.ANOMALY,
                    subcategory="detector_error", severity=2, annotator=detectors.ANNOTATOR,
                    explanation=f"detector {detector.name!r} raised {type(exc).__name__} during {hook}",
                    metadata={"detector": detector.name, "error_type": type(exc).__name__, "phase": hook},
                )
                if event is not None:
                    ann.event_id = event.id
                    ann.metadata["seq"] = event.metadata.get("seq")
                out.append(ann)
        return out

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        if self._finished:
            raise ValueError("detector engine is finished")
        self._bind(state)
        found = self._run("on_event", state, event)
        reasons = state.limit_reasons | ({"request_correlation"}
                  if event.metadata.get("correlation_limited") else set())
        for reason in sorted(reasons - self._reported_limits):
            found.append(detectors._ann(
                event, detectors.AnnotationKind.ANOMALY, "analysis_limit",
                f"session state limit reached ({reason}); analysis may be incomplete",
                severity=1, reason=reason, limits=asdict(state.limits)))
            self._reported_limits.add(reason)
        return found

    def finish(self, state: SessionState) -> list[Annotation]:
        self._bind(state)
        if self._finished:
            return []
        self._finished = True
        return self._run("finish", state)


def replay(trace: InteractionTrace, active: Iterable[StreamingDetector] | None = None) -> list[Annotation]:
    """Batch collection of incremental findings, using the same event-time facts."""
    state = SessionState.from_trace(trace)
    engine = DetectorEngine(active)
    out = []
    for event in trace.events:
        state.observe(event)
        out.extend(engine.on_event(event, state))
    out.extend(engine.finish(state))
    return out
