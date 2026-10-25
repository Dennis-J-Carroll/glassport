"""Incremental detection over session facts. No transport or enforcement code.

PLAY-BY-PLAY
------------
`detectors.py` can analyze a finished session in one pass. This file runs
the same checks one event at a time, while the session is still live, so
a finding can exist before the log is complete.

Two things make that safe:

1. Detectors never look ahead. `on_event()` sees the current event and
the state after observing it, nothing more. `finish()` is the only place
allowed to use end-of-session knowledge.
2. Detectors do not keep their own history. Anything a check needs to
remember lives in `SessionState`, which is folded once per event. That
is why a streaming engine and a batch replay cannot disagree: they
observe the same facts in the same order through the same object.

The lifecycle, in order:

1. `StreamingDetector` is the contract. Read state, return findings.
   Do not mutate events, retain unbounded history, or touch traffic.
2. The five concrete detectors below are the standard set, and
   `default_detectors()` returns fresh instances -- one set per session,
   never reused.
3. `DetectorEngine` runs them with a fault boundary: one detector that
   raises becomes a `detector_error` finding instead of taking the
   session, or the other detectors' findings, down with it.
4. `replay()` walks a finished trace through the identical path.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not forward or block anything, and it does not re-derive
protocol facts that `SessionState` already folded. Retrospective
analysis that needs the whole log belongs in `detectors.py`.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict

from glassport import detectors
from glassport.finding_ids import assign_stable_ids
from glassport.interaction_trace import Annotation, Event, EventKind, InteractionTrace, _new_id
from glassport.session import SessionState


class StreamingDetector:
    """One instance per session. Construction starts it; finish closes it.

    Implementations read evidence/state and return annotations. They must not
    mutate events, modify session facts, retain unbounded history, or forward
    or block traffic. Retrospective analysis remains outside this interface.
    """
    # PLAY: There is no reset() on purpose. A detector that can be reset is
    # a detector that can leak state from one session into the next; the
    # contract is to build a new instance instead.
    name = "streaming_detector"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        return []

    def finish(self, state: SessionState) -> list[Annotation]:
        return []


class FabricatedCallsDetector(StreamingDetector):
    name = "fabricated_calls"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        # PLAY: Three facts must hold before this can fire: it is a tool
        # call, a declaration is known (not None), and the name is absent
        # from it. no_declaration_seen=False in the finding is that middle
        # condition, spelled out for the policy layer, which refuses to
        # block on anything weaker.
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
        # PLAY: The general-purpose detector: several unrelated checks
        # that all need event-time state. Each one appends findings to a
        # single list and none of them short-circuits the others, so one
        # event can produce a surface change, a premature call, and a
        # schema violation at once.
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
        # a quarantine replacement re-answers an id the logged original
        # already answered; it is the delivered copy, not an orphan
        gate_mark = md.get("gate")
        if md.get("orphaned") and not (isinstance(gate_mark, dict) and gate_mark.get(
                "action") == "quarantine_replacement"):
            out.append(detectors._ann(
                event, detectors.AnnotationKind.ANOMALY, "orphaned_response",
                f"response id={md.get('jsonrpc_id')} matched no request", severity=1))
        return out


class GateRecordsDetector(StreamingDetector):
    name = "gate_actions"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        return detectors._gate_actions_for_event(event)


class SemanticTaintDetector(StreamingDetector):
    name = "semantic_taint"

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        return detectors._taint_for_event(event)


class DataExfiltrationDetector(StreamingDetector):
    name = "data_exfiltration"

    def __init__(self, pii_patterns=None):
        """`pii_patterns` pins this detector to a frozen pattern set for the
        whole session (see detectors.snapshot_pii_patterns). None — the
        default — keeps reading the live process-global registry per scan."""
        # PLAY: The declared-host set is derived from tool descriptions
        # and server_info, which arrive early and rarely change. Rebuilding
        # it per event would re-scan every schema on every frame, so the
        # detector keeps a cache keyed on object identity below.
        self._tool_defs = self._server_info = None
        self._declared_hosts: set[str] = set()
        self._pii_patterns = tuple(pii_patterns) if pii_patterns is not None else None

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
        return detectors._exfiltration_for_event(event, self._declared_hosts,
                                                 self._pii_patterns)


def default_detectors(pii_patterns=None) -> tuple[StreamingDetector, ...]:
    """The standard streaming detector set, optionally pinned to a frozen
    PII pattern snapshot. One fresh instance set per session."""
    return (FabricatedCallsDetector(), ContextDetector(), GateRecordsDetector(),
            SemanticTaintDetector(), DataExfiltrationDetector(pii_patterns))


class DetectorEngine:
    """Fault-isolated detector lifecycle; findings are returned, never accumulated.

    The caller supplies the state *after* observing each event. A builder and
    an engine therefore share one state fold instead of updating declarations
    twice. An engine binds to one SessionState; use a new pair for a new session.
    """

    def __init__(self, active: Iterable[StreamingDetector] | None = None):
        # PLAY: Converted to a tuple once so the set cannot be mutated
        # mid-session -- a detector list that grows while running would
        # make a session's findings depend on when they were read.
        self.active = tuple(active) if active is not None else default_detectors()
        self._state: SessionState | None = None
        self._finished = False
        self._reported_limits: set[str] = set()

    def _bind(self, state: SessionState):
        # PLAY: Identity check, not equality. An engine is allowed exactly
        # one state object for its life; handing it a second session is a
        # bug worth raising rather than a case worth merging.
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
                # PLAY: This is also why the except below can be trusted.
                # A half-built list never reaches `out`, so a crash leaves
                # one detector_error finding instead of a plausible-looking
                # subset of a failed check.
                found = list(detector.on_event(event, state) if event is not None
                             else detector.finish(state))
                assign_stable_ids(found, detector.name)
                out.extend(found)
            except Exception as exc:
                # Exception messages can contain secrets from hostile payloads.
                # Keep only the type in streaming diagnostics.
                # PLAY: type(exc).__name__ is a class name chosen by
                # glassport, not a string built by whoever sent the frame.
                # Logging str(exc) here would be the one place a credential
                # could reach a log through an error path.
                ann = Annotation(
                    id=_new_id("ann"), event_id="", kind=detectors.AnnotationKind.ANOMALY,
                    subcategory="detector_error", severity=2, annotator=detectors.ANNOTATOR,
                    explanation=f"detector {detector.name!r} raised {type(exc).__name__} during {hook}",
                    metadata={"detector": detector.name, "error_type": type(exc).__name__, "phase": hook},
                )
                if event is not None:
                    ann.event_id = event.id
                    ann.metadata["seq"] = event.metadata.get("seq")
                assign_stable_ids([ann], detector.name)
                out.append(ann)
        return out

    def on_event(self, event: Event, state: SessionState) -> list[Annotation]:
        if self._finished:
            raise ValueError("detector engine is finished")
        self._bind(state)
        found = self._run("on_event", state, event)
        reasons = state.limit_reasons | ({"request_correlation"}
                  if event.metadata.get("correlation_limited") else set())
        limit_anns = []
        # PLAY: Once per session, not once per frame. `_reported_limits`
        # turns "the state fold hit its cap" into a single finding at the
        # moment it first became true, which is new information; repeating
        # it on every later event would bury everything else.
        for reason in sorted(reasons - self._reported_limits):
            limit_ann = detectors._ann(
                event, detectors.AnnotationKind.ANOMALY, "analysis_limit",
                f"session state limit reached ({reason}); analysis may be incomplete",
                severity=1, reason=reason, limits=asdict(state.limits))
            limit_anns.append(limit_ann)
            self._reported_limits.add(reason)
        assign_stable_ids(limit_anns, "session_limits")
        found.extend(limit_anns)
        return found

    def finish(self, state: SessionState) -> list[Annotation]:
        self._bind(state)
        if self._finished:
            return []
        self._finished = True
        return self._run("finish", state)


def replay(trace: InteractionTrace, active: Iterable[StreamingDetector] | None = None) -> list[Annotation]:
    """Batch collection of incremental findings, using the same event-time facts."""
    # PLAY: Same engine, same fold, same order as the live path. That is
    # the point of the function: a replayed session and a watched session
    # produce the same findings because there is only one implementation.
    state = SessionState.from_trace(trace)
    engine = DetectorEngine(active)
    out = []
    for event in trace.events:
        state.observe(event)
        out.extend(engine.on_event(event, state))
    out.extend(engine.finish(state))
    return out
