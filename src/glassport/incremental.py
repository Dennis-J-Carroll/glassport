"""Incremental detection over session facts. No transport or enforcement code."""
from __future__ import annotations

from collections.abc import Iterable

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


class DetectorEngine:
    """Fault-isolated detector lifecycle; findings are returned, never accumulated.

    The caller supplies the state *after* observing each event. A builder and
    an engine therefore share one state fold instead of updating declarations
    twice. An engine binds to one SessionState; use a new pair for a new session.
    """

    def __init__(self, active: Iterable[StreamingDetector] | None = None):
        self.active = tuple(active) if active is not None else (FabricatedCallsDetector(),)
        self._state: SessionState | None = None
        self._finished = False

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
        return self._run("on_event", state, event)

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
