"""Permanent semantic parity harness for batch, event replay, and live frames."""
from dataclasses import asdict
import json
import unittest

from glassport import detectors
from glassport.adapters.mcp_session import MCPTraceBuilder, from_mcp_session
from glassport.incremental import DetectorEngine, FabricatedCallsDetector, StreamingDetector
from glassport.session import SessionState
from tests.test_detectors import L, call, handshake


def semantic_findings(events, annotations):
    """Normalize generated annotation/event IDs and incidental finding order only."""
    ids = {event.id: i for i, event in enumerate(events)}
    found = []
    for annotation in annotations:
        value = asdict(annotation)
        value.pop("id")
        value["event_id"] = ids.get(annotation.event_id, annotation.event_id)
        found.append(json.dumps(value, sort_keys=True))
    return sorted(found)


class TestFabricatedParity(unittest.TestCase):
    def assert_parity(self, lines):
        batch = from_mcp_session(lines)
        expected = detectors.fabricated_calls(batch)
        state, engine = SessionState.from_trace(batch), DetectorEngine()
        observed = []
        for event in batch.events:
            state.observe(event)
            observed.extend(engine.on_event(event, state))
        observed.extend(engine.finish(state))
        self.assertEqual(semantic_findings(batch.events, expected),
                         semantic_findings(batch.events, observed))
        builder, live = MCPTraceBuilder(retain_events=False), DetectorEngine()
        events, findings = [], []
        for line in lines:
            event = builder.ingest_frame(json.loads(line))
            if event:
                events.append(event)
                findings.extend(live.on_event(event, builder.state))
        findings.extend(live.finish(builder.state))
        self.assertEqual(semantic_findings(batch.events, expected),
                         semantic_findings(events, findings))
        return events, findings

    def test_unknown_empty_known_and_in_flight(self):
        for prefix in (handshake()[:3], handshake()[:4], handshake(tools=[]), handshake()):
            with self.subTest(prefix=len(prefix)):
                self.assert_parity(prefix + [call(6, 3, "web_search", {}), call(7, 4, "other", {})])

    def test_later_declaration_cannot_reinterpret_prior_call(self):
        self.assert_parity(handshake(tools=[]) + [call(6, 3, "new", {}),
            L(7, "c2s", {"id": 4, "method": "tools/list"}),
            L(8, "s2c", {"id": 4, "result": {"tools": [{"name": "new"}]}}),
            call(9, 5, "new", {})])

    def test_annotation_available_before_reply_or_finish(self):
        builder, engine = MCPTraceBuilder(retain_events=False), DetectorEngine()
        for line in handshake(tools=[]):
            event = builder.feed(json.loads(line))
            self.assertEqual(engine.on_event(event, builder.state), [])
        event = builder.feed(json.loads(call(6, 3, "foo", {})))
        found = engine.on_event(event, builder.state)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].event_id, event.id)
        self.assertEqual(found[0].metadata, {"seq": 6, "tool": "foo",
                         "no_declaration_seen": False, "declaration_seq": 5})
        self.assertEqual(engine.finish(builder.state), [])
        self.assertEqual(builder.events, [])

    def test_complete_metadata_participates_in_parity_oracle(self):
        events, found = self.assert_parity(handshake(tools=[]) + [call(6, 3, "foo", {})])
        before = semantic_findings(events, found)
        found[0].metadata["tool"] = "different"
        self.assertNotEqual(before, semantic_findings(events, found))

    def test_pagination_and_surface_shrink(self):
        self.assert_parity(handshake() + [
            L(6, "c2s", {"id": 3, "method": "tools/list"}),
            L(7, "s2c", {"id": 3, "result": {"tools": [], "nextCursor": "next"}}),
            call(8, 4, "web_search", {}),
            L(9, "c2s", {"id": 5, "method": "tools/list", "params": {"cursor": "next"}}),
            L(10, "s2c", {"id": 5, "result": {"tools": []}}), call(11, 6, "web_search", {})])


class TestDetectorLifecycle(unittest.TestCase):
    def test_failure_does_not_blind_surviving_detector_or_leak_exception_text(self):
        class Broken(StreamingDetector):
            name = "broken"
            def on_event(self, event, state):
                raise ValueError("secret-payload")
        trace = from_mcp_session(handshake(tools=[]) + [call(6, 3, "foo", {})])
        state = SessionState.from_trace(trace)
        for event in trace.events:
            state.observe(event)
        engine = DetectorEngine([Broken(), FabricatedCallsDetector()])
        found = engine.on_event(trace.events[-1], state)
        self.assertEqual([a.subcategory for a in found], ["detector_error", "fabricated_tool_call"])
        self.assertNotIn("secret-payload", json.dumps([asdict(a) for a in found]))

    def test_finish_once_and_session_identity(self):
        class Finish(StreamingDetector):
            def finish(self, state):
                raise RuntimeError("failed")
        state, engine = SessionState(), DetectorEngine([Finish()])
        self.assertEqual(engine.finish(state)[0].metadata["phase"], "finish")
        self.assertEqual(engine.finish(state), [])
        with self.assertRaises(ValueError):
            engine.on_event(None, state)
        with self.assertRaises(ValueError):
            engine.finish(SessionState())

    def test_empty_registry_and_default_hooks(self):
        state = SessionState()
        event = from_mcp_session([call(1, 1, "foo", {})]).events[0]
        for active in ([], [StreamingDetector()]):
            engine = DetectorEngine(active)
            self.assertEqual(engine.on_event(event, state), [])
            self.assertEqual(engine.finish(state), [])

    def test_exception_diagnostic_never_constructs_or_stringifies_exception(self):
        class HostileError(Exception):
            def __init__(self, required):
                self.required = required
            def __str__(self):
                raise RuntimeError("must not stringify")
        class Broken(StreamingDetector):
            def on_event(self, event, state):
                raise HostileError("private")
        event = from_mcp_session([call(1, 1, "foo", {})]).events[0]
        found = DetectorEngine([Broken()]).on_event(event, SessionState())
        self.assertEqual(found[0].metadata["error_type"], "HostileError")
