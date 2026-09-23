"""Permanent semantic parity harness for batch, event replay, and live frames."""
from dataclasses import asdict
import json
import unittest
from pathlib import Path

from glassport import detectors
from glassport.adapters.mcp_session import MCPTraceBuilder, from_mcp_session, _iter_entries
from glassport.incremental import DetectorEngine, FabricatedCallsDetector, ContextDetector, DataExfiltrationDetector, StreamingDetector
from glassport.session import SessionLimits, SessionState
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
    def assert_parity(self, lines, batch_fn=detectors.fabricated_calls, active_type=FabricatedCallsDetector):
        batch = from_mcp_session(lines)
        expected = batch_fn(batch)
        state = SessionState.from_trace(batch)
        engine = DetectorEngine([active_type()]) if active_type else DetectorEngine()
        observed = []
        for event in batch.events:
            state.observe(event)
            observed.extend(engine.on_event(event, state))
        observed.extend(engine.finish(state))
        self.assertEqual(semantic_findings(batch.events, expected),
                         semantic_findings(batch.events, observed))
        builder = MCPTraceBuilder(retain_events=False)
        live = DetectorEngine([active_type()]) if active_type else DetectorEngine()
        events, findings = [], []
        for entry in _iter_entries(lines):
            event = builder.ingest_frame(entry)
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


class TestContextParity(unittest.TestCase):
    def check(self, lines):
        return TestFabricatedParity.assert_parity(
            self, lines, detectors.context_violations, ContextDetector)

    def test_future_schema_cannot_reject_earlier_arguments(self):
        h = handshake()
        _, found = self.check(h[:4] + [call(6, 3, "web_search", {})] + [h[4]])
        self.assertNotIn("schema_violation", [a.subcategory for a in found])

    def test_future_capabilities_do_not_judge_earlier_request(self):
        _, found = self.check([L(0, "s2c", {"id": 42, "method": "sampling/createMessage"})] + handshake())
        self.assertNotIn("capability_violation", [a.subcategory for a in found])

    def test_current_schema_replaces_old_schema(self):
        lines = handshake(tools=[{"name": "foo", "inputSchema": {"required": ["old"]}}]) + [
            call(6, 3, "foo", {"old": 1}),
            L(7, "c2s", {"id": 4, "method": "tools/list"}),
            L(8, "s2c", {"id": 4, "result": {"tools": [{"name": "foo", "inputSchema": {"required": ["new"]}}]}}),
            call(9, 5, "foo", {"old": 1}), call(10, 6, "foo", {"new": 1})]
        _, found = self.check(lines)
        self.assertEqual([(a.subcategory, a.metadata["seq"]) for a in found], [("schema_violation", 9)])

    def test_server_notification_cannot_initialize_client(self):
        _, found = self.check([L(1, "s2c", {"method": "notifications/initialized"}), call(2, 2, "foo", {})])
        self.assertIn("premature_call", [a.subcategory for a in found])

    def test_context_categories_and_surface_changes(self):
        _, found = self.check(handshake() + [call(6, 3, "web_search", {}),
            L(7, "s2c", {"id": 4, "method": "sampling/createMessage"}),
            L(8, "s2c", {"id": 5, "method": "secrets/dump"}),
            L(9, "s2c", {"id": 999, "result": {}}),
            L(10, "c2s", {"id": 6, "method": "tools/list"}),
            L(11, "s2c", {"id": 6, "result": {"tools": []}})])
        self.assertEqual({a.subcategory for a in found}, {"schema_violation", "capability_violation",
                         "unknown_server_request", "orphaned_response", "surface_change"})

    def test_faulty_schema_does_not_blind_next_event(self):
        _, found = self.check(handshake(tools=[{"name": "foo", "inputSchema": {"required": 7}}]) +
                              [call(6, 3, "foo", {}), L(7, "s2c", {"id": 99, "result": {}})])
        self.assertEqual([a.subcategory for a in found], ["detector_error", "orphaned_response"])


class TestExfiltrationParity(unittest.TestCase):
    def check(self, lines):
        return TestFabricatedParity.assert_parity(
            self, lines, detectors.data_exfiltration, DataExfiltrationDetector)

    def test_argument_and_result_credentials_remain_redacted(self):
        secret = "sk-ant-api03-" + "A" * 90
        _, found = self.check(handshake() + [call(6, 3, "web_search", {"key": secret}),
            L(7, "s2c", {"id": 3, "result": {"content": [{"type": "text", "text": secret}]}})])
        self.assertIn("pii_anthropic_key", [a.subcategory for a in found])
        self.assertIn("pii_in_result_anthropic_key", [a.subcategory for a in found])
        self.assertNotIn(secret, json.dumps([asdict(a) for a in found]))

    def test_future_host_declaration_cannot_erase_egress(self):
        h = handshake(tools=[{"name": "foo", "description": "https://api.example.test"}])
        _, found = self.check(h[:4] + [call(6, 3, "foo", {"url": "https://api.example.test/x"})]
                             + [h[4], call(7, 4, "foo", {"url": "https://api.example.test/x"})])
        self.assertEqual([(a.subcategory, a.metadata["seq"]) for a in found], [("unexpected_egress_host", 6)])

    def test_removed_host_declaration_applies_to_later_calls(self):
        h = handshake(tools=[{"name": "foo", "description": "https://api.example.test"}])
        _, found = self.check(h + [
            L(6, "c2s", {"id": 3, "method": "tools/list"}),
            L(7, "s2c", {"id": 3, "result": {"tools": [{"name": "foo"}]}}),
            call(8, 4, "foo", {"url": "https://api.example.test/x"})])
        self.assertEqual([a.metadata["seq"] for a in found], [8])

    def test_trusted_cloud_cannot_suppress_sensitive_egress(self):
        _, found = self.check(handshake() + [call(6, 3, "web_search", {
            "url": "https://bucket.s3.amazonaws.com/x", "key": "sk-ant-api03-" + "A" * 90})])
        egress = next(a for a in found if a.subcategory == "unexpected_egress_host")
        self.assertEqual(egress.severity, 2)
        self.assertTrue(egress.metadata["has_pii"])


class TestFullSemanticParity(unittest.TestCase):
    def test_every_registered_detector_has_a_streaming_twin(self):
        # annotate() replays default_detectors() whenever DETECTORS is the
        # default, so a batch pass with no streaming twin would silently
        # never run — and batch/stream parity checks cannot catch that.
        from glassport.incremental import default_detectors
        self.assertEqual([d.__name__ for d in detectors.DETECTORS],
                         [d.name for d in default_detectors()])

    def test_all_builtin_detectors_and_raw_evidence(self):
        from tests.test_streaming import HOSTILE
        TestFabricatedParity.assert_parity(self, HOSTILE, detectors.annotate, None)

    def test_committed_wire_fixture(self):
        path = Path(__file__).resolve().parents[1] / "examples/20260609T183929Z_python3_538.jsonl"
        TestFabricatedParity.assert_parity(self, path.read_text().splitlines(), detectors.annotate, None)

    def test_gate_evidence_survives_full_replay(self):
        entry = json.loads(call(6, 3, "shadow", {}))
        entry["gate"] = {"action": "blocked", "tool": "shadow"}
        _, found = TestFabricatedParity.assert_parity(
            self, handshake() + [json.dumps(entry)], detectors.annotate, None)
        self.assertIn("gate_blocked", [a.subcategory for a in found])

    def test_limits_report_once_and_do_not_accumulate_findings(self):
        builder = MCPTraceBuilder(retain_events=False, limits=SessionLimits(max_pending=1))
        engine = DetectorEngine()
        limit_reasons = []
        for i in range(100):
            event = builder.feed(json.loads(call(i, i, "foo", {})))
            found = engine.on_event(event, builder.state)
            limit_reasons.extend(a.metadata["reason"] for a in found
                                 if a.subcategory == "analysis_limit")
        self.assertCountEqual(limit_reasons,
                              ["request_correlation", "request_correlation_saturated"])
        self.assertEqual(len(builder.pending), 1)
        self.assertEqual(builder.events, [])
        self.assertEqual(builder.snapshot().annotations, [])

    def test_declared_state_limit_notice_replays_identically(self):
        b = MCPTraceBuilder(limits=SessionLimits(max_tools=1))
        engine, found = DetectorEngine(), []
        for line in handshake(tools=[{"name": "one"}, {"name": "two"}]):
            event = b.feed(json.loads(line))
            found.extend(engine.on_event(event, b.state))
        trace = b.snapshot()
        self.assertEqual(semantic_findings(trace.events, found),
                         semantic_findings(trace.events, detectors.annotate(trace)))
        self.assertIn("analysis_limit", [a.subcategory for a in found])

    def test_identity_metadata_limit_notice_survives_event_and_wire_replay(self):
        for index, container, field in ((0, "params", "clientInfo"),
                                        (0, "params", "protocolVersion"),
                                        (1, "result", "protocolVersion")):
            with self.subTest(field=field, index=index):
                entries = [json.loads(line) for line in handshake(tools=[])]
                entries[index]["frame"][container][field] = "x" * 200
                limits = SessionLimits(max_state_bytes=100)
                retained = MCPTraceBuilder(limits=limits)
                bounded = MCPTraceBuilder(limits=limits, retain_events=False)
                live_engine, bounded_engine = DetectorEngine(), DetectorEngine()
                live, bounded_found, bounded_events = [], [], []
                for entry in entries:
                    event = retained.feed(entry)
                    live.extend(live_engine.on_event(event, retained.state))
                    event = bounded.feed(entry)
                    bounded_events.append(event)
                    bounded_found.extend(bounded_engine.on_event(event, bounded.state))
                trace = retained.snapshot()
                expected = semantic_findings(trace.events, live)
                self.assertEqual(expected, semantic_findings(trace.events, detectors.annotate(trace)))
                self.assertEqual(expected, semantic_findings(bounded_events, bounded_found))
                limits_found = [a for a in live if a.subcategory == "analysis_limit"]
                self.assertEqual(len(limits_found), 1)
                self.assertEqual(limits_found[0].metadata["reason"], "session_metadata")
                self.assertEqual(limits_found[0].event_id, trace.events[index].id)
