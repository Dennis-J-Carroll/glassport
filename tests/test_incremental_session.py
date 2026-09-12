"""Incremental evidence/state equivalence, pagination, and bounded retention."""
from copy import deepcopy
import json
import unittest

from glassport.adapters.mcp_session import MCPTraceBuilder, from_mcp_session
from glassport.session import SessionLimits, SessionState
from tests.test_detectors import L, call, handshake, result
from tests.test_streaming import canon_events, canon_actors


class TestIncrementalSession(unittest.TestCase):
    def test_builder_returns_event_and_matches_batch_after_each_frame(self):
        builder = MCPTraceBuilder()
        lines = handshake() + [call(6, 3, "web_search", {"query": "x"}), result(7, 3)]
        for i, line in enumerate(lines):
            event = builder.ingest_frame(json.loads(line))
            trace = builder.snapshot()
            self.assertIs(event, trace.events[-1])
            batch = from_mcp_session(lines[:i + 1])
            self.assertEqual(canon_events(trace), canon_events(batch))
            self.assertEqual(canon_actors(trace), canon_actors(batch))
            self.assertEqual(trace.declared_surface(), builder.state.surface)

    def test_gate_evidence_available_immediately_and_never_rewritten(self):
        builder = MCPTraceBuilder()
        entry = json.loads(call(6, 3, "foo", {}))
        entry["gate"] = {"action": "blocked", "tool": "foo"}
        event = builder.ingest_frame(entry)
        self.assertEqual(event.metadata["gate"], entry["gate"])
        before = deepcopy(event)
        for line in handshake():
            builder.ingest_frame(json.loads(line))
        builder.snapshot()
        self.assertEqual(event, before)

    def test_state_isolated_from_mutable_evidence(self):
        builder = MCPTraceBuilder()
        for line in handshake():
            event = builder.ingest_frame(json.loads(line))
        event.parts[0].content["result"]["tools"][0]["name"] = "changed"
        self.assertEqual(builder.state.surface, {"web_search"})
        self.assertEqual(builder.state.tool_defs["web_search"]["name"], "web_search")

    def test_no_history_mode_retains_only_bounded_correlation(self):
        builder = MCPTraceBuilder(retain_events=False, limits=SessionLimits(max_pending=8))
        for line in handshake():
            builder.ingest_frame(json.loads(line))
        for i in range(1000):
            builder.ingest_frame(json.loads(call(i + 10, i + 10, "web_search", {})))
        self.assertEqual(builder.events, [])
        self.assertEqual(len(builder.pending), 8)
        self.assertEqual(builder.correlation_evictions, 992)
        self.assertEqual(builder.snapshot().declared_surface(), {"web_search"})
        self.assertEqual(builder.snapshot().annotations, [])
        self.assertEqual(builder.state.tool_defs.keys(), {"web_search"})

    def test_evicted_response_is_orphaned_and_directions_stay_separate(self):
        b = MCPTraceBuilder(limits=SessionLimits(max_pending=1))
        b.feed(json.loads(call(1, 1, "one", {})))
        b.feed(json.loads(call(2, 2, "two", {})))
        b.feed(json.loads(L(3, "s2c", {"id": 2, "method": "ping"})))
        self.assertTrue(b.feed(json.loads(result(4, 1))).metadata["orphaned"])
        self.assertEqual(b.feed(json.loads(result(5, 2))).metadata["tool_name"], "two")
        self.assertEqual(len(b.pending_s2c), 1)

    def test_hostile_ids_do_not_expand_pending_state(self):
        for rid in ([], {}, True, "x" * 2048, 2 ** 256):
            with self.subTest(rid=type(rid).__name__):
                b = MCPTraceBuilder()
                event = b.feed({"dir": "c2s", "frame": {"id": rid, "method": "ping"}})
                self.assertTrue(event.metadata["correlation_limited"])
                self.assertEqual(len(b.pending), 0)

    def test_oversized_declaration_becomes_unknown_without_losing_evidence(self):
        b = MCPTraceBuilder(limits=SessionLimits(max_tools=1))
        for line in handshake(tools=[{"name": "one"}, {"name": "two"}]):
            event = b.feed(json.loads(line))
        self.assertIsNone(b.state.surface)
        self.assertEqual(b.state.tool_defs, {})
        self.assertIn("tool_declaration", b.state.limit_reasons)
        self.assertEqual(len(event.parts[0].content["result"]["tools"]), 2)
        self.assertIsNone(b.snapshot().declared_surface())

    def test_schema_budget_bounds_retained_state(self):
        b = MCPTraceBuilder(limits=SessionLimits(max_state_bytes=100))
        for line in handshake(tools=[{"name": "one", "inputSchema": {"description": "x" * 1000}}]):
            b.feed(json.loads(line))
        self.assertIsNone(b.state.surface)
        self.assertEqual(b.state.tool_defs, {})

    def test_pagination_only_establishes_surface_after_complete_chain(self):
        lines = handshake()[:4] + [L(5, "s2c", {"id": 2, "result": {
            "tools": [{"name": "one"}], "nextCursor": "page2"}}),
            call(6, 3, "two", {}),
            L(7, "c2s", {"id": 4, "method": "tools/list", "params": {"cursor": "page2"}}),
            L(8, "s2c", {"id": 4, "result": {"tools": [{"name": "two"}]}}),
            call(9, 5, "one", {}), call(10, 6, "absent", {})]
        b = MCPTraceBuilder()
        for i, line in enumerate(lines):
            b.feed(json.loads(line))
            if i < 7:
                self.assertIsNone(b.state.surface)
        self.assertEqual(b.state.surface, {"one", "two"})
        self.assertEqual([n for _, n in b.snapshot().fabricated_tool_calls()], ["absent"])

    def test_unmatched_pagination_cursor_cannot_exclude_tools(self):
        lines = handshake()[:3] + [
            L(4, "c2s", {"id": 2, "method": "tools/list", "params": {"cursor": "lost"}}),
            L(5, "s2c", {"id": 2, "result": {"tools": []}})]
        self.assertIsNone(from_mcp_session(lines).declared_surface())

    def test_capabilities_and_initialization_follow_event_order(self):
        b = MCPTraceBuilder()
        self.assertIsNone(b.state.client_capabilities)
        lines = handshake(client_caps={"sampling": {}})
        b.feed(json.loads(lines[0]))
        self.assertEqual(b.state.client_capabilities, {"sampling": {}})
        self.assertFalse(b.state.initialized)
        b.feed(json.loads(lines[1]))
        self.assertEqual(b.state.server_capabilities, {"tools": {}})
        b.feed(json.loads(lines[2]))
        self.assertTrue(b.state.initialized)
        self.assertFalse(b.state.tools_list_requested)
        b.feed(json.loads(lines[3]))
        self.assertTrue(b.state.tools_list_requested)

    def test_limits_validate_and_raw_entries_remain_events(self):
        for value in (0, -1, True):
            with self.assertRaises(ValueError):
                SessionLimits(max_pending=value)
        b = MCPTraceBuilder(retain_events=False)
        self.assertIsNone(b.ingest_frame({"frame": None}))
        self.assertEqual(b.ingest_frame({"raw": "bad wire"}).parts[0].content, "bad wire")
        with self.assertRaises(ValueError):
            b.ingest_frame([])
