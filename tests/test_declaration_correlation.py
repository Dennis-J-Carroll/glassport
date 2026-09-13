"""Hostile correlation cannot manufacture declaration or policy evidence."""
import json
import unittest
from types import SimpleNamespace

from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.detectors import annotate
from glassport.incremental import DetectorEngine
from glassport.interaction_trace import EventKind
from glassport.policy import Action, decide
from glassport.session import SessionLimits, SessionState
from tests.test_incremental_detectors import semantic_findings
from tests.test_streaming import canon_events


def req(rid, method="tools/list", **params):
    return "c2s", {"id": rid, "method": method, "params": params}


def reply(rid, tools, **extra):
    return "s2c", {"id": rid, "result": {"tools": [{"name": n} for n in tools], **extra}}


def call(rid, name="real", **arguments):
    return req(rid, "tools/call", name=name, arguments=arguments)


class TestDeclarationCorrelation(unittest.TestCase):
    def check(self, frames, *, limits=None, action=Action.WARN):
        frames = [("c2s", {"method": "notifications/initialized"})] + frames
        entries = [{"seq": i, "dir": direction, "frame": frame}
                   for i, (direction, frame) in enumerate(frames)]
        retained = MCPTraceBuilder(limits=limits)
        for entry in entries:
            retained.ingest_frame(entry)
        trace = retained.snapshot()
        batch = annotate(trace)
        expected = semantic_findings(trace.events, batch)
        for raw in (False, True):
            engine = DetectorEngine()
            live = MCPTraceBuilder(retain_events=False, limits=limits)
            state = SessionState.from_trace(trace)
            events, found = [], []
            for index, entry in enumerate(entries):
                if raw:
                    event = live.ingest_frame(json.loads(json.dumps(entry)))
                    current = live.state
                else:
                    event = trace.events[index]
                    state.observe(event)
                    current = state
                events.append(event)
                found.extend(engine.on_event(event, current))
            found.extend(engine.finish(current))
            self.assertEqual(expected, semantic_findings(events, found))
            if raw:
                self.assertEqual(canon_events(trace), canon_events(SimpleNamespace(
                    events=events, actors=[live.client, live.server])))
            self.assertEqual(current.surface, retained.state.surface)
            self.assertEqual(current.tool_defs, retained.state.tool_defs)
            def decisions(events, findings):
                return [(d.action, d.reason, sorted(
                    a.subcategory for a in findings if a.id in d.annotation_ids))
                    for event in events if event.kind == EventKind.TOOL_CALL
                    for d in [decide(event.id, findings, block_fabricated=True)]]
            self.assertEqual(decisions(trace.events, batch), decisions(events, found))
            self.assertEqual(live.events, [])
        last = next(e for e in reversed(trace.events) if e.kind == EventKind.TOOL_CALL)
        last_findings = [a for a in batch if a.event_id == last.id]
        self.assertEqual(decide(last.id, batch, block_fabricated=True).action, action)
        if action == Action.WARN:
            self.assertNotIn("fabricated_tool_call", [a.subcategory for a in last_findings])
            self.assertEqual(len([a for a in last_findings if a.severity == 1 and
                a.subcategory in {"declaration_unavailable", "call_before_declaration"}]), 1)
        return retained, trace, batch

    def test_tool_names_cannot_impersonate_protocol_methods(self):
        for name in ("<tools/list>", "<initialize>", "<ordinary>"):
            with self.subTest(name=name):
                b, trace, _ = self.check([call(1, name), reply(1, []), call(2)])
                response = trace.events[2]
                self.assertEqual(response.kind, EventKind.TOOL_RESULT)
                self.assertEqual(response.metadata["tool_name"], name)
                self.assertIsNone(b.state.server_capabilities)
                self.assertNotIn("capabilities", b.server.metadata)

    def test_rejected_duplicate_cannot_reuse_stale_list_request(self):
        self.check([req(1), req(1, cursor="x" * 20), reply(1, []), call(2)],
                   limits=SessionLimits(max_name_chars=12))

    def test_old_continuation_cannot_complete_new_chain_with_reused_cursor(self):
        self.check([req(1), reply(1, ["a1"], nextCursor="page2"),
            req(2, cursor="page2"), req(3), reply(3, ["b1"], nextCursor="page2"),
            reply(2, ["a2"]), call(4, "a1")])

    def test_evicted_refresh_cannot_preserve_stale_exclusion(self):
        self.check([req(1), reply(1, []), req(2), req(3, "ping"),
                    reply(2, ["real"]), call(4)], limits=SessionLimits(max_pending=1))

    def test_duplicate_valid_ids_do_not_establish_evidence(self):
        self.check([req(1), req(1), reply(1, []), call(2)])

    def test_duplicate_id_quarantine_survives_first_reply_and_immediate_reuse(self):
        self.check([req(1), req(1), reply(1, []), req(1), reply(1, []), call(2)])

    def test_evicted_id_reuse_cannot_attach_delayed_old_reply(self):
        self.check([req(1), req(2, "ping"), req(1), reply(1, []), call(3)],
                   limits=SessionLimits(max_pending=1))

    def test_quarantine_saturation_cannot_forget_ambiguous_ids(self):
        self.check([req(1), req(2, "ping"), req(3, "ping"), req(1),
                    reply(1, []), call(4)], limits=SessionLimits(max_pending=1))

    def test_fresh_id_recovers_while_ambiguous_id_remains_quarantined(self):
        self.check([req(1), req(1), reply(1, []), req(2), reply(2, ["real"]), call(3)],
                   limits=SessionLimits(max_pending=3), action=Action.ALLOW)

    def test_server_quarantine_saturation_does_not_disable_client_listing(self):
        self.check([("s2c", {"id": i, "method": "ping"}) for i in range(3)] +
                   [req(1), reply(1, ["real"]), call(2)],
                   limits=SessionLimits(max_pending=1), action=Action.ALLOW)

    def test_duplicate_continuations_are_ambiguous(self):
        self.check([req(1), reply(1, ["a"], nextCursor="next"),
            req(2, cursor="next"), req(3, cursor="next"), reply(2, []),
            reply(3, []), call(4)])

    def test_pending_malformed_and_failed_refreshes_warn(self):
        for suffix in ([req(2)], [req(2), ("s2c", {"id": 2, "result": {}})],
                       [req(2), ("s2c", {"id": 2, "error": {"code": -1}})]):
            with self.subTest(suffix=suffix):
                self.check([req(1), reply(1, [])] + suffix + [call(4)])

    def test_valid_declarations_pagination_and_schema_still_apply(self):
        self.check([req(1), reply(1, []), call(2)], action=Action.BLOCK)
        self.check([req(1), reply(1, ["real"]), call(2)], action=Action.ALLOW)
        b, _, _ = self.check([req(1), reply(1, ["a"], nextCursor="next"),
            req(2, cursor="next"), reply(2, ["real"]), call(3)], action=Action.ALLOW)
        self.assertEqual(b.state.surface, {"a", "real"})
        _, _, findings = self.check([req(1), ("s2c", {"id": 1, "result": {
            "tools": [{"name": "real", "inputSchema": {"required": ["q"]}}]}}),
            call(2), call(3, q=1)], action=Action.ALLOW)
        self.assertEqual([a.subcategory for a in findings], ["schema_violation"])

    def test_fresh_listing_restores_evidence_after_loss(self):
        self.check([req(1), reply(1, []), req(2), req(3, "ping"),
            reply(2, ["real"]), reply(3, []), req(4), reply(4, ["real"]), call(5)],
            limits=SessionLimits(max_pending=1), action=Action.ALLOW)

    def test_unrelated_evictions_and_opposite_direction_preserve_surface(self):
        self.check([req(1), reply(1, ["real"]), req(2, "ping"),
            req(3, "ping"), ("s2c", {"id": 3, "method": "tools/list"}),
            ("s2c", {"id": 4, "method": "ping"}), req(6, "ping"), call(5)],
            limits=SessionLimits(max_pending=1), action=Action.ALLOW)

    def test_superseded_root_reply_cannot_replace_new_surface(self):
        self.check([req(1), req(2), reply(2, ["real"]), reply(1, []), call(3)],
                   action=Action.ALLOW)

    def test_eviction_of_superseded_request_preserves_new_surface(self):
        self.check([req(1), req(2), reply(2, ["real"]), req(3, "ping"), req(4, "ping"), call(5)],
                   limits=SessionLimits(max_pending=2), action=Action.ALLOW)

    def test_tool_errors_with_angle_names_remain_tool_results(self):
        for name in ("<tools/list>", "<initialize>", "<ordinary>"):
            _, trace, _ = self.check([call(1, name),
                ("s2c", {"id": 1, "error": {"code": -1, "message": "denied"}}), call(2)])
            self.assertEqual(trace.events[2].kind, EventKind.TOOL_RESULT)

    def test_rejected_method_and_name_replacements_clear_old_associations(self):
        for replacement in (req(1, ""), req(1, "x" * 20), call(1, "x" * 20),
                            ("c2s", {"id": 1, "method": "tools/list", "params": []})):
            with self.subTest(replacement=replacement):
                self.check([req(1), replacement, reply(1, []), call(2)],
                           limits=SessionLimits(max_name_chars=12))

    def test_retention_and_generation_identity_are_bounded(self):
        b = MCPTraceBuilder(retain_events=False, limits=SessionLimits(max_pending=3))
        engine = DetectorEngine()
        for i in range(1000):
            event = b.ingest_frame({"seq": i, "dir": "c2s", "frame": req(i)[1]})
            engine.on_event(event, b.state)
        self.assertEqual(len(b.pending), 3)
        self.assertEqual(len(b._quarantined["c2s"]), 3)
        self.assertEqual(b._correlation_saturated, {"c2s"})
        self.assertEqual(b.events, [])
        self.assertEqual(b.snapshot().annotations, [])
        self.assertIsNone(b.state._pages)
        self.assertLessEqual(b._generation_counter.bit_length(), 128)
        b = MCPTraceBuilder(retain_events=False)
        b._generation_counter = (1 << 128) - 1
        b.ingest_frame({"dir": "c2s", "frame": req(1001)[1]})
        b.ingest_frame({"dir": "s2c", "frame": reply(1001, [])[1]})
        self.assertIsNone(b.state.surface)
        self.assertEqual(b._generation_counter, (1 << 128) - 1)


if __name__ == "__main__":
    unittest.main()
