"""Issue #76: unknown is not an explicitly empty observed declaration."""
import json
import tempfile
import unittest

from glassport import detectors, report, sarif, watch
from glassport.adapters.mcp_session import from_mcp_session
from tests.test_cli import run_main, write_session
from tests.test_detectors import L, handshake, call


class TestDeclaredSurface(unittest.TestCase):
    def check_surface(self, lines, surface, fabricated_seqs):
        trace = from_mcp_session(lines)
        self.assertEqual(trace.declared_surface(), surface)
        seq_of = {e.id: e.metadata.get("seq") for e in trace.events}
        self.assertEqual([seq_of[eid] for eid, _ in trace.fabricated_tool_calls()],
                         fabricated_seqs)
        anns = detectors.fabricated_calls(trace)
        self.assertEqual([a.metadata["seq"] for a in anns], fabricated_seqs)
        self.assertTrue(all(a.severity == 3 for a in anns))
        self.assertTrue(all(a.metadata["no_declaration_seen"] is False for a in anns))
        return trace

    def test_unknown_keeps_context_finding_without_high_fabrication(self):
        trace = self.check_surface(handshake()[:3] + [call(6, 3, "foo", {})], None, [])
        anns = detectors.annotate(trace)
        self.assertEqual([(a.subcategory, a.severity) for a in anns],
                         [("call_before_declaration", 1)])

    def test_explicit_empty_is_known_and_excludes_every_call(self):
        self.check_surface(handshake(tools=[]) + [call(6, 3, "foo", {})], set(), [6])

    def test_known_surface_only_flags_excluded_name(self):
        self.check_surface(handshake(tools=[{"name": "foo"}]) +
                           [call(6, 3, "foo", {}), call(7, 4, "bar", {})], {"foo"}, [7])

    def test_in_flight_list_is_unknown_even_after_later_empty_response(self):
        h = handshake(tools=[])
        lines = h[:4] + [call(6, 3, "foo", {})]
        self.check_surface(lines, None, [])
        self.check_surface(lines + [h[4]], set(), [])

    def test_later_declaration_does_not_erase_earlier_divergence(self):
        lines = handshake(tools=[]) + [call(6, 3, "foo", {}),
            L(7, "c2s", {"id": 4, "method": "tools/list"}),
            L(8, "s2c", {"id": 4, "result": {"tools": [{"name": "foo"}]}}),
            call(9, 5, "foo", {})]
        self.check_surface(lines, {"foo"}, [6])

    def test_latest_surface_can_remove_tools(self):
        lines = handshake(tools=[{"name": "foo"}]) + [call(6, 3, "foo", {}),
            L(7, "c2s", {"id": 4, "method": "tools/list"}),
            L(8, "s2c", {"id": 4, "result": {"tools": []}}), call(9, 5, "foo", {})]
        self.check_surface(lines, set(), [9])

    def test_unusable_list_response_remains_unknown(self):
        for result in ({}, {"tools": None}, {"tools": {}}, {"tools": [None]},
                       {"tools": [{"name": []}]}, {"tools": [{"description": "x"}]}):
            with self.subTest(result=result):
                self.check_surface(handshake()[:4] +
                    [L(5, "s2c", {"id": 2, "result": result}), call(6, 3, "foo", {})],
                    None, [])

    def test_error_or_uncorrelated_tools_payload_is_not_declaration(self):
        for frame in ({"id": 2, "error": {"code": -1}, "result": {"tools": []}},
                      {"id": 999, "result": {"tools": []}}):
            with self.subTest(frame=frame):
                self.check_surface(handshake()[:4] + [L(5, "s2c", frame),
                                                       call(6, 3, "foo", {})], None, [])

    def test_unknown_and_empty_remain_distinct_in_outputs(self):
        for lines, known, label in ((handshake()[:3], False, "unknown"),
                                    (handshake(tools=[]), True, "explicitly empty")):
            with self.subTest(known=known), tempfile.TemporaryDirectory() as tmp:
                path = write_session(tmp, lines)
                _, output = run_main(["summarize", "--json", str(path)])
                self.assertEqual(json.loads(output)["declaration_known"], known)
                _, output = run_main(["summarize", str(path)])
                self.assertIn(label, output)
                trace = from_mcp_session(lines)
                self.assertIn(label, report.render_html(trace))
                self.assertEqual(watch.fingerprint(trace)["declaration_known"], known)

    def test_unknown_cannot_become_high_in_sarif_or_html(self):
        trace = from_mcp_session(handshake()[:3] + [call(6, 3, "foo", {})])
        detectors.annotate(trace)
        self.assertNotIn('class="ann" data-sev="3"', report.render_html(trace))
        results = json.loads(sarif.render_session_sarif(trace))["runs"][0]["results"]
        self.assertNotIn("error", [r["level"] for r in results])

    def test_drift_can_prove_removal_only_from_known_surface(self):
        baseline = watch.new_baseline()
        watch.merge(baseline, watch.fingerprint(from_mcp_session(handshake())))
        unknown = watch.fingerprint(from_mcp_session(handshake()[:3]))
        empty = watch.fingerprint(from_mcp_session(handshake(tools=[])))
        self.assertNotIn("removed_declared_tool", [d.kind for d in watch.drift(baseline, unknown)])
        self.assertIn("removed_declared_tool", [d.kind for d in watch.drift(baseline, empty)])
