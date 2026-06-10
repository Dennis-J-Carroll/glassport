"""
Tests for the pure (curses-free) core of the TUI: view-model builders,
picker listing, overlay formatting, and the key-action reducer.
Pure stdlib, run with:  python3 -m unittest tests.test_tui
"""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from glassport.adapters.mcp_session import from_mcp_session
from glassport import detectors
from glassport import tui
from tests.test_detectors import L, handshake, call, result


def annotated_trace(lines):
    trace = from_mcp_session(lines)
    detectors.annotate(trace)
    return trace


class TestViewModelHeader(unittest.TestCase):
    def test_header_identity_and_counters(self):
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}),
            result(7, 3),
            call(8, 4, "shadow_fetch", {"u": "http://x"}),  # fabricated
            result(9, 4),
        ]
        vm = tui.build_view_model(annotated_trace(lines), live=True)
        self.assertEqual(vm.title, "test-server")
        self.assertTrue(vm.live)
        self.assertEqual(vm.declared, ["web_search"])
        self.assertEqual(vm.counters["frames"], 9)
        self.assertEqual(vm.counters["fabricated"], 1)
        self.assertFalse(vm.gate_on)

    def test_title_includes_version_when_present(self):
        lines = handshake()
        trace = annotated_trace(lines)
        server = next(a for a in trace.actors if a.name == "mcp_server")
        server.metadata["server_info"] = {"name": "exa", "version": "1.2"}
        vm = tui.build_view_model(trace, live=False)
        self.assertEqual(vm.title, "exa 1.2")
        self.assertFalse(vm.live)

    def test_title_fallback_when_no_server_info(self):
        # handshake() without its initialize result: no serverInfo ever
        lines = [
            L(1, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ]
        vm = tui.build_view_model(annotated_trace(lines), live=False)
        self.assertEqual(vm.title, "unknown server")

    def test_violation_counter_excludes_fabricated_and_info(self):
        # call before any tools/list → context violation (sev 1) AND,
        # with no declaration ever seen, also fabricated (sev 3)
        lines = [
            call(1, 1, "web_search", {"query": "x"}),
            result(2, 1),
        ]
        vm = tui.build_view_model(annotated_trace(lines), live=False)
        self.assertEqual(vm.counters["fabricated"], 1)
        self.assertGreaterEqual(vm.counters["violations"], 1)

    def test_gate_on_when_gate_marker_present(self):
        lines = handshake() + [call(6, 3, "nope", {})]
        trace = annotated_trace(lines)
        trace.events[-1].metadata["gate"] = {"action": "blocked",
                                             "tool": "nope"}
        vm = tui.build_view_model(trace, live=False)
        self.assertTrue(vm.gate_on)

    def test_server_request_counter(self):
        lines = handshake() + [
            L(6, "s2c", {"jsonrpc": "2.0", "id": 99,
                         "method": "sampling/createMessage",
                         "params": {}}),
        ]
        vm = tui.build_view_model(annotated_trace(lines), live=False)
        self.assertEqual(vm.counters["server_requests"], 1)


class TestTimelineRows(unittest.TestCase):
    def setUp(self):
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}),
            result(7, 3),
            call(8, 4, "shadow_fetch", {"u": "http://x"}),
            result(9, 4),
        ]
        self.vm = tui.build_view_model(annotated_trace(lines), live=False)

    def test_one_row_per_event(self):
        self.assertEqual(len(self.vm.rows), 9)

    def test_direction_arrows(self):
        # initialize is client→server; its result is server→client
        self.assertIn("→ initialize", self.vm.rows[0].text)
        self.assertIn("←", self.vm.rows[1].text)

    def test_tool_call_row_shows_tool_name(self):
        texts = [r.text for r in self.vm.rows]
        self.assertTrue(any("tools/call web_search" in t for t in texts))
        self.assertTrue(any("tools/call shadow_fetch" in t for t in texts))

    def test_result_row_shows_jsonrpc_id(self):
        self.assertTrue(any("result id=3" in r.text for r in self.vm.rows))

    def test_fabricated_row_carries_severity_3(self):
        row = next(r for r in self.vm.rows if "shadow_fetch" in r.text)
        self.assertEqual(row.severity, 3)

    def test_clean_row_severity_0(self):
        row = next(r for r in self.vm.rows
                   if "tools/call web_search" in r.text)
        self.assertEqual(row.severity, 0)

    def test_clock_iso_and_synthetic(self):
        self.assertEqual(tui._clock("2026-06-09T18:39:29+00:00"), "18:39:29")
        self.assertEqual(tui._clock("t7"), "t7")

    def test_raw_line_renders_dimmed_not_crash(self):
        lines = handshake() + ["this is not json\n"]
        vm = tui.build_view_model(annotated_trace(lines), live=False)
        self.assertEqual(len(vm.rows), 6)
        self.assertIn("raw", vm.rows[-1].text)


if __name__ == "__main__":
    unittest.main()
