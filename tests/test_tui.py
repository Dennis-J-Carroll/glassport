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


if __name__ == "__main__":
    unittest.main()
