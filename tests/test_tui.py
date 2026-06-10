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


class TestFindingsAndOverlay(unittest.TestCase):
    def setUp(self):
        lines = handshake() + [
            call(6, 3, "shadow_fetch", {"u": "http://x"}),
            result(7, 3),
        ]
        self.trace = annotated_trace(lines)
        self.vm = tui.build_view_model(self.trace, live=False)

    def test_findings_present_and_sorted_by_severity_desc(self):
        self.assertGreaterEqual(len(self.vm.findings), 1)
        sevs = [f.severity for f in self.vm.findings]
        self.assertEqual(sevs, sorted(sevs, reverse=True))

    def test_finding_text_has_sev_and_subcategory(self):
        top = self.vm.findings[0]
        self.assertIn("sev 3", top.text)
        self.assertIn("fabricated_tool_call", top.text)

    def test_finding_points_at_timeline_row(self):
        top = self.vm.findings[0]
        self.assertIn("shadow_fetch", self.vm.rows[top.row_index].text)

    def test_overlay_shows_json_and_annotations(self):
        top = self.vm.findings[0]
        text = "\n".join(tui.format_overlay(self.trace, top.row_index))
        self.assertIn('"name": "shadow_fetch"', text)
        self.assertIn("sev 3", text)
        self.assertIn("outside the declared surface", text)

    def test_overlay_on_clean_event_says_no_findings(self):
        text = "\n".join(tui.format_overlay(self.trace, 0))
        self.assertIn("no findings", text)


class TestPicker(unittest.TestCase):
    def _write_session(self, dir_, name, n_lines, mtime):
        p = Path(dir_) / name
        p.write_text("\n".join(
            L(i, "c2s", {"jsonrpc": "2.0", "method": "ping"})
            for i in range(1, n_lines + 1)) + "\n")
        os.utime(p, (mtime, mtime))
        return p

    def test_listing_sorted_newest_first_with_live_flag(self):
        now = 1_780_000_000.0
        with tempfile.TemporaryDirectory() as d:
            self._write_session(d, "old_srv.jsonl", 3, now - 3600)
            self._write_session(d, "hot_srv.jsonl", 5, now - 1)
            entries = tui.list_sessions(Path(d), now=now)
        self.assertEqual([e.path.name for e in entries],
                         ["hot_srv.jsonl", "old_srv.jsonl"])
        self.assertTrue(entries[0].live)
        self.assertFalse(entries[1].live)
        self.assertEqual(entries[0].frames, 5)

    def test_listing_ignores_non_jsonl(self):
        now = 1_780_000_000.0
        with tempfile.TemporaryDirectory() as d:
            self._write_session(d, "a_srv.jsonl", 1, now - 10)
            (Path(d) / "report.html").write_text("<html></html>")
            entries = tui.list_sessions(Path(d), now=now)
        self.assertEqual(len(entries), 1)

    def test_missing_dir_returns_empty(self):
        entries = tui.list_sessions(Path("/nonexistent/glassport"), now=0.0)
        self.assertEqual(entries, [])


class TestReducer(unittest.TestCase):
    def setUp(self):
        lines = handshake() + [
            call(6, 3, "shadow_fetch", {"u": "x"}),
            result(7, 3),
        ]
        self.vm = tui.build_view_model(annotated_trace(lines), live=True)
        self.st = tui.UIState()

    def test_initial_state_follows_tail(self):
        self.assertTrue(self.st.follow)
        self.assertEqual(self.st.focus, "timeline")
        self.assertFalse(self.st.overlay_open)

    def test_scroll_up_disables_follow(self):
        tui.reduce(self.st, "up", self.vm)
        self.assertFalse(self.st.follow)

    def test_follow_toggle_and_bottom_jump(self):
        tui.reduce(self.st, "up", self.vm)
        tui.reduce(self.st, "follow", self.vm)
        self.assertTrue(self.st.follow)
        self.assertEqual(self.st.selected, len(self.vm.rows) - 1)

    def test_selection_clamped(self):
        tui.reduce(self.st, "top", self.vm)
        tui.reduce(self.st, "up", self.vm)
        self.assertEqual(self.st.selected, 0)
        tui.reduce(self.st, "bottom", self.vm)
        tui.reduce(self.st, "down", self.vm)
        self.assertEqual(self.st.selected, len(self.vm.rows) - 1)

    def test_enter_on_timeline_opens_overlay_back_closes(self):
        tui.reduce(self.st, "enter", self.vm)
        self.assertTrue(self.st.overlay_open)
        tui.reduce(self.st, "back", self.vm)
        self.assertFalse(self.st.overlay_open)

    def test_tab_switches_focus_and_enter_jumps_to_event(self):
        tui.reduce(self.st, "tab", self.vm)
        self.assertEqual(self.st.focus, "findings")
        self.st.selected = 0
        target = self.vm.findings[0].row_index
        tui.reduce(self.st, "enter", self.vm)
        self.assertEqual(self.st.focus, "timeline")
        self.assertEqual(self.st.selected, target)
        self.assertFalse(self.st.follow)

    def test_up_down_move_within_focused_list(self):
        tui.reduce(self.st, "tab", self.vm)      # findings focus
        tui.reduce(self.st, "down", self.vm)
        self.assertLessEqual(self.st.selected, len(self.vm.findings) - 1)

    def test_overlay_scroll_clamps_at_zero_and_grows(self):
        tui.reduce(self.st, "enter", self.vm)      # open overlay
        tui.reduce(self.st, "up", self.vm)
        self.assertEqual(self.st.overlay_scroll, 0)   # clamped
        tui.reduce(self.st, "down", self.vm)
        tui.reduce(self.st, "down", self.vm)
        self.assertEqual(self.st.overlay_scroll, 2)   # unbounded growth
        self.assertTrue(self.st.overlay_open)         # still open
        self.assertTrue(self.st.follow)               # untouched while overlay


if __name__ == "__main__":
    unittest.main()
