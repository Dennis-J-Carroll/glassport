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

    def test_enter_with_stale_findings_selection_does_not_crash(self):
        # findings can shrink on re-ingest: a call made before any
        # tools/list is fabricated until a later declaration arrives
        pre = [call(1, 1, "web_search", {"query": "x"}), result(2, 1)]
        vm_many = tui.build_view_model(annotated_trace(pre), live=True)
        vm_fewer = tui.build_view_model(
            annotated_trace(pre + handshake(start_seq=3)), live=True)
        self.assertLess(len(vm_fewer.findings), len(vm_many.findings))

        st = tui.UIState(focus="findings",
                         selected=len(vm_many.findings) - 1)
        tui.reduce(st, "enter", vm_fewer)   # must not raise
        self.assertEqual(st.focus, "timeline")
        self.assertLess(st.selected, len(vm_fewer.rows))


class TestTabs(unittest.TestCase):
    """Pure tab-state operations — no curses, no filesystem."""

    def test_open_tab_appends_and_activates(self):
        tabs = tui.Tabs()
        tui.open_tab(tabs, Path("/a.jsonl"))
        tui.open_tab(tabs, Path("/b.jsonl"))
        self.assertEqual([t.path.name for t in tabs.tabs],
                         ["a.jsonl", "b.jsonl"])
        self.assertEqual(tabs.active, 1)

    def test_open_existing_path_switches_without_duplicate(self):
        tabs = tui.Tabs()
        tui.open_tab(tabs, Path("/a.jsonl"))
        tui.open_tab(tabs, Path("/b.jsonl"))
        tui.open_tab(tabs, Path("/a.jsonl"))
        self.assertEqual(len(tabs.tabs), 2)
        self.assertEqual(tabs.active, 0)

    def test_cycle_wraps_around(self):
        tabs = tui.Tabs()
        for p in ("/a.jsonl", "/b.jsonl", "/c.jsonl"):
            tui.open_tab(tabs, Path(p))
        self.assertEqual(tabs.active, 2)
        tui.cycle_tab(tabs)
        self.assertEqual(tabs.active, 0)
        tui.cycle_tab(tabs)
        self.assertEqual(tabs.active, 1)

    def test_cycle_single_tab_is_noop(self):
        tabs = tui.Tabs()
        tui.open_tab(tabs, Path("/a.jsonl"))
        tui.cycle_tab(tabs)
        self.assertEqual(tabs.active, 0)

    def test_cycle_empty_is_noop(self):
        tabs = tui.Tabs()
        tui.cycle_tab(tabs)   # must not raise
        self.assertEqual(tabs.active, 0)

    def test_close_removes_active_and_clamps(self):
        tabs = tui.Tabs()
        for p in ("/a.jsonl", "/b.jsonl", "/c.jsonl"):
            tui.open_tab(tabs, Path(p))
        # active == 2 (c); close it -> active clamps to last remaining
        tui.close_tab(tabs)
        self.assertEqual([t.path.name for t in tabs.tabs],
                         ["a.jsonl", "b.jsonl"])
        self.assertEqual(tabs.active, 1)

    def test_close_middle_keeps_position(self):
        tabs = tui.Tabs()
        for p in ("/a.jsonl", "/b.jsonl", "/c.jsonl"):
            tui.open_tab(tabs, Path(p))
        tabs.active = 1
        tui.close_tab(tabs)
        self.assertEqual([t.path.name for t in tabs.tabs],
                         ["a.jsonl", "c.jsonl"])
        self.assertEqual(tabs.active, 1)   # now points at c

    def test_close_last_tab_leaves_empty(self):
        tabs = tui.Tabs()
        tui.open_tab(tabs, Path("/a.jsonl"))
        tui.close_tab(tabs)
        self.assertEqual(tabs.tabs, [])
        self.assertEqual(tabs.active, 0)

    def test_close_empty_is_noop(self):
        tabs = tui.Tabs()
        tui.close_tab(tabs)   # must not raise
        self.assertEqual(tabs.tabs, [])

    def test_each_tab_has_independent_ui_state(self):
        tabs = tui.Tabs()
        tui.open_tab(tabs, Path("/a.jsonl"))
        tui.open_tab(tabs, Path("/b.jsonl"))
        tabs.tabs[0].state.selected = 7
        self.assertEqual(tabs.tabs[1].state.selected, 0)
        self.assertIsNot(tabs.tabs[0].state, tabs.tabs[1].state)

    def test_keymap_binds_ctrl_t_and_ctrl_w(self):
        self.assertEqual(tui.KEYMAP.get(20), "next_tab")   # Ctrl+T
        self.assertEqual(tui.KEYMAP.get(23), "close_tab")  # Ctrl+W

    def test_tab_strip_marks_active_and_numbers_tabs(self):
        tabs = tui.Tabs()
        tui.open_tab(tabs, Path("/x/alpha.jsonl"))
        tui.open_tab(tabs, Path("/x/beta.jsonl"))
        tabs.active = 0
        strip = tui.format_tab_strip(tabs)
        self.assertIn("1:alpha.jsonl", strip)
        self.assertIn("2:beta.jsonl", strip)
        # active tab is marked, inactive is not
        self.assertIn("[1:alpha.jsonl]", strip)
        self.assertNotIn("[2:beta.jsonl]", strip)


class TestSearch(unittest.TestCase):
    """Incremental search over already-sanitized row text (less-style
    match-jump, never row-hiding: row indices stay stable so findings
    row_index and the overlay keep working)."""

    def setUp(self):
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}),
            result(7, 3),
            call(8, 4, "shadow_fetch", {"u": "http://x"}),
            result(9, 4),
        ]
        self.vm = tui.build_view_model(annotated_trace(lines), live=False)

    def test_matches_case_insensitive_on_timeline(self):
        hits = tui.search_matches(self.vm, "WEB_SEARCH", "timeline")
        self.assertEqual(len(hits), 1)
        self.assertIn("web_search", self.vm.rows[hits[0]].text)

    def test_matches_on_findings_focus(self):
        hits = tui.search_matches(self.vm, "fabricated", "findings")
        self.assertTrue(hits)
        for i in hits:
            self.assertIn("fabricated", self.vm.findings[i].text)

    def test_empty_query_matches_nothing(self):
        self.assertEqual(tui.search_matches(self.vm, "", "timeline"), [])

    def test_search_open_enters_input_mode(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        self.assertTrue(st.search_input)
        self.assertEqual(st.search_query, "")

    def test_typing_appends_and_jumps_to_first_match(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        for ch in "shadow":
            tui.reduce(st, f"input:{ch}", self.vm)
        self.assertEqual(st.search_query, "shadow")
        self.assertIn("shadow_fetch", self.vm.rows[st.selected].text)
        self.assertFalse(st.follow)

    def test_backspace_edits_query(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        tui.reduce(st, "input:w", self.vm)
        tui.reduce(st, "input:z", self.vm)
        tui.reduce(st, "search_backspace", self.vm)
        self.assertEqual(st.search_query, "w")

    def test_accept_leaves_input_mode_keeps_query(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        tui.reduce(st, "input:t", self.vm)
        tui.reduce(st, "search_accept", self.vm)
        self.assertFalse(st.search_input)
        self.assertEqual(st.search_query, "t")

    def test_cancel_clears_query_and_input_mode(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        tui.reduce(st, "input:t", self.vm)
        tui.reduce(st, "search_cancel", self.vm)
        self.assertFalse(st.search_input)
        self.assertEqual(st.search_query, "")

    def test_next_prev_cycle_matches_with_wraparound(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        # "tools/" appears in both tools/list and tools/call rows
        for ch in "tools/call":
            tui.reduce(st, f"input:{ch}", self.vm)
        tui.reduce(st, "search_accept", self.vm)
        hits = tui.search_matches(self.vm, "tools/call", "timeline")
        self.assertEqual(len(hits), 2)
        self.assertEqual(st.selected, hits[0])
        tui.reduce(st, "search_next", self.vm)
        self.assertEqual(st.selected, hits[1])
        tui.reduce(st, "search_next", self.vm)    # wraps
        self.assertEqual(st.selected, hits[0])
        tui.reduce(st, "search_prev", self.vm)    # wraps back
        self.assertEqual(st.selected, hits[1])

    def test_next_with_no_query_is_noop(self):
        st = tui.UIState()
        before = st.selected
        tui.reduce(st, "search_next", self.vm)
        self.assertEqual(st.selected, before)

    def test_cancel_after_accept_clears_query(self):
        # regression: q sends search_cancel after an accepted search;
        # if the reducer only honors it in input mode, q can never
        # clear the query and therefore can never quit the dashboard
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        tui.reduce(st, "input:t", self.vm)
        tui.reduce(st, "search_accept", self.vm)
        tui.reduce(st, "search_cancel", self.vm)
        self.assertEqual(st.search_query, "")

    def test_esc_after_accept_clears_query(self):
        st = tui.UIState()
        tui.reduce(st, "search_open", self.vm)
        tui.reduce(st, "input:t", self.vm)
        tui.reduce(st, "search_accept", self.vm)
        tui.reduce(st, "back", self.vm)
        self.assertEqual(st.search_query, "")

    def test_search_ignored_while_overlay_open(self):
        st = tui.UIState(overlay_open=True)
        tui.reduce(st, "search_open", self.vm)
        self.assertFalse(st.search_input)

    def test_keymap_binds_slash_n_and_shift_n(self):
        self.assertEqual(tui.KEYMAP.get(ord("/")), "search_open")
        self.assertEqual(tui.KEYMAP.get(ord("n")), "search_next")
        self.assertEqual(tui.KEYMAP.get(ord("N")), "search_prev")


class TestDriftPanel(unittest.TestCase):
    """build_drift_lines: current session vs the merged baseline of the
    other logs in the same directory (watch.py is the engine; the TUI
    only renders). Lines are (severity, text) for severity coloring."""

    def _write(self, tmp, name, lines):
        p = Path(tmp) / name
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def _session(self, tools=None, calls=()):
        from tests.test_watch import session
        return session(tools=tools, calls=calls)

    def test_only_session_is_its_own_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "01_srv_1.jsonl", self._session())
            lines = tui.build_drift_lines(p, Path(tmp))
            text = "\n".join(t for _, t in lines)
            self.assertIn("baseline", text)

    def test_new_declared_tool_surfaces_with_severity(self):
        two = [{"name": "web_search"}, {"name": "shell_exec"}]
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "01_srv_1.jsonl", self._session())
            p = self._write(tmp, "02_srv_2.jsonl", self._session(tools=two))
            lines = tui.build_drift_lines(p, Path(tmp))
            hot = [(sev, t) for sev, t in lines if "shell_exec" in t]
            self.assertTrue(hot)
            self.assertEqual(hot[0][0], 2)          # new_declared_tool sev
            self.assertIn("new_declared_tool", hot[0][1])

    def test_clean_repeat_session_reports_no_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "01_srv_1.jsonl", self._session())
            p = self._write(tmp, "02_srv_2.jsonl", self._session())
            lines = tui.build_drift_lines(p, Path(tmp))
            text = "\n".join(t for _, t in lines)
            self.assertIn("no drift", text)

    def test_unreadable_dir_degrades_not_raises(self):
        lines = tui.build_drift_lines(
            Path("/nonexistent/s.jsonl"), Path("/nonexistent"))
        self.assertTrue(lines)          # explains itself instead of raising

    def test_d_toggles_drift_panel(self):
        vm = tui.build_view_model(annotated_trace(handshake()), live=False)
        st = tui.UIState()
        tui.reduce(st, "drift", vm)
        self.assertTrue(st.drift_open)
        tui.reduce(st, "drift", vm)
        self.assertFalse(st.drift_open)

    def test_shift_d_opens_full_drift_overlay_and_back_closes(self):
        vm = tui.build_view_model(annotated_trace(handshake()), live=False)
        st = tui.UIState()
        tui.reduce(st, "drift_full", vm)
        self.assertTrue(st.overlay_open)
        self.assertEqual(st.overlay_mode, "drift")
        tui.reduce(st, "back", vm)
        self.assertFalse(st.overlay_open)

    def test_enter_still_opens_frame_overlay(self):
        vm = tui.build_view_model(annotated_trace(handshake()), live=False)
        st = tui.UIState()
        tui.reduce(st, "enter", vm)
        self.assertTrue(st.overlay_open)
        self.assertEqual(st.overlay_mode, "frame")

    def test_keymap_binds_d_and_shift_d(self):
        self.assertEqual(tui.KEYMAP.get(ord("d")), "drift")
        self.assertEqual(tui.KEYMAP.get(ord("D")), "drift_full")


class TestAuditPanel(unittest.TestCase):
    """build_audit_lines: static audit score + runtime findings as
    (severity, text). Static finding lines carry rule + location only —
    never f.detail, which embeds matched (attacker-controlled) source.
    Runtime explanations are glassport-generated and already redacted
    by detectors._redact, same trust level as the findings list."""

    def _trace_with_findings(self):
        # fabricated call -> sev-3 runtime annotation
        return annotated_trace(
            handshake() + [call(6, 3, "shadow_fetch", {"u": "http://x"}),
                           result(7, 3)])

    def test_no_report_says_skipped_but_shows_runtime(self):
        trace = self._trace_with_findings()
        lines = tui.build_audit_lines(None, trace.annotations)
        text = "\n".join(t for _, t in lines)
        self.assertIn("--audit", text)              # how to enable
        self.assertIn("fabricated_tool_call", text)
        self.assertTrue(any(sev == 3 for sev, _ in lines))

    def test_report_shows_score_grade_and_rule_not_detail(self):
        from glassport import audit
        secret = "AKIA" + "A" * 16
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "server.py").write_text(
                f'key = "{secret}"\n', encoding="utf-8")
            report = audit.audit_path(tmp)
        self.assertTrue(report.findings)
        lines = tui.build_audit_lines(report, [])
        text = "\n".join(t for _, t in lines)
        self.assertIn(str(report.score), text)
        self.assertIn(report.grade, text)
        self.assertIn("server.py", text)
        self.assertNotIn(secret, text)               # detail never rendered

    def test_clean_trace_no_report_degrades_gracefully(self):
        trace = annotated_trace(handshake() + [
            call(6, 3, "web_search", {"query": "x"}), result(7, 3)])
        lines = tui.build_audit_lines(None, trace.annotations)
        self.assertTrue(lines)                       # still explains itself

    def test_a_opens_audit_overlay_and_back_closes(self):
        vm = tui.build_view_model(annotated_trace(handshake()), live=False)
        st = tui.UIState()
        tui.reduce(st, "audit", vm)
        self.assertTrue(st.overlay_open)
        self.assertEqual(st.overlay_mode, "audit")
        tui.reduce(st, "back", vm)
        self.assertFalse(st.overlay_open)

    def test_keymap_binds_a(self):
        self.assertEqual(tui.KEYMAP.get(ord("a")), "audit")


class TestParseArgs(unittest.TestCase):
    def test_defaults(self):
        path, log_dir, audit_dir, gate_control, want_help = \
            tui._parse_args([])
        self.assertIsNone(path)
        self.assertIsNone(audit_dir)
        self.assertFalse(gate_control)
        self.assertFalse(want_help)
        self.assertTrue(str(log_dir).endswith("sessions"))

    def test_session_path_and_flags(self):
        path, log_dir, audit_dir, gate_control, want_help = \
            tui._parse_args(["s.jsonl", "--log-dir", "/logs",
                             "--audit", "/srv/src", "--gate-control"])
        self.assertEqual(path, Path("s.jsonl"))
        self.assertEqual(log_dir, Path("/logs"))
        self.assertEqual(audit_dir, Path("/srv/src"))
        self.assertTrue(gate_control)
        self.assertFalse(want_help)

    def test_help_flag(self):
        *_, want_help = tui._parse_args(["--help"])
        self.assertTrue(want_help)


class TestGateOverrideControl(unittest.TestCase):
    """TUI side of gate control: read/toggle the per-session override
    file. Toggle only ever runs when the TUI was launched with
    --gate-control; the file written must be one the tap's fail-closed
    reader actually accepts (owner-only perms)."""

    def _session(self, tmp):
        p = Path(tmp) / "s.jsonl"
        p.write_text("", encoding="utf-8")
        return p

    def test_read_absent_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(tui.read_gate_override(self._session(tmp)))

    def test_first_toggle_disables_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self._session(tmp)
            new = tui.toggle_gate_override(s)
            self.assertFalse(new)                     # on -> off
            self.assertIs(tui.read_gate_override(s), False)

    def test_second_toggle_reenables(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = self._session(tmp)
            tui.toggle_gate_override(s)
            self.assertTrue(tui.toggle_gate_override(s))
            self.assertIs(tui.read_gate_override(s), True)

    @unittest.skipUnless(os.name == "posix",
                         "st_mode owner-bits are POSIX semantics")
    def test_written_file_is_owner_only(self):
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            s = self._session(tmp)
            tui.toggle_gate_override(s)
            mode = stat.S_IMODE((Path(tmp) / "s.jsonl.gate").stat().st_mode)
            self.assertEqual(mode & 0o077, 0)         # no group/world bits

    def test_gate_honors_tui_written_override(self):
        # end-to-end lock: what the TUI writes, the tap's fail-closed
        # reader accepts — a drifting file format would break silently
        from glassport.tap import Gate
        with tempfile.TemporaryDirectory() as tmp:
            s = self._session(tmp)
            tui.toggle_gate_override(s)               # enforcement off
            g = Gate(control_path=Path(tmp) / "s.jsonl.gate")
            g.observe_s2c((json.dumps(
                {"jsonrpc": "2.0", "id": 2,
                 "result": {"tools": [{"name": "web_search"}]}}) +
                "\n").encode())
            action, _, info = g.check_c2s((json.dumps(
                {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                 "params": {"name": "shadow_fetch"}}) + "\n").encode())
            self.assertEqual(action, "forward")
            self.assertEqual(info["action"], "gate_disabled")

    def test_keymap_binds_bang(self):
        self.assertEqual(tui.KEYMAP.get(ord("!")), "gate_toggle")


class TestMouse(unittest.TestCase):
    """Layout + hit-testing are pure so a click maps to a selection
    without curses. The draw code uses the same layout function, so
    the hit test can never drift from what is on screen."""

    def _vm(self, n_findings=0):
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}), result(7, 3)]
        if n_findings:
            lines += [call(8, 4, "shadow_fetch", {"u": "u"}), result(9, 4)]
        return tui.build_view_model(annotated_trace(lines), live=False)

    def test_layout_no_findings_no_tabs(self):
        vm = self._vm()
        lo = tui.layout(24, vm, many_tabs=False)
        self.assertEqual(lo.tl_top, 2)
        self.assertEqual(lo.tl_h, 21)        # rows 2..22, footer at 23
        self.assertEqual(lo.n_findings, 0)

    def test_layout_tabs_shift_timeline_down(self):
        vm = self._vm()
        lo = tui.layout(24, vm, many_tabs=True)
        self.assertEqual(lo.tl_top, 3)

    def test_click_on_timeline_row_selects_it(self):
        vm = self._vm()
        st = tui.UIState()
        lo = tui.layout(24, vm, many_tabs=False)
        first = tui.first_visible(st, vm, lo.tl_h)
        hit = tui.hit_test(lo.tl_top + 2, lo, first, vm)
        self.assertEqual(hit, ("timeline", first + 2))

    def test_click_below_rows_is_none(self):
        vm = self._vm()   # 7 rows, tall window: clicks past last row
        lo = tui.layout(40, vm, many_tabs=False)
        first = tui.first_visible(tui.UIState(), vm, lo.tl_h)
        self.assertIsNone(tui.hit_test(lo.tl_top + 30, lo, first, vm))

    def test_click_on_finding_row_selects_finding(self):
        vm = self._vm(n_findings=1)
        self.assertTrue(vm.findings)
        lo = tui.layout(24, vm, many_tabs=False)
        first = tui.first_visible(tui.UIState(), vm, lo.tl_h)
        y = lo.findings_top + 1          # first finding line (after rule)
        self.assertEqual(tui.hit_test(y, lo, first, vm), ("findings", 0))

    def test_click_on_header_is_none(self):
        vm = self._vm()
        lo = tui.layout(24, vm, many_tabs=False)
        first = tui.first_visible(tui.UIState(), vm, lo.tl_h)
        self.assertIsNone(tui.hit_test(0, lo, first, vm))
        self.assertIsNone(tui.hit_test(1, lo, first, vm))


class TestCLIWiring(unittest.TestCase):
    def test_main_rejects_missing_file(self):
        rc = tui.main(["/nonexistent/session.jsonl"])
        self.assertEqual(rc, 1)

    def test_usage_mentions_tui(self):
        from glassport.tap import USAGE
        self.assertIn("tui", USAGE)


class TestHelpOverlay(unittest.TestCase):
    """F-UX-1: `?` surfaces all bindings — 11 of 18 were footer-invisible."""

    def setUp(self):
        self.vm = tui.build_view_model(
            annotated_trace(handshake()), live=True)
        self.st = tui.UIState()

    def test_question_mark_in_keymap(self):
        self.assertEqual(tui.KEYMAP.get(ord("?")), "help")

    def test_help_opens_overlay(self):
        tui.reduce(self.st, "help", self.vm)
        self.assertTrue(self.st.overlay_open)
        self.assertEqual(self.st.overlay_mode, "help")
        self.assertEqual(self.st.overlay_scroll, 0)

    def test_back_closes_help(self):
        tui.reduce(self.st, "help", self.vm)
        tui.reduce(self.st, "back", self.vm)
        self.assertFalse(self.st.overlay_open)

    def test_help_scrolls_like_any_overlay(self):
        tui.reduce(self.st, "help", self.vm)
        tui.reduce(self.st, "down", self.vm)
        self.assertEqual(self.st.overlay_scroll, 1)
        tui.reduce(self.st, "up", self.vm)
        self.assertEqual(self.st.overlay_scroll, 0)

    def test_all_keymap_actions_documented(self):
        text = " ".join(t[1] if isinstance(t, tuple) else t
                        for t in tui.build_help_lines())
        # every semantic key the reducer understands must appear
        for token in ("j/k", "arrows", "g/G", "enter", "tab", "f",
                      "esc", "q", "/", "n/N", "d", "D", "a", "!",
                      "^T", "^W", "mouse", "?"):
            self.assertIn(token, text, f"help missing binding: {token}")

    def test_help_grouped_by_category(self):
        headers = [t[1] for t in tui.build_help_lines()
                   if isinstance(t, tuple)]
        for cat in ("movement", "selection", "search", "overlays",
                    "gate", "quit"):
            self.assertTrue(any(cat in h.lower() for h in headers),
                            f"missing category header: {cat}")

    def test_footer_mentions_help_key(self):
        # the footer literal lives in the render shell; lock the string
        import inspect
        src = inspect.getsource(tui._draw_dashboard)
        self.assertIn("? help", src)


if __name__ == "__main__":
    unittest.main()
