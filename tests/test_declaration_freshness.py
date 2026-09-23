"""A declared surface is only authority while it is current.

After `notifications/tools/list_changed` or once a `ttlMs` has elapsed, the
old list can no longer prove that a tool is excluded: a newly added tool
would be falsely treated as fabricated (and, in gate mode, blocked). Stale
means unknown, never empty. Expiry is measured on wire timestamps so live
processing and replay reach the same answer.
"""
import json
import unittest
from datetime import datetime, timedelta, timezone

from glassport import detectors
from glassport.adapters.mcp_session import MCPTraceBuilder, from_mcp_session

T0 = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def W(seq, direction, frame, at_ms=None):
    """One tap line stamped `at_ms` milliseconds after T0 (ISO 8601 UTC)."""
    ts = (T0 + timedelta(milliseconds=seq if at_ms is None else at_ms)).isoformat()
    return json.dumps({"schema_version": "0.1", "seq": seq, "ts": ts,
                       "dir": direction, "frame": frame, "raw": None})


def session(tools=("web_search",), ttl=None, list_extra=None):
    result = {"tools": [{"name": n} for n in tools]}
    if ttl is not None:
        result["ttlMs"] = ttl
    result.update(list_extra or {})
    return [
        W(1, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "c"}}}),
        W(2, "s2c", {"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2025-11-25", "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "s"}}}),
        W(3, "c2s", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
        W(4, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        W(5, "s2c", {"jsonrpc": "2.0", "id": 2, "result": result}),
    ]


def call(seq, rid, name, at_ms=None):
    return W(seq, "c2s", {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                          "params": {"name": name, "arguments": {}}}, at_ms)


LIST_CHANGED = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}


def surface_after(lines):
    builder = MCPTraceBuilder()
    for line in lines:
        builder.feed(json.loads(line))
    return builder.state.surface


def fabricated(lines):
    return [a.metadata.get("tool") or a.explanation
            for a in detectors.annotate(from_mcp_session(lines))
            if a.subcategory == "fabricated_tool_call"]


class TestListChanged(unittest.TestCase):
    def test_server_list_changed_makes_the_surface_unknown(self):
        lines = session() + [W(6, "s2c", LIST_CHANGED)]
        self.assertEqual(surface_after(lines[:-1]), {"web_search"})
        self.assertIsNone(surface_after(lines))

    def test_new_tool_after_list_changed_is_not_fabricated(self):
        lines = session() + [W(6, "s2c", LIST_CHANGED), call(7, 3, "new_tool")]
        self.assertEqual(fabricated(lines), [])

    def test_relisting_restores_authority(self):
        lines = session() + [
            W(6, "s2c", LIST_CHANGED),
            W(7, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            W(8, "s2c", {"jsonrpc": "2.0", "id": 3, "result": {
                "tools": [{"name": "web_search"}, {"name": "new_tool"}]}}),
            call(9, 4, "new_tool"), call(10, 5, "absent")]
        self.assertEqual(surface_after(lines), {"web_search", "new_tool"})
        self.assertEqual(len(fabricated(lines)), 1)

    def test_list_in_flight_across_list_changed_cannot_restore_authority(self):
        # Over HTTP the notification and the reply travel on different
        # streams: nothing proves the reply reflects the change.
        lines = session() + [
            W(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            W(7, "s2c", LIST_CHANGED),
            W(8, "s2c", {"jsonrpc": "2.0", "id": 3, "result": {
                "tools": [{"name": "web_search"}]}})]
        self.assertIsNone(surface_after(lines))

    def test_client_sent_list_changed_is_ignored(self):
        """Only the server can retract its declaration. A client that could
        would switch enforcement off at will."""
        lines = session() + [W(6, "c2s", LIST_CHANGED)]
        self.assertEqual(surface_after(lines), {"web_search"})


class TestTTL(unittest.TestCase):
    def test_surface_is_authority_until_ttl_then_unknown(self):
        base = session(ttl=1000)
        self.assertEqual(surface_after(base + [call(6, 3, "x", at_ms=1005)]),
                         {"web_search"})
        self.assertIsNone(surface_after(base + [call(6, 3, "x", at_ms=1006)]))

    def test_expired_surface_does_not_flag_calls(self):
        base = session(ttl=1000)
        self.assertEqual(len(fabricated(base + [call(6, 3, "absent", at_ms=900)])), 1)
        self.assertEqual(fabricated(base + [call(6, 3, "absent", at_ms=5000)]), [])

    def test_refresh_racing_expiry_still_restores_authority(self):
        """Expiry retires the current surface, not a refresh already asked for."""
        lines = session(ttl=1000) + [
            W(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, at_ms=990),
            W(7, "s2c", {"jsonrpc": "2.0", "id": 3, "result": {
                "tools": [{"name": "web_search"}], "ttlMs": 1000}}, at_ms=1010)]
        self.assertEqual(surface_after(lines), {"web_search"})
        self.assertEqual(surface_after(lines + [call(8, 4, "x", at_ms=2010)]),
                         {"web_search"})
        self.assertIsNone(surface_after(lines + [call(8, 4, "x", at_ms=2011)]))

    def test_zero_ttl_is_never_reusable(self):
        self.assertIsNone(surface_after(session(ttl=0) + [call(6, 3, "x", at_ms=6)]))

    def test_no_ttl_keeps_todays_behavior(self):
        self.assertEqual(surface_after(session() + [call(6, 3, "x", at_ms=10**9)]),
                         {"web_search"})

    def test_huge_ttl_does_not_overflow(self):
        self.assertEqual(surface_after(session(ttl=10**30) + [call(6, 3, "x", at_ms=10**9)]),
                         {"web_search"})

    def test_malformed_ttl_makes_the_declaration_unknown(self):
        for ttl in (-1, "1000", 1.5, True, None, [1000]):
            with self.subTest(ttl=ttl):
                lines = session(list_extra={"ttlMs": ttl})
                self.assertIsNone(surface_after(lines))

    def test_unreadable_timestamp_with_ttl_is_unknown(self):
        lines = session(ttl=60_000)
        entry = json.loads(lines[-1])
        entry["ts"] = "not-a-time"
        self.assertIsNone(surface_after(lines[:-1] + [json.dumps(entry)]))

    def test_earliest_page_expiry_governs_a_paginated_list(self):
        lines = session(tools=("one",), list_extra={"ttlMs": 500, "nextCursor": "p2"}) + [
            W(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/list",
                         "params": {"cursor": "p2"}}),
            W(7, "s2c", {"jsonrpc": "2.0", "id": 3, "result": {
                "tools": [{"name": "two"}], "ttlMs": 60_000}})]
        self.assertEqual(surface_after(lines + [call(8, 4, "x", at_ms=505)]), {"one", "two"})
        self.assertIsNone(surface_after(lines + [call(8, 4, "x", at_ms=506)]))

    def test_live_and_replay_agree(self):
        lines = session(ttl=1000) + [call(6, 3, "absent", at_ms=500),
                                     W(7, "s2c", LIST_CHANGED),
                                     call(8, 4, "absent2", at_ms=600),
                                     call(9, 5, "absent3", at_ms=5000)]
        from glassport.incremental import DetectorEngine
        builder, engine, live = MCPTraceBuilder(retain_events=False), DetectorEngine(), []
        for line in lines:
            event = builder.feed(json.loads(line))
            live.extend(a.subcategory for a in engine.on_event(event, builder.state))
        replay = [a.subcategory for a in detectors.annotate(from_mcp_session(lines))]
        self.assertEqual(sorted(live), sorted(replay))
        self.assertEqual(live.count("fabricated_tool_call"), 1)


if __name__ == "__main__":
    unittest.main()
