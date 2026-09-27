"""Correlation keyed by HTTP exchange (plan S2).

In a stateless 2026 scope, independent POSTs from different callers reuse
JSON-RPC ids freely. Keying pending requests by id alone would quarantine
every reused id for good, and no tools/list could ever establish a surface.
Each POST's response travels on that POST, so an exchange id plus the
JSON-RPC id is unambiguous.
"""
import json
import unittest

from glassport.adapters.mcp_session import MCPTraceBuilder


def entry(seq, direction, frame, exchange=None):
    out = {"seq": seq, "ts": f"t{seq}", "dir": direction, "frame": frame}
    if exchange is not None:
        out["http_observation"] = {"exchange": exchange}
    return out


def list_req(rid):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/list"}


def list_reply(rid, *names):
    return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": n} for n in names]}}


def fold(entries):
    builder = MCPTraceBuilder()
    for e in entries:
        builder.ingest_frame(json.loads(json.dumps(e)))
    return builder


class TestExchangeCorrelation(unittest.TestCase):
    def test_reused_ids_on_different_exchanges_both_correlate(self):
        b = fold([entry(1, "c2s", list_req(1), "ex-a"), entry(2, "c2s", list_req(1), "ex-b"),
                  entry(3, "s2c", list_reply(1, "search"), "ex-b"),
                  entry(4, "s2c", list_reply(1, "search"), "ex-a")])
        self.assertEqual(b.state.surface, {"search"})

    def test_same_ids_without_exchange_stay_ambiguous(self):
        """Legacy and stdio keep id-only keying: a reused id is ambiguous."""
        b = fold([entry(1, "c2s", list_req(1)), entry(2, "c2s", list_req(1)),
                  entry(3, "s2c", list_reply(1, "search"))])
        self.assertIsNone(b.state.surface)

    def test_reply_on_another_exchange_does_not_pair(self):
        b = fold([entry(1, "c2s", list_req(1), "ex-a"),
                  entry(2, "s2c", list_reply(1, "search"), "ex-b")])
        self.assertIsNone(b.state.surface)

    def test_quarantine_is_per_exchange(self):
        # ex-a duplicates id 1 (ambiguous there); ex-b's id 1 is unaffected.
        b = fold([entry(1, "c2s", list_req(1), "ex-a"), entry(2, "c2s", list_req(1), "ex-a"),
                  entry(3, "c2s", list_req(1), "ex-b"),
                  entry(4, "s2c", list_reply(1, "search"), "ex-b")])
        self.assertEqual(b.state.surface, {"search"})

    def test_malformed_exchange_values_fall_back_to_id_only(self):
        for bad in (5, "", "x" * 200, None, ["a"]):
            with self.subTest(exchange=bad):
                raw = [entry(1, "c2s", list_req(1)), entry(2, "c2s", list_req(1)),
                       entry(3, "s2c", list_reply(1, "search"))]
                for e in raw:
                    e["http_observation"] = {"exchange": bad}
                self.assertIsNone(fold(raw).state.surface)

    def test_replay_matches_live(self):
        from glassport.adapters.mcp_session import from_mcp_session
        entries = [entry(1, "c2s", list_req(1), "ex-a"), entry(2, "c2s", list_req(1), "ex-b"),
                   entry(3, "s2c", list_reply(1, "search"), "ex-b"),
                   entry(4, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                    "params": {"name": "nope"}}, "ex-c")]
        live = fold(entries)
        replay = from_mcp_session([json.dumps(e) for e in entries])
        self.assertEqual(live.state.surface, replay.declared_surface())
        self.assertEqual([n for _, n in replay.fabricated_tool_calls()], ["nope"])


if __name__ == "__main__":
    unittest.main()
