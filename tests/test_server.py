"""
Tests for `glassport serve` — glassport exposed as a queryable MCP
server (newline-delimited JSON-RPC over stdio, zero dependencies).

serve() is exercised directly over StringIO pairs; no subprocess is
needed because the transport is just lines in, lines out.

Pure stdlib, run with:  python3 -m unittest tests.test_server
"""
import io
import json
import tempfile
import unittest
from pathlib import Path

from glassport import server as server_mod
from tests.test_detectors import handshake, call


def rpc(rid, method, params=None):
    req = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        req["params"] = params
    return req


def run_server(requests: list[dict], log_dir) -> list[dict]:
    src = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    out = io.StringIO()
    rc = server_mod.serve(src, out, log_dir=Path(log_dir))
    assert rc == 0
    return [json.loads(l) for l in out.getvalue().splitlines()]


def tool_call(rid, name, arguments=None):
    return rpc(rid, "tools/call", {"name": name,
                                   "arguments": arguments or {}})


def text_of(resp: dict) -> str:
    return resp["result"]["content"][0]["text"]


def write_session(tmp, name, lines) -> Path:
    p = Path(tmp) / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


class TestServeProtocol(unittest.TestCase):
    def test_initialize_and_tools_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            resps = run_server([
                rpc(1, "initialize", {"protocolVersion": "2025-06-18",
                                      "capabilities": {}}),
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                rpc(2, "tools/list"),
            ], tmp)
        self.assertEqual(len(resps), 2)   # notification draws no response
        init = resps[0]["result"]
        self.assertEqual(init["serverInfo"]["name"], "glassport")
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        names = {t["name"] for t in resps[1]["result"]["tools"]}
        self.assertEqual(names, {"list_sessions", "analyze_session",
                                 "audit_server", "get_gate_status",
                                 "watch_drift"})

    def test_unknown_tool_is_error_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            resps = run_server([tool_call(1, "no_such_tool")], tmp)
        self.assertTrue(resps[0]["result"]["isError"])

    def test_garbage_line_skipped(self):
        src = io.StringIO("%%% not json %%%\n" +
                          json.dumps(rpc(1, "tools/list")) + "\n")
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            server_mod.serve(src, out, log_dir=Path(tmp))
        self.assertEqual(len(out.getvalue().splitlines()), 1)

    def test_tool_exception_becomes_error_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            resps = run_server(
                [tool_call(1, "analyze_session",
                           {"session_path": tmp + "/missing.jsonl"})], tmp)
        self.assertTrue(resps[0]["result"]["isError"])


class TestServeTools(unittest.TestCase):
    def test_list_sessions_newest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_session(tmp, "20260101T000000Z_a_1.jsonl", handshake())
            write_session(tmp, "20260201T000000Z_b_2.jsonl", handshake())
            resps = run_server([tool_call(1, "list_sessions")], tmp)
        paths = json.loads(text_of(resps[0]))
        self.assertEqual(len(paths), 2)
        self.assertIn("20260201", paths[0])

    def test_analyze_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake() +
                              [call(6, 3, "shadow_tool", {})])
            resps = run_server(
                [tool_call(1, "analyze_session",
                           {"session_path": str(p)})], tmp)
        data = json.loads(text_of(resps[0]))
        self.assertEqual(data["declared_tools"], ["web_search"])
        self.assertEqual(data["fabricated_calls"],
                         [{"seq": 6, "tool": "shadow_tool"}])
        self.assertTrue(any(a["subcategory"] == "fabricated_tool_call"
                            for a in data["annotations"]))

    def test_get_gate_status(self):
        blocked = {"schema_version": "0.1", "seq": 6, "ts": "t6",
                   "dir": "c2s", "frame": {}, "raw": None,
                   "gate": {"action": "blocked", "tool": "shadow_tool",
                            "declared": ["web_search"]}}
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "g.jsonl",
                              handshake() + [json.dumps(blocked)])
            resps = run_server(
                [tool_call(1, "get_gate_status",
                           {"session_path": str(p)})], tmp)
        data = json.loads(text_of(resps[0]))
        self.assertEqual(data["blocked_count"], 1)
        self.assertEqual(data["blocked"][0]["tool"], "shadow_tool")

    def test_audit_server_returns_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "srv.py"
            target.write_text("import os\nos.system('id')\n",
                              encoding="utf-8")
            resps = run_server(
                [tool_call(1, "audit_server", {"path": str(target)})], tmp)
        json.loads(text_of(resps[0]))   # must be machine-parseable

    def test_watch_drift_groups_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_session(tmp, "20260101T000000Z_srv_1.jsonl", handshake())
            write_session(tmp, "20260102T000000Z_srv_2.jsonl", handshake())
            resps = run_server([tool_call(1, "watch_drift")], tmp)
        groups = json.loads(text_of(resps[0]))
        (rows,) = groups.values()
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
