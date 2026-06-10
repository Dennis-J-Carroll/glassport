"""
Tests for the M5 gate — active enforcement on the c2s path.

Unit-tests the Gate class directly (frame in, decision out), then the
plumbing that carries gate actions through the log schema, the adapter,
the gate_actions detector, and the HTML report. Ends with a live
end-to-end run: gate-wrapped fake_server.py, a blocked call dying at
the glass and a declared call passing untouched.

Pure stdlib, run with:  python3 -m unittest tests.test_gate
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from adapters.mcp_session import from_mcp_session
from interaction_trace import AnnotationKind, EventKind
import detectors
import report as report_mod
from glassport_tap import Gate
from tests.test_detectors import handshake

REPO = Path(__file__).resolve().parent.parent


def line(frame: dict) -> bytes:
    return (json.dumps(frame) + "\n").encode()

TOOLS_LIST_RESULT = line({"jsonrpc": "2.0", "id": 2,
                          "result": {"tools": [{"name": "web_search"}]}})


def declared_gate() -> Gate:
    g = Gate()
    g.observe_s2c(TOOLS_LIST_RESULT)
    return g


class TestGateDecisions(unittest.TestCase):
    def test_forwards_until_declaration_seen(self):
        g = Gate()
        action, resp, info = g.check_c2s(
            line({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "anything"}}))
        self.assertEqual(action, "forward")
        self.assertIsNone(resp)

    def test_blocks_undeclared_call_with_error_response(self):
        g = declared_gate()
        action, resp, info = g.check_c2s(
            line({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                  "params": {"name": "shadow_tool"}}))
        self.assertEqual(action, "block")
        err = json.loads(resp)
        self.assertEqual(err["id"], 7)
        self.assertEqual(err["error"]["code"], -32000)
        self.assertEqual(err["error"]["data"]["glassport"], "gate_blocked")
        self.assertEqual(err["error"]["data"]["tool"], "shadow_tool")
        self.assertEqual(info["action"], "blocked")

    def test_forwards_declared_call(self):
        g = declared_gate()
        action, resp, _ = g.check_c2s(
            line({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "web_search",
                             "arguments": {"query": "x"}}}))
        self.assertEqual(action, "forward")

    def test_forwards_non_call_frames(self):
        g = declared_gate()
        for frame in (
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 9, "result": {}},   # reply to server
        ):
            action, _, _ = g.check_c2s(line(frame))
            self.assertEqual(action, "forward")

    def test_forwards_unparseable_line(self):
        # the relay stays sacred for anything the gate cannot read
        action, _, _ = declared_gate().check_c2s(b"%%% not json %%%\n")
        self.assertEqual(action, "forward")

    def test_blocked_notification_call_gets_no_response(self):
        g = declared_gate()
        action, resp, info = g.check_c2s(
            line({"jsonrpc": "2.0", "method": "tools/call",
                  "params": {"name": "shadow_tool"}}))   # no id
        self.assertEqual(action, "block")
        self.assertIsNone(resp)
        self.assertEqual(info["action"], "blocked")

    def test_latest_declaration_is_the_contract(self):
        g = declared_gate()
        g.observe_s2c(line({"jsonrpc": "2.0", "id": 5,
                            "result": {"tools": [{"name": "file_read"}]}}))
        action, _, _ = g.check_c2s(
            line({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                  "params": {"name": "web_search"}}))    # no longer declared
        self.assertEqual(action, "block")

    def test_malformed_tools_entries_ignored(self):
        g = Gate()
        g.observe_s2c(line({"jsonrpc": "2.0", "id": 2,
                            "result": {"tools": ["junk", {"x": 1},
                                                 {"name": "real_tool"}]}}))
        action, _, _ = g.check_c2s(
            line({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "real_tool"}}))
        self.assertEqual(action, "forward")


def gated_log_lines():
    """Synthetic session log as gate mode would write it: a blocked call
    plus the injected error response, both carrying gate markers."""
    blocked = {"schema_version": "0.1", "seq": 6, "ts": "t6", "dir": "c2s",
               "frame": {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "shadow_tool", "arguments": {}}},
               "raw": None,
               "gate": {"action": "blocked", "tool": "shadow_tool",
                        "declared": ["web_search"]}}
    injected = {"schema_version": "0.1", "seq": 7, "ts": "t7", "dir": "s2c",
                "frame": {"jsonrpc": "2.0", "id": 3,
                          "error": {"code": -32000,
                                    "message": "glassport gate: blocked",
                                    "data": {"glassport": "gate_blocked",
                                             "tool": "shadow_tool"}}},
                "raw": None,
                "gate": {"action": "injected", "tool": "shadow_tool"}}
    return handshake() + [json.dumps(blocked), json.dumps(injected)]


class TestGateInTrace(unittest.TestCase):
    def test_adapter_carries_gate_metadata(self):
        trace = from_mcp_session(gated_log_lines())
        call_ev = next(e for e in trace.events
                       if e.kind == EventKind.TOOL_CALL)
        self.assertEqual(call_ev.metadata.get("gate", {}).get("action"),
                         "blocked")
        result_ev = next(e for e in trace.events
                         if e.kind == EventKind.TOOL_RESULT)
        self.assertEqual(result_ev.metadata.get("gate", {}).get("action"),
                         "injected")
        # the injected error still pairs to the blocked call
        self.assertEqual(result_ev.parent_event_id, call_ev.id)

    def test_gate_actions_detector_emits_info(self):
        trace = from_mcp_session(gated_log_lines())
        anns = detectors.gate_actions(trace)
        self.assertEqual([a.subcategory for a in anns],
                         ["gate_blocked", "gate_injected_response"])
        for a in anns:
            self.assertEqual(a.kind, AnnotationKind.INFO)
            self.assertEqual(a.severity, 1)

    def test_annotate_includes_gate_actions(self):
        trace = from_mcp_session(gated_log_lines())
        anns = detectors.annotate(trace)
        self.assertIn("gate_blocked", [a.subcategory for a in anns])

    def test_report_renders_gate_block_as_info(self):
        trace = from_mcp_session(gated_log_lines())
        detectors.annotate(trace)
        html = report_mod.render_html(trace, source_name="gated.jsonl")
        self.assertIn('data-kind="info"', html)
        self.assertIn("gate_blocked", html)


class TestGateEndToEnd(unittest.TestCase):
    def test_blocked_call_dies_at_the_glass(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = subprocess.Popen(
                [sys.executable, str(REPO / "glassport_tap.py"), "gate",
                 "--log-dir", tmp, "--",
                 sys.executable, str(REPO / "examples" / "fake_server.py")],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0)

            def ask(frame):
                child.stdin.write(line(frame))
                child.stdin.flush()
                return json.loads(child.stdout.readline())

            try:
                init = ask({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {}})
                self.assertIn("serverInfo", init["result"])
                listed = ask({"jsonrpc": "2.0", "id": 2,
                              "method": "tools/list"})
                self.assertEqual(listed["result"]["tools"][0]["name"],
                                 "web_search")

                # undeclared call: fake_server would happily answer it,
                # so any error here can only have come from the gate
                blocked = ask({"jsonrpc": "2.0", "id": 3,
                               "method": "tools/call",
                               "params": {"name": "shadow_tool",
                                          "arguments": {}}})
                self.assertEqual(blocked["error"]["data"]["glassport"],
                                 "gate_blocked")

                # declared call passes through untouched
                allowed = ask({"jsonrpc": "2.0", "id": 4,
                               "method": "tools/call",
                               "params": {"name": "web_search",
                                          "arguments": {"query": "x"}}})
                self.assertIn("ran web_search",
                              allowed["result"]["content"][0]["text"])
            finally:
                child.stdin.close()
                child.wait(timeout=10)

            log = next(Path(tmp).glob("*.jsonl")).read_text(encoding="utf-8")
            entries = [json.loads(l) for l in log.splitlines()]
            actions = [e["gate"]["action"] for e in entries if "gate" in e]
            self.assertEqual(actions, ["blocked", "injected"])
            # the blocked frame is logged but was never sent to the server:
            # the server's log lines contain no shadow_tool response
            server_lines = [e for e in entries
                            if e["dir"] == "s2c" and "gate" not in e]
            self.assertFalse(any("shadow_tool" in json.dumps(e)
                                 for e in server_lines))


if __name__ == "__main__":
    unittest.main()
