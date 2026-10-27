"""
Tests for `glassport probe` — the one-command client that drives a server
through the tap and renders a report, including a *partial* one when the
handshake never completes.

A tiny fake MCP server (below) runs as a real subprocess behind the real
tap, so these cover the spawn → handshake → log → report path end to end
without npx or network. Pure stdlib.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from glassport import probe as probe_mod
from glassport.report import render_html
from glassport.interaction_trace import (
    Annotation, AnnotationKind, InteractionTrace, ProtocolKind,
)

FAKE_SERVER = r'''
import json, os, sys, time
mode = sys.argv[1]
if len(sys.argv) > 2:   # side channel for the test: pid + inherited env
    with open(sys.argv[2], "w") as f:
        json.dump({"pid": os.getpid(),
                   "pythonpath": os.environ.get("PYTHONPATH")}, f)
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    msg = json.loads(line)
    rid, method = msg.get("id"), msg.get("method")
    if mode == "die_on_init":
        sys.exit(1)
    if method == "initialize":
        if mode == "init_error":
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32603, "message": "missing API key"}})
            continue
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake", "version": "0"}}})
    elif method == "tools/list":
        if mode == "hang_list":
            time.sleep(60)
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": "echo", "description": "echo text",
             "inputSchema": {"type": "object",
                             "properties": {"text": {"type": "string"}}}}]}})
    elif method == "tools/call":
        name = msg["params"]["name"]
        if name != "echo":
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32602, "message": "unknown tool"}})
        else:
            send({"jsonrpc": "2.0", "id": rid, "result": {"content": [
                {"type": "text",
                 "text": msg["params"]["arguments"].get("text", "")}]}})
'''


class _FakeServer:
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.server = Path(cls._tmp.name) / "fake_server.py"
        cls.server.write_text(FAKE_SERVER, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self._logs = tempfile.TemporaryDirectory()
        self.log_dir = Path(self._logs.name)

    def tearDown(self):
        self._logs.cleanup()

    def cmd(self, mode, *extra):
        return [sys.executable, str(self.server), mode, *extra]

    def run_probe(self, mode, **kw):
        kw.setdefault("startup_timeout", 15)
        kw.setdefault("timeout", 5)
        return probe_mod.probe(self.cmd(mode), log_dir=self.log_dir, **kw)


class TestProbeHandshake(_FakeServer, unittest.TestCase):

    def test_complete_handshake_renders_full_report(self):
        res = self.run_probe("ok")
        self.assertTrue(res.handshake["completed"])
        self.assertIsNone(res.handshake["failed_at"])
        self.assertEqual(res.declared_tools, ["echo"])
        self.assertEqual(res.exit_code, 0)
        html = res.report_path.read_text(encoding="utf-8")
        self.assertIn("CLEAN", html)
        self.assertNotIn("INCOMPLETE", html)

    def test_list_only_is_the_default(self):
        res = self.run_probe("ok")
        self.assertEqual(res.called_tools, [])

    def test_declared_call_is_exercised(self):
        res = self.run_probe("ok", calls=[("echo", {"text": "hi"})])
        self.assertTrue(res.handshake["completed"])
        self.assertEqual(res.called_tools, ["echo"])
        self.assertEqual(res.exit_code, 0)

    def test_undeclared_call_is_a_finding_not_an_incomplete_handshake(self):
        # the server answered (with an error) — the handshake is complete;
        # calling outside the declared surface is the detectors' business
        res = self.run_probe("ok", calls=[("ghost", {})])
        self.assertTrue(res.handshake["completed"])
        self.assertEqual(res.exit_code, 1)

    def test_server_dies_on_initialize_yields_partial_report(self):
        res = self.run_probe("die_on_init")
        self.assertFalse(res.handshake["completed"])
        self.assertEqual(res.handshake["failed_at"], "initialize")
        self.assertEqual(res.handshake["reason"], "exited")
        self.assertEqual(res.exit_code, 3)
        html = res.report_path.read_text(encoding="utf-8")
        self.assertIn("INCOMPLETE", html)
        self.assertNotIn("CLEAN", html)

    def test_initialize_error_is_incomplete(self):
        res = self.run_probe("init_error")
        self.assertEqual(res.handshake["failed_at"], "initialize")
        self.assertEqual(res.handshake["reason"], "error_response")
        self.assertEqual(res.exit_code, 3)

    def test_hanging_server_is_killed_and_marked_incomplete(self):
        side = self.log_dir / "side.json"
        t0 = time.monotonic()
        res = probe_mod.probe(self.cmd("hang_list", str(side)),
                              log_dir=self.log_dir, startup_timeout=15,
                              timeout=1)
        self.assertLess(time.monotonic() - t0, 15)
        self.assertEqual(res.handshake["failed_at"], "tools_list")
        self.assertEqual(res.handshake["reason"], "timeout")
        self.assertEqual(res.exit_code, 3)
        if os.name == "posix":
            # the server itself, not just the tap, must be gone
            pid = json.loads(side.read_text())["pid"]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                os.kill(pid, 9)
                self.fail("server outlived the probe")

    def test_server_env_is_not_altered(self):
        # the session must be what `wrap` records: probe may not inject
        # its own package path into the server's environment
        side = self.log_dir / "side.json"
        probe_mod.probe(self.cmd("ok", str(side)), log_dir=self.log_dir,
                        startup_timeout=15, timeout=5)
        self.assertEqual(json.loads(side.read_text())["pythonpath"],
                         os.environ.get("PYTHONPATH"))

    def test_ignores_other_sessions_in_a_shared_log_dir(self):
        decoy = self.log_dir / "29991231T000000Z_other_1.jsonl"
        decoy.write_text("", encoding="utf-8")
        res = self.run_probe("ok")
        self.assertNotEqual(res.log_path, decoy)
        self.assertEqual(res.declared_tools, ["echo"])

    def test_missing_command_fails_at_spawn(self):
        res = probe_mod.probe(["glassport-no-such-binary-xyz"],
                              log_dir=self.log_dir, startup_timeout=10)
        self.assertEqual(res.handshake["failed_at"], "spawn")
        self.assertEqual(res.exit_code, 3)


class TestProbeCli(_FakeServer, unittest.TestCase):

    def test_json_output_carries_handshake(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = probe_mod.main(["--json", "--log-dir", str(self.log_dir),
                                 "--timeout", "5", "--", *self.cmd("ok")])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertTrue(out["handshake"]["completed"])
        self.assertTrue(Path(out["report"]).exists())

    def test_call_flag_parses_json_arguments(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = probe_mod.main(["--json", "--log-dir", str(self.log_dir),
                                 "--call", "echo", '{"text": "hi"}',
                                 "--", *self.cmd("ok")])
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(json.loads(buf.getvalue())["called"], ["echo"])

    def test_usage_errors_exit_2(self):
        for argv in ([], ["--json"], ["--call", "echo", "{bad", "--", "x"],
                     ["--timeout", "nope", "--", "x"]):
            with self.subTest(argv=argv), redirect_stdout(io.StringIO()):
                self.assertEqual(probe_mod.main(argv), 2)


class TestIncompleteVerdict(unittest.TestCase):
    """render_html: an incomplete handshake must never read as complete."""

    def trace(self, handshake, severities=()):
        t = InteractionTrace(id="t", protocol=ProtocolKind.AGENT_TOOL,
                             actors=[], events=[])
        t.metadata["handshake"] = handshake
        for s in severities:
            t.annotations.append(Annotation(
                id=f"a{len(t.annotations)}", event_id="", kind=AnnotationKind.ANOMALY,
                subcategory="x", explanation="x", severity=s))
        return t

    def test_incomplete_with_no_findings_never_says_clean(self):
        html = render_html(self.trace({"completed": False,
                                       "failed_at": "tools_list"}))
        self.assertIn("INCOMPLETE", html)
        self.assertIn("tools_list", html)
        self.assertNotIn("CLEAN", html)

    def test_incomplete_headline_precedes_hostile(self):
        html = render_html(self.trace({"completed": False,
                                       "failed_at": "call"}, [3]))
        self.assertIn("HOSTILE", html)
        self.assertLess(html.index("INCOMPLETE"), html.index("HOSTILE"))

    def test_unknown_stage_is_not_echoed(self):
        html = render_html(self.trace({"completed": False,
                                       "failed_at": "<script>x</script>"}))
        self.assertIn("INCOMPLETE", html)
        self.assertNotIn("<script>x", html)

    def test_complete_handshake_unchanged(self):
        html = render_html(self.trace({"completed": True, "failed_at": None}))
        self.assertIn("CLEAN", html)
        self.assertNotIn("INCOMPLETE", html)


if __name__ == "__main__":
    unittest.main()
