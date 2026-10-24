"""One upstream-receipt assertion for each enforcement-contract path."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from glassport import decision_journal as dj
from glassport import probe
from glassport.adapters.mcp_http import run_http_tap
from tests.test_http_gate import GateCase, Upstream


ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "tests" / "fixtures" / "counting_stdio_server.py"
CONTRACT = ROOT / "docs" / "enforcement-contract.md"


class TestStdioContract(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.received = self.root / "upstream.jsonl"
        self.server = [sys.executable, str(SERVER), str(self.received)]

    def _exchange(self, prefix, *, call=True):
        proc = subprocess.Popen([*prefix, *self.server], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                bufsize=0)
        try:
            def ask(rid, method, params=None):
                frame = {"jsonrpc": "2.0", "id": rid, "method": method}
                if params is not None:
                    frame["params"] = params
                proc.stdin.write((json.dumps(frame) + "\n").encode())
                proc.stdin.flush()
                return json.loads(proc.stdout.readline())

            ask(1, "initialize", {"protocolVersion": "2025-03-26",
                                  "capabilities": {},
                                  "clientInfo": {"name": "contract", "version": "1"}})
            ask(2, "tools/list")
            return ask(3, "tools/call", {"name": "ghost", "arguments": {}}) if call else None
        finally:
            proc.stdin.close()
            proc.wait(timeout=10)
            proc.stdout.close()
            proc.stderr.close()

    def _received(self):
        return [json.loads(line) for line in self.received.read_text().splitlines()] \
            if self.received.exists() else []

    def test_stdio_gate(self):
        reply = self._exchange([sys.executable, str(ROOT / "glassport_tap.py"),
                                "gate", "--log-dir", str(self.root / "logs"), "--"])
        self.assertEqual(reply["error"]["data"]["glassport"], "gate_blocked")
        self.assertEqual(self._received(), [])
        entries = [json.loads(line) for path in (self.root / "logs").glob("*.jsonl")
                   for line in path.read_text().splitlines()]
        self.assertIn("blocked_policy", [e.get("gate", {}).get("evidence_level")
                                         for e in entries])
        self.assertIn("forwarded", [e.get("gate", {}).get("evidence_level")
                                    for e in entries])

    def test_stdio_wrap(self):
        reply = self._exchange([sys.executable, str(ROOT / "glassport_tap.py"),
                                "wrap", "--log-dir", str(self.root / "logs"), "--"])
        self.assertIn("result", reply)
        self.assertEqual([x["name"] for x in self._received()], ["ghost"])

    def test_probe(self):
        result = probe.probe(self.server, log_dir=self.root / "logs",
                             startup_timeout=5, timeout=5)
        self.assertTrue(result.handshake["completed"])
        self.assertEqual(self._received(), [])

    def test_probe_call(self):
        result = probe.probe(self.server, calls=[("ghost", {})],
                             log_dir=self.root / "logs", startup_timeout=5, timeout=5)
        self.assertTrue(result.handshake["completed"])
        self.assertEqual([x["name"] for x in self._received()], ["ghost"])

    def test_direct_server(self):
        reply = self._exchange([])
        self.assertIn("result", reply)
        self.assertEqual([x["name"] for x in self._received()], ["ghost"])


class TestHttpContract(GateCase):
    def test_http_gate(self):
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call("ghost")
        self.assert_blocked(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent["evidence_level"], "blocked_policy")
        self.assertEqual(delivery["evidence_level"], "blocked_policy")

    def test_http_gate_strict(self):
        self.proxy(strict=True)
        self.handshake(declare=False)
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call("search")
        frame = json.loads(body)
        self.assertEqual(frame["error"]["data"], {
            "glassport": "http_gate_strict_blocked",
            "reason": "call_before_declaration"})
        self.quiesce()
        self.assertEqual(self.upstream_calls(), before,
                         "strict contract call reached upstream")
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent["evidence_level"], "blocked_evidence_gap")
        self.assertEqual(delivery["evidence_level"], "blocked_evidence_gap")

    def test_http_observe(self):
        self.proxy(mode=dj.MODE_OBSERVE)
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call("ghost")
        self.assert_forwarded(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent["evidence_level"], "intended_block")
        self.assertEqual(delivery["evidence_level"], "intended_block")

    def test_http_wrap(self):
        remote = self.upstream()
        ready, box = threading.Event(), []
        threading.Thread(target=run_http_tap,
                         args=(remote, self.root / "wire"),
                         kwargs={"ready": ready, "server_box": box},
                         daemon=True).start()
        self.assertTrue(ready.wait(5), "proxy did not bind")
        self.addCleanup(box[0].shutdown)
        self.url = f"http://127.0.0.1:{box[0].server_address[1]}/mcp"
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call("ghost")
        self.assert_forwarded(body, before)


class TestContractRowGuard(unittest.TestCase):
    def test_each_matrix_row_has_an_upstream_receipt_test(self):
        rows = set(re.findall(r"^\| `([a-z0-9-]+)` \|", CONTRACT.read_text(), re.M))
        expected = {
            "stdio-gate": TestStdioContract.test_stdio_gate,
            "http-gate": TestHttpContract.test_http_gate,
            "http-gate-strict": TestHttpContract.test_http_gate_strict,
            "stdio-wrap": TestStdioContract.test_stdio_wrap,
            "http-wrap": TestHttpContract.test_http_wrap,
            "observe": TestHttpContract.test_http_observe,
            "probe": TestStdioContract.test_probe,
            "probe-call": TestStdioContract.test_probe_call,
            "direct-server": TestStdioContract.test_direct_server,
        }
        self.assertEqual(rows, set(expected))
        self.assertEqual(len(set(expected.values())), len(expected))
