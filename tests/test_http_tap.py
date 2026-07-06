"""H2.01 streamable-HTTP tap — tests. A mock MCP remote runs in a background
thread; no real network. The proxy under test forwards client<->remote and
logs every JSON-RPC message into the same JSONL the stdio tap writes.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from glassport.adapters.mcp_http import run_http_tap
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.interaction_trace import EventKind


def _serve(handler_cls) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _start_proxy(remote_url: str, logdir: Path):
    ready = threading.Event()
    box: list = []
    t = threading.Thread(
        target=run_http_tap, args=(remote_url, logdir),
        kwargs={"ready": ready, "server_box": box}, daemon=True)
    t.start()
    assert ready.wait(5), "proxy did not bind"
    return box[0]


def _post(url: str, obj: dict) -> bytes:
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"})
    return urllib.request.urlopen(req, timeout=5).read()


class _JsonRemote(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "result": {"tools": [{"name": "search"}]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SseRemote(BaseHTTPRequestHandler):
    """Responds to a POST with an SSE stream of two JSON-RPC messages."""

    def log_message(self, *args, **kwargs):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for i in (1, 2):
            msg = json.dumps({"jsonrpc": "2.0", "id": i,
                              "result": {"n": i}}).encode()
            self.wfile.write(b"data: " + msg + b"\n\n")
            self.wfile.flush()


class TestHttpTapJson(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_post_round_trip_logs_both_directions(self):
        remote = _serve(_JsonRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
        ph, pp = proxy.server_address
        try:
            resp = json.loads(_post(f"http://{ph}:{pp}/mcp",
                                    {"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"}))
            self.assertIn("search", json.dumps(resp))  # remote's answer reached client
        finally:
            proxy.shutdown()
            remote.shutdown()

        logs = list(self.logdir.glob("*.jsonl"))
        self.assertTrue(logs, "no session log written")
        text = logs[0].read_text(encoding="utf-8")
        self.assertIn('"tools/list"', text)   # c2s captured
        self.assertIn('"search"', text)        # s2c captured

        trace = from_mcp_session_file(str(logs[0]))
        self.assertIn("search", trace.declared_tools())
        self.assertTrue(any(e.kind == EventKind.TOOL_RESULT for e in trace.events)
                        or trace.events)  # trace built from HTTP-captured frames


class TestHttpTapSse(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_sse_response_streamed_and_each_event_logged(self):
        remote = _serve(_SseRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
        ph, pp = proxy.server_address
        try:
            raw = _post(f"http://{ph}:{pp}/mcp",
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
            # both SSE events reached the client verbatim
            self.assertEqual(raw.count(b"data: "), 2)
        finally:
            proxy.shutdown()
            proxy.server_close()
            remote.shutdown()
            remote.server_close()

        logs = list(self.logdir.glob("*.jsonl"))
        text = logs[0].read_text(encoding="utf-8")
        # two s2c frames, one per SSE event (framed at the data: boundary)
        s2c = [ln for ln in text.splitlines() if '"dir": "s2c"' in ln]
        self.assertEqual(len(s2c), 2)
        self.assertIn('"n": 1', text)
        self.assertIn('"n": 2', text)


if __name__ == "__main__":
    unittest.main()
