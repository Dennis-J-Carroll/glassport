"""Regression locks for the round-2 red-team of the HTTP relay path.

Targets three defects in `adapters/mcp_http.py::_relay` that the SSE round
(PR #52) left unprobed:

  R1 — unbounded response/request copy (memory + disk DoS)
  R2 — request smuggling via ambiguous framing (Transfer-Encoding / dup CL)
  R3 — no handler socket timeout (slowloris pins a thread)

The relay is sacred: every byte must still reach the client. What these lock is
that glassport cannot be made to buffer an unbounded body, forward a body it
framed differently from the upstream, or pin a worker thread forever.
"""

from __future__ import annotations

import http.client
import shutil
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from glassport.adapters.mcp_http import _make_handler, run_http_tap
from glassport.tap import SessionLog


# ── infra ──────────────────────────────────────────────────────────
def _serve(handler_cls) -> ThreadingHTTPServer:
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def _start_proxy(remote_url: str, logdir: Path) -> ThreadingHTTPServer:
    box: list = []
    ev = threading.Event()
    threading.Thread(
        target=run_http_tap, args=(remote_url, logdir),
        kwargs={"ready": ev, "server_box": box}, daemon=True).start()
    ev.wait(5)
    return box[0]


class _BigRemote(BaseHTTPRequestHandler):
    """Answers any POST with a large non-SSE body — a hostile upstream."""
    SIZE = 4 * 1024 * 1024

    def log_message(self, *a, **k):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        body = b"A" * self.SIZE
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CountingRemote(BaseHTTPRequestHandler):
    """Records every request target it is asked to serve."""
    paths: list = []

    def log_message(self, *a, **k):
        pass

    def _handle(self):
        type(self).paths.append(self.path)
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = _handle
    do_GET = _handle


# ── R1 · unbounded copy ────────────────────────────────────────────
class TestUnboundedResponse(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir, ignore_errors=True))

    def test_huge_response_reaches_client_whole_but_log_stays_bounded(self):
        remote = _serve(_BigRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=30)
            c.request("POST", "/mcp",
                      body=b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}')
            r = c.getresponse()
            data = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        # relay is sacred: the client received every byte
        self.assertEqual(len(data), _BigRemote.SIZE)
        # but the session log must NOT contain the whole 4 MiB body
        logs = list(self.logdir.glob("*.jsonl"))
        self.assertTrue(logs)
        self.assertLess(logs[0].stat().st_size, 1_500_000,
                        "log grew with the hostile response body")


# ── R2 · request smuggling ─────────────────────────────────────────
class TestRequestSmuggling(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir, ignore_errors=True))
        _CountingRemote.paths = []

    def _raw(self, payload: bytes) -> bytes:
        remote = _serve(_CountingRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            s = socket.create_connection((ph, pp), timeout=5)
            s.sendall(payload)
            s.settimeout(5)
            chunks = b""
            try:
                while True:
                    b = s.recv(4096)
                    if not b:
                        break
                    chunks += b
            except socket.timeout:
                pass
            s.close()
            return chunks
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

    def test_chunked_request_without_content_length_is_rejected(self):
        payload = (
            b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
            b"POST /smuggled HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        )
        resp = self._raw(payload)
        self.assertIn(b"400", resp.split(b"\r\n", 1)[0])
        # the smuggled second request must never reach the upstream
        self.assertNotIn("/smuggled", _CountingRemote.paths)

    def test_duplicate_conflicting_content_length_is_rejected(self):
        payload = (
            b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
            b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
        )
        resp = self._raw(payload)
        status = resp.split(b"\r\n", 1)[0] if resp else b""
        self.assertTrue(status.startswith(b"HTTP/1.1 4"),
                        "conflicting Content-Length was not rejected: %r" % status)


# ── R3 · slowloris / thread survival ───────────────────────────────
class TestHandlerTimeoutAndSurvival(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir, ignore_errors=True))

    def test_handler_defines_a_socket_timeout(self):
        log = SessionLog(self.logdir / "t.jsonl")
        cls = _make_handler(urlsplit("http://127.0.0.1:1/"), log)
        log.close()
        self.assertIsNotNone(getattr(cls, "timeout", None),
                             "no socket timeout: a slow client can pin a thread")

    def test_server_survives_a_client_that_aborts_midrequest(self):
        remote = _serve(_CountingRemote)
        _CountingRemote.paths = []
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            # open, promise a body, send a fragment, then vanish
            s = socket.create_connection((ph, pp), timeout=5)
            s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
                      b"Content-Length: 1000\r\n\r\npartial")
            s.close()
            # a normal request on a fresh connection must still be served
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp",
                      body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
            r = c.getresponse()
            status = r.status
            r.read(); c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
