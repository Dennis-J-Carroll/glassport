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

    def test_duplicate_identical_content_length_is_rejected(self):
        """RFC 7230 forbids multiple Content-Length headers regardless of value;
        accept-and-collapse is a request-smuggling footgun."""
        payload = (
            b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
            b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
        )
        resp = self._raw(payload)
        status = resp.split(b"\r\n", 1)[0] if resp else b""
        self.assertTrue(status.startswith(b"HTTP/1.1 4"),
                        "duplicate identical Content-Length was not rejected: %r" % status)


# ── response framing abuse (Kimi surface #1) ────────────────────────
class TestResponseFraming(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir, ignore_errors=True))

    def test_conflicting_response_content_length_drops_cl_and_closes(self):
        """A hostile upstream with two Content-Length values must not make the
        proxy promise a body length that exceeds the bytes it actually reads."""
        class _BadRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "5")
                self.send_header("Content-Length", "50")
                self.end_headers()
                self.wfile.write(b"hello")

        remote = _serve(_BadRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            data = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(data, b"hello")
        # Ambiguous framing -> Content-Length must not be forwarded;
        # close-delimit so the client reads exactly what the relay sent.
        self.assertIsNone(r.getheader("Content-Length"))
        self.assertEqual(r.getheader("Connection"), "close")

    def test_comma_folded_response_content_length_drops_cl_and_closes(self):
        """A single *comma-folded* Content-Length ("5, 50") is as ambiguous as
        two header lines (RFC 7230 §3.3.2). BaseHTTPRequestHandler always emits
        one line per send_header, so it can't reproduce this — a raw upstream
        socket can. Regression: the round-2 fix counted CL header *lines* and
        forwarded this verbatim, hanging the client."""
        rp_box: list = []
        ready = threading.Event()

        def raw_upstream():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            rp_box.append(s.getsockname()[1])
            ready.set()
            try:
                conn, _ = s.accept()
                conn.recv(65536)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 5, 50\r\n\r\nhello")
                # Clean half-close: send FIN so the proxy reads "hello" then a
                # graceful EOF, then drain until the proxy closes — closing with
                # unread inbound data would RST and race the proxy's read.
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(3)
                try:
                    while conn.recv(4096):
                        pass
                except OSError:
                    pass
                conn.close()
            finally:
                s.close()

        t = threading.Thread(target=raw_upstream, daemon=True)
        t.start()
        ready.wait(5)
        proxy = _start_proxy(f"http://127.0.0.1:{rp_box[0]}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            data = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            t.join(2)

        self.assertEqual(data, b"hello")
        self.assertIsNone(r.getheader("Content-Length"))
        self.assertEqual(r.getheader("Connection"), "close")

    def test_lying_short_content_length_forces_close(self):
        """A hostile upstream that declares Content-Length larger than the body
        it sends, then closes, must not make the client hang forever on a
        kept-alive socket. The proxy can't verify the length before sending
        headers (that would need to buffer the whole body — the R1 DoS), but once
        the stream ends short it closes the connection so the client gets a
        prompt EOF. Regression: the proxy used to keep the socket open and the
        client blocked until its own timeout."""
        rp_box: list = []
        ready = threading.Event()

        def raw_upstream():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            rp_box.append(s.getsockname()[1])
            ready.set()
            try:
                conn, _ = s.accept()
                conn.recv(65536)
                # Declares 100 bytes, sends 5, then closes.
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: 100\r\n\r\nhello")
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(3)
                try:
                    while conn.recv(4096):
                        pass
                except OSError:
                    pass
                conn.close()
            finally:
                s.close()

        t = threading.Thread(target=raw_upstream, daemon=True)
        t.start()
        ready.wait(5)
        proxy = _start_proxy(f"http://127.0.0.1:{rp_box[0]}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            # The upstream lied: 100 promised, 5 delivered, then EOF. A prompt
            # IncompleteRead (not a hang to the 5s timeout) proves the proxy
            # closed. The relay stays sacred: the 5 real bytes still arrived.
            with self.assertRaises(http.client.IncompleteRead) as cm:
                r.read()
            self.assertEqual(cm.exception.partial, b"hello")
        finally:
            c.close()
            proxy.shutdown(); proxy.server_close()
            t.join(2)

    def test_chunked_upstream_reaches_client_dechunked(self):
        """A chunked upstream response must reach the client as clean de-chunked
        bytes with no Transfer-Encoding header and no leaked chunk-size markers.
        http.client de-chunks on read; the proxy strips TE (a _HOP header)."""
        rp_box: list = []
        ready = threading.Event()

        def raw_upstream():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            rp_box.append(s.getsockname()[1])
            ready.set()
            try:
                conn, _ = s.accept()
                conn.recv(65536)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Transfer-Encoding: chunked\r\n\r\n"
                             b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(3)
                try:
                    while conn.recv(4096):
                        pass
                except OSError:
                    pass
                conn.close()
            finally:
                s.close()

        t = threading.Thread(target=raw_upstream, daemon=True)
        t.start()
        ready.wait(5)
        proxy = _start_proxy(f"http://127.0.0.1:{rp_box[0]}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            data = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            t.join(2)

        self.assertEqual(data, b"helloworld")
        self.assertIsNone(r.getheader("Transfer-Encoding"))

    def test_sse_response_is_close_delimited(self):
        """An SSE response carries no Content-Length and the proxy strips the
        upstream's Transfer-Encoding, so the only honest framing is close-delimit.
        The proxy must mark the connection to close; when the upstream ends the
        stream the client gets a prompt EOF, not a hang on a kept-alive socket.
        Regression: the SSE branch set no framing and the client blocked to its
        own timeout."""
        class _SSERemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"data: hello\n\ndata: world\n\n")

        remote = _serve(_SSERemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()          # Connection: close → reads to EOF, no hang
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(r.getheader("Connection"), "close")
        self.assertEqual(body, b"data: hello\n\ndata: world\n\n")

    def test_content_type_substring_does_not_flip_to_sse(self):
        """A non-SSE body whose Content-Type merely *contains* the SSE token in a
        parameter ('application/json; note=text/event-stream') must stay on the
        non-SSE path: its Content-Length is preserved and the body is delivered
        intact. Regression: a substring match reframed it as SSE and dropped CL."""
        class _FlipRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                body = b'{"ok":"data"}'
                self.send_response(200)
                self.send_header("Content-Type",
                                 "application/json; note=text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        remote = _serve(_FlipRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(body, b'{"ok":"data"}')
        self.assertEqual(r.getheader("Content-Length"), "13")

    def test_oversized_sse_event_is_memory_bounded(self):
        """A hostile SSE stream that never sends an event terminator must reach
        the client in full (relay is sacred) while the session log stays bounded:
        _MAX_SSE_BUF caps buffering and a single drop-note replaces the runaway."""
        payload = b"A" * (512 * 1024)   # over _MAX_SSE_BUF (256 KB), no terminator

        class _FloodRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"data: " + payload)
                self.wfile.flush()

        remote = _serve(_FloodRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=8)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(len(body), len(payload) + len(b"data: "))   # relay sacred
        log_size = sum(f.stat().st_size for f in self.logdir.rglob("*_http_*.jsonl"))
        self.assertLess(log_size, 1_000_000, "runaway SSE was not memory-bounded")

    def test_1xx_processing_response_is_skipped(self):
        """A 1xx informational response (e.g., 102 Processing) before the final
        reply must not be forwarded to the client as the final answer."""
        rp_box: list = []
        ready = threading.Event()

        def raw_upstream():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            rp_box.append(s.getsockname()[1])
            ready.set()
            try:
                conn, _ = s.accept()
                conn.recv(65536)
                conn.sendall(
                    b"HTTP/1.1 102 Processing\r\n\r\n"
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 15\r\n\r\n"
                    b"{\"result\":true}")
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(3)
                try:
                    while conn.recv(4096):
                        pass
                except OSError:
                    pass
                conn.close()
            finally:
                s.close()

        t = threading.Thread(target=raw_upstream, daemon=True)
        t.start()
        ready.wait(5)
        proxy = _start_proxy(f"http://127.0.0.1:{rp_box[0]}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            data = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            t.join(2)

        self.assertEqual(r.status, 200)
        self.assertEqual(data, b'{"result":true}')

    def _raw_upstream_then_client(self, raw_response: bytes):
        """Serve one raw HTTP response, drive one client POST, return the
        client HTTPResponse status and body (with a timeout so a hang fails
        the test rather than blocking forever)."""
        rp_box: list = []
        ready = threading.Event()

        def raw_upstream():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0)); s.listen(1)
            rp_box.append(s.getsockname()[1]); ready.set()
            try:
                conn, _ = s.accept()
                conn.recv(65536)
                conn.sendall(raw_response)
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(3)
                try:
                    while conn.recv(4096):
                        pass
                except OSError:
                    pass
                conn.close()
            finally:
                s.close()

        t = threading.Thread(target=raw_upstream, daemon=True)
        t.start(); ready.wait(5)
        proxy = _start_proxy(f"http://127.0.0.1:{rp_box[0]}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            status = r.status
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            t.join(2)
        return status, body

    def test_101_switching_protocols_becomes_502_not_a_hang(self):
        """A hostile 101 re-tasks the connection; the bytes after it are not
        HTTP. The proxy must refuse (502), never echo the upgraded bytes and
        never hang trying to parse them as a status line."""
        status, body = self._raw_upstream_then_client(
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
            b"\x00\x01\x02not-http-garbage\xff\xfe")
        self.assertEqual(status, 502)
        self.assertNotIn(b"not-http-garbage", body)

    def test_stacked_103_early_hints_then_final(self):
        """Multiple 103 Early Hints before the final 200 are all skipped."""
        status, body = self._raw_upstream_then_client(
            b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n"
            b"HTTP/1.1 103 Early Hints\r\nLink: </t.css>\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 15\r\n\r\n{\"result\":true}")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"result":true}')

    def test_1xx_with_unbounded_header_block_fails_bounded(self):
        """A 1xx whose header block never ends must fail bounded (502), not pin
        the handler thread streaming fake headers."""
        flood = b"HTTP/1.1 102 Processing\r\n" + b"X-Pad: y\r\n" * 5000 + b"\r\n"
        status, _ = self._raw_upstream_then_client(flood)
        self.assertEqual(status, 502)

    def test_duplicate_content_type_does_not_flip_to_sse(self):
        """An upstream that emits two Content-Type headers cannot trick the
        proxy into treating a JSON body as SSE (which would drop CL)."""
        class _DupCTRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                body = b'{"ok":"data"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        remote = _serve(_DupCTRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(body, b'{"ok":"data"}')
        self.assertEqual(r.getheader("Content-Length"), "13")
        # Ambiguous CT -> non-streaming, so no forced close.
        self.assertNotEqual(r.getheader("Connection"), "close")

    def test_204_drops_content_length_and_closes(self):
        """A 204/304 response is bodiless; a hostile Content-Length must not be
        forwarded and the connection must close-delimit cleanly."""
        rp_box: list = []
        ready = threading.Event()

        def raw_upstream():
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            rp_box.append(s.getsockname()[1])
            ready.set()
            try:
                conn, _ = s.accept()
                conn.recv(65536)
                conn.sendall(
                    b"HTTP/1.1 204 No Content\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 5\r\n\r\n")
                conn.shutdown(socket.SHUT_WR)
                conn.settimeout(3)
                try:
                    while conn.recv(4096):
                        pass
                except OSError:
                    pass
                conn.close()
            finally:
                s.close()

        t = threading.Thread(target=raw_upstream, daemon=True)
        t.start()
        ready.wait(5)
        proxy = _start_proxy(f"http://127.0.0.1:{rp_box[0]}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=5)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            data = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            t.join(2)

        self.assertEqual(r.status, 204)
        self.assertEqual(data, b"")
        self.assertIsNone(r.getheader("Content-Length"))
        self.assertEqual(r.getheader("Connection"), "close")


# ── SSE residue (surface #4) ───────────────────────────────────────
class TestSseResidue(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir, ignore_errors=True))

    def _log_text(self):
        paths = list(self.logdir.rglob("*_http_*.jsonl"))
        if not paths:
            return ""
        return paths[0].read_text(encoding="utf-8", errors="replace")

    def test_terminated_oversized_sse_event_is_dropped(self):
        """A terminated SSE event larger than _MAX_SSE_BUF must reach the client
        in full but must not be logged whole; a drop-note replaces it."""
        payload = b"A" * (512 * 1024)  # over _MAX_SSE_BUF (256 KB)

        class _FloodRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"data: " + payload + b"\n\n")

        remote = _serve(_FloodRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=10)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(len(body), len(payload) + len(b"data: ") + 2)
        log = self._log_text()
        self.assertIn("sse_frame_dropped_oversize", log)
        self.assertNotIn(payload.decode(), log)
        self.assertLess(len(log), 1_000_000)

    def test_terminated_oversized_sse_event_with_metadata_is_dropped(self):
        """Metadata fields do not exempt a huge event from the log cap."""
        payload = b"A" * (512 * 1024)

        class _FloodRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"event: big\ndata: " + payload + b"\n\n")

        remote = _serve(_FloodRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=10)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        self.assertEqual(len(body), len(payload) + len(b"event: big\ndata: ") + 2)
        log = self._log_text()
        self.assertIn("sse_frame_dropped_oversize", log)
        self.assertNotIn(payload.decode(), log)
        self.assertLess(len(log), 1_000_000)

    def test_interleaved_flood_does_not_log_partial_tails(self):
        """A stream of terminated oversized events interleaved with tiny valid
        events must emit one drop-note per oversized event (not one per chunk)
        and must log the valid events; partial tails of the oversized events
        must never be logged as if they were complete frames."""
        payload = b"A" * (300 * 1024)  # over _MAX_SSE_BUF, terminated

        class _InterleaveRemote(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                self.rfile.read(n)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.write(b"data: ok\n\n")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()

        remote = _serve(_InterleaveRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/", self.logdir)
        ph, pp = proxy.server_address
        try:
            c = http.client.HTTPConnection(ph, pp, timeout=10)
            c.request("POST", "/mcp", body=b'{}')
            r = c.getresponse()
            body = r.read()
            c.close()
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        # Client sees everything.
        self.assertIn(b"data: ok\n\n", body)
        log = self._log_text()
        # Exactly two drop notes (one per oversized event), and the valid event.
        self.assertEqual(log.count("sse_frame_dropped_oversize"), 2)
        self.assertIn("ok", log)
        # The flood payload must not appear as a logged frame.
        self.assertNotIn(payload.decode(), log)
        self.assertLess(len(log), 1_000_000)


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


class TestConnectionNominatedHops(unittest.TestCase):
    def test_connection_nominated_header_is_dropped(self):
        from glassport.adapters import mcp_http
        pairs = [("Connection", "keep-alive, X-Internal-Hop"),
                 ("X-Internal-Hop", "secret"), ("X-Keep", "ok")]
        drop = mcp_http._hop_headers(pairs)
        self.assertIn("x-internal-hop", drop)   # nominated → dropped
        self.assertIn("connection", drop)       # static _HOP member
        self.assertNotIn("x-keep", drop)        # ordinary header survives

    def test_multiple_connection_headers_all_parsed(self):
        from glassport.adapters import mcp_http
        pairs = [("Connection", "Foo"), ("Connection", "Bar, Baz")]
        drop = mcp_http._hop_headers(pairs)
        self.assertTrue({"foo", "bar", "baz"} <= drop)

    def test_static_hop_set_still_present_with_no_connection(self):
        from glassport.adapters import mcp_http
        drop = mcp_http._hop_headers([("Content-Type", "application/json")])
        self.assertEqual(drop, set(mcp_http._HOP))


class TestNoPrivateStdlibSymbols(unittest.TestCase):
    """H1 — the 1xx handler must not depend on nonpublic http.client symbols,
    which "may change" across the 3.10–3.13 matrix. Lock that in source."""

    def test_mcp_http_uses_no_private_http_client_symbols(self):
        import glassport.adapters.mcp_http as m
        src = Path(m.__file__).read_text(encoding="utf-8")
        # strip comments so a mention in prose doesn't trip the check
        code = "\n".join(ln.split("#", 1)[0] for ln in src.splitlines())
        for forbidden in ("http.client._read_headers", "http.client._MAXLINE",
                          "._MAXLINE"):
            self.assertNotIn(forbidden, code,
                             f"private stdlib symbol {forbidden!r} in mcp_http.py")


if __name__ == "__main__":
    unittest.main()
