"""HTTP relay red-team grill (round 2).

Runs the real `glassport.adapters.mcp_http.run_http_tap` against hostile clients
and upstreams, asserting the relay stays sacred while glassport cannot be made to
buffer an unbounded body, forward a body it framed differently from the upstream,
or pin a worker thread. No live network is used.

Run: PYTHONPATH=src python dogfood/eval_http_relay_redteam.py
"""
from __future__ import annotations

import http.client
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from glassport.adapters.mcp_http import _make_handler, run_http_tap
from glassport.tap import SessionLog

LOG_DIR = "dogfood/logs/http-relay-redteam"
FINDINGS = "dogfood/findings/http-relay-redteam.md"


def _serve(handler_cls) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _start_tap(remote_url: str):
    log_dir = Path(LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    for old in log_dir.glob("*_http_*.jsonl"):
        old.unlink()
    ready = threading.Event()
    box: list = []
    threading.Thread(
        target=run_http_tap, args=(remote_url, log_dir),
        kwargs={"ready": ready, "server_box": box}, daemon=True).start()
    ready.wait(5.0)
    if not box:
        raise RuntimeError("http tap failed to start")
    return box[0], box[0].server_address[1], log_dir


# ── R1 · unbounded response copy ───────────────────────────────────
def r1_unbounded_response() -> tuple[bool, str]:
    SIZE = 4 * 1024 * 1024

    class Big(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            body = b"A" * SIZE
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    remote = _serve(Big)
    rp = remote.server_address[1]
    tap, tp, log_dir = _start_tap(f"http://127.0.0.1:{rp}/mcp")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=30)
        c.request("POST", "/mcp", body=b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}')
        got = len(c.getresponse().read())
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    logs = list(log_dir.glob("*_http_*.jsonl"))
    log_size = logs[0].stat().st_size if logs else 0
    ok = got == SIZE and log_size < 1_500_000
    return ok, f"client_recv={got} of {SIZE}, log_size={log_size} (bounded={log_size < 1_500_000})"


# ── R2 · request smuggling ─────────────────────────────────────────
class _Counting(BaseHTTPRequestHandler):
    paths: list = []

    def log_message(self, *a):
        pass

    def _h(self):
        type(self).paths.append(self.path)
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = _h
    do_GET = _h


def _raw(payload: bytes):
    _Counting.paths = []
    remote = _serve(_Counting)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        s = socket.create_connection(("127.0.0.1", tp), timeout=5)
        s.sendall(payload); s.settimeout(5)
        buf = b""
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                buf += b
        except socket.timeout:
            pass
        s.close()
        return buf, list(_Counting.paths)
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()


def r2_chunked_smuggling() -> tuple[bool, str]:
    resp, paths = _raw(
        b"POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
        b"POST /smuggled HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    status = resp.split(b"\r\n", 1)[0] if resp else b""
    ok = status.startswith(b"HTTP/1.1 400") and "/smuggled" not in paths
    return ok, f"status={status!r}, upstream_saw={paths}"


def r2_duplicate_content_length() -> tuple[bool, str]:
    resp, _ = _raw(
        b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello")
    status = resp.split(b"\r\n", 1)[0] if resp else b""
    ok = status.startswith(b"HTTP/1.1 4")
    return ok, f"status={status!r}"


# ── response framing abuse (Kimi surface #1) ────────────────────────
def rf_response_conflicting_content_length() -> tuple[bool, str]:
    class Bad(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "5")
            self.send_header("Content-Length", "50")
            self.end_headers()
            self.wfile.write(b"hello")

    remote = _serve(Bad)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = data == b"hello" and r.getheader("Content-Length") is None and r.getheader("Connection") == "close"
    return ok, f"client_recv={data!r}, cl={r.getheader('Content-Length')!r}, conn={r.getheader('Connection')!r}"


def rf_comma_folded_content_length() -> tuple[bool, str]:
    """A single comma-folded Content-Length ('5, 50') is as ambiguous as two
    header lines. send_header can't emit it, so drive a raw upstream socket.
    Round-2 fix counted CL *lines* and forwarded this verbatim → client hang."""
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
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Content-Length: 5, 50\r\n\r\nhello")
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
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp_box[0]}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = data == b"hello" and r.getheader("Content-Length") is None and r.getheader("Connection") == "close"
    return ok, f"client_recv={data!r}, cl={r.getheader('Content-Length')!r}, conn={r.getheader('Connection')!r}"


def _serve_raw(raw_response: bytes) -> tuple[int, threading.Thread]:
    """Serve one hostile raw HTTP response a BaseHTTPRequestHandler can't emit
    (bare LF, comma-folded headers, lying Content-Length). Half-closes cleanly
    so the proxy reads a graceful EOF rather than racing a RST."""
    rp_box: list = []
    ready = threading.Event()

    def upstream():
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

    t = threading.Thread(target=upstream, daemon=True)
    t.start(); ready.wait(5)
    return rp_box[0], t


def rf_lying_short_content_length() -> tuple[bool, str]:
    """A hostile upstream declares Content-Length 100, sends 5 bytes, closes.
    The proxy can't verify the length before sending headers (buffering the whole
    body would be the R1 DoS), but once the stream ends short it must close the
    connection so the client gets a prompt EOF instead of hanging forever."""
    rp, t = _serve_raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                       b"Content-Length: 100\r\n\r\nhello")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    hung = False
    partial = b""
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=4)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        try:
            r.read()
        except http.client.IncompleteRead as exc:
            partial = exc.partial          # prompt short-read: the fix worked
        except (TimeoutError, socket.timeout):
            hung = True                     # proxy held the socket open (the bug)
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = (not hung) and partial == b"hello"
    return ok, f"hung={hung}, partial={partial!r}"


def rf_bare_lf_header_smuggling() -> tuple[bool, str]:
    """Bare-LF header smuggling: the upstream tries to inject a second
    Content-Length via a bare LF ('X-Evil: a\\nContent-Length: 9999'). http.client
    normalizes framing on read, so the proxy sees two CLs and the dedup guard
    drops CL + close-delimits. Proves a bare LF can't smuggle a desyncing length
    past the relay."""
    rp, t = _serve_raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                       b"Content-Length: 5\r\nX-Evil: a\nContent-Length: 9999\r\n\r\nhello")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = data == b"hello" and r.getheader("Content-Length") is None
    return ok, f"client_recv={data!r}, cl={r.getheader('Content-Length')!r}"


def rf_chunked_upstream_dechunked() -> tuple[bool, str]:
    """A chunked upstream response must reach the client as clean de-chunked
    bytes, never raw chunk-size markers. The proxy strips Transfer-Encoding (a
    _HOP header) and http.client de-chunks on read; the client sees the payload
    with no TE header and no leaked '5\\r\\n' framing."""
    rp, t = _serve_raw(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                       b"Transfer-Encoding: chunked\r\n\r\n"
                       b"5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = data == b"helloworld" and r.getheader("Transfer-Encoding") is None
    return ok, f"client_recv={data!r}, te={r.getheader('Transfer-Encoding')!r}"


def rf_sse_close_delimited() -> tuple[bool, str]:
    """An SSE response has no Content-Length and the proxy strips Transfer-Encoding,
    so the proxy must close-delimit: mark Connection: close so the client gets a
    prompt EOF when the upstream ends the stream instead of hanging on keep-alive."""
    class SSE(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: hello\n\ndata: world\n\n")

    remote = _serve(SSE)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=4)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        body = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = body == b"data: hello\n\ndata: world\n\n" and r.getheader("Connection") == "close"
    return ok, f"client_recv={body!r}, conn={r.getheader('Connection')!r}"


def rf_content_type_no_sse_flip() -> tuple[bool, str]:
    """A non-SSE body whose Content-Type merely contains the SSE token in a
    parameter must not flip to the SSE path (which drops Content-Length). Media
    type is matched, not any substring; CL is preserved, body intact."""
    class Flip(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            body = b'{"ok":"data"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; note=text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    remote = _serve(Flip)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=4)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        body = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = body == b'{"ok":"data"}' and r.getheader("Content-Length") == "13"
    return ok, f"client_recv={body!r}, cl={r.getheader('Content-Length')!r}"


def rf_sse_oversized_event_bounded() -> tuple[bool, str]:
    """A hostile SSE stream that never sends an event terminator must reach the
    client in full (the relay is sacred) while the session log stays bounded —
    _MAX_SSE_BUF caps buffering and one drop-note replaces the runaway."""
    payload = b"A" * (2 * 1024 * 1024)   # 2 MB, no \n\n terminator

    class Flood(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: " + payload)
            self.wfile.flush()

    remote = _serve(Flood)
    rp = remote.server_address[1]
    tap, tp, logdir = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=8)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        body = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    log_size = sum(f.stat().st_size for f in Path(logdir).rglob("*_http_*.jsonl"))
    ok = len(body) == len(payload) + len(b"data: ") and log_size < 1_500_000
    return ok, f"client_recv={len(body)} of {len(payload)+6}, log_size={log_size} (bounded={log_size < 1_500_000})"


def rf_pipeline_closes_after_ambiguous_body() -> tuple[bool, str]:
    """After a close-delimited (ambiguous-framing) response the proxy must close
    the connection, so a second pipelined request on the same socket is not
    desynced and reparsed against leftover bytes. Only one response comes back;
    the second request's bytes die with the closed connection."""
    class DupCL(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "5")
            self.send_header("Content-Length", "50")   # ambiguous → close-delimit
            self.end_headers()
            self.wfile.write(b"hello")

    remote = _serve(DupCL)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = socket.create_connection(("127.0.0.1", tp), timeout=4)
        c.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"
                  b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")
        c.settimeout(3)
        buf = b""
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
        except socket.timeout:
            pass
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = buf.count(b"HTTP/1.1 200") == 1 and b"Connection: close" in buf
    return ok, f"responses={buf.count(b'HTTP/1.1 200')}, close_present={b'Connection: close' in buf}"


# ── SSE surface #4 residue ─────────────────────────────────────────
def sse_terminated_oversized_event_dropped() -> tuple[bool, str]:
    """A terminated SSE event larger than _MAX_SSE_BUF must reach the client in
    full, but the session log must not hold the whole event — one drop-note
    replaces it."""
    payload = b"A" * (512 * 1024)  # over _MAX_SSE_BUF

    class Flood(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: " + payload + b"\n\n")

    remote = _serve(Flood)
    rp = remote.server_address[1]
    tap, tp, logdir = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=8)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        body = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    log_size = sum(f.stat().st_size for f in Path(logdir).rglob("*_http_*.jsonl"))
    ok = len(body) == len(payload) + len(b"data: ") + 2 and log_size < 1_000_000
    return ok, f"client_recv={len(body)}, log_size={log_size} (bounded={log_size < 1_000_000})"


def sse_oversized_event_with_metadata_dropped() -> tuple[bool, str]:
    """Metadata lines do not exempt a terminated oversized event from the log
    cap; the raw event is dropped instead of being logged whole."""
    payload = b"A" * (512 * 1024)

    class Flood(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"event: big\ndata: " + payload + b"\n\n")

    remote = _serve(Flood)
    rp = remote.server_address[1]
    tap, tp, logdir = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=8)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        body = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    log_size = sum(f.stat().st_size for f in Path(logdir).rglob("*_http_*.jsonl"))
    ok = len(body) == len(payload) + len(b"event: big\ndata: ") + 2 and log_size < 1_000_000
    return ok, f"client_recv={len(body)}, log_size={log_size} (bounded={log_size < 1_000_000})"


# ── surface #5 — connection / hop-by-hop / header path ─────────────
def rf_1xx_processing_skipped() -> tuple[bool, str]:
    """A 1xx informational response (e.g., 102 Processing) before the final
    response must be swallowed by the proxy, not forwarded to the client."""
    rp, t = _serve_raw(
        b"HTTP/1.1 102 Processing\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 15\r\n\r\n{\"result\":true}")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = r.status == 200 and data == b'{"result":true}'
    return ok, f"status={r.status}, data={data!r}"


def rf_101_upgrade_refused() -> tuple[bool, str]:
    """A hostile 101 Switching Protocols re-tasks the connection; the bytes
    after it are not HTTP. The proxy must refuse with a 502, never echo the
    upgraded bytes and never hang parsing them as a status line."""
    rp, t = _serve_raw(
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n"
        b"\x00\x01not-http-garbage\xff")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    hung = False
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=4)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        status = r.status
        c.close()
    except (TimeoutError, socket.timeout):
        hung, status, data = True, 0, b""
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = (not hung) and status == 502 and b"not-http-garbage" not in data
    return ok, f"hung={hung}, status={status}, garbage_leaked={b'not-http-garbage' in data}"


def rf_duplicate_content_type_safe() -> tuple[bool, str]:
    """Duplicate Content-Type headers cannot flip a JSON body onto the SSE
    path. Ambiguous CT defaults to non-streaming so Content-Length is preserved."""
    class DupCT(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            body = b'{"ok":"data"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    remote = _serve(DupCT)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = data == b'{"ok":"data"}' and r.getheader("Content-Length") == "13"
    return ok, f"client_recv={data!r}, cl={r.getheader('Content-Length')!r}"


def rf_204_no_content_drops_cl() -> tuple[bool, str]:
    """A 204/304 response is bodiless. A hostile upstream Content-Length must
    not be forwarded; the proxy close-delimits cleanly instead."""
    rp, t = _serve_raw(
        b"HTTP/1.1 204 No Content\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 5\r\n\r\n")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = r.status == 204 and data == b"" and r.getheader("Content-Length") is None
    return ok, f"status={r.status}, cl={r.getheader('Content-Length')!r}, conn={r.getheader('Connection')!r}"


def rf_chunked_trailers_not_forwarded() -> tuple[bool, str]:
    """Trailers on a chunked response are consumed by http.client during
    de-chunking and are not forwarded (TE is a _HOP header). This is a green
    lock: the client has no trailer channel because TE is stripped."""
    rp, t = _serve_raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n"
        b"5\r\nhello\r\n5\r\nworld\r\n0\r\n"
        b"X-Trailer: smuggled\r\n\r\n")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = data == b"helloworld" and r.getheader("X-Trailer") is None
    return ok, f"client_recv={data!r}, trailer={r.getheader('X-Trailer')!r}"


def rf_connection_nominated_hop_stripped_response() -> tuple[bool, str]:
    """s2c: an upstream Connection header nominates X-Internal-Hop as
    hop-by-hop; the proxy must NOT forward that connection-local header to the
    client, while ordinary headers and the body pass through. Locks finding #2
    (response direction)."""
    rp, t = _serve_raw(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Connection: close, X-Internal-Hop\r\n"
        b"X-Internal-Hop: leaked-secret\r\n"
        b"X-Keep: ok\r\n"
        b"Content-Length: 5\r\n\r\nhello")
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{}')
        r = c.getresponse()
        data = r.read()
        hop = r.getheader("X-Internal-Hop")
        keep = r.getheader("X-Keep")
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); t.join(2)
    ok = data == b"hello" and hop is None and keep == "ok"
    return ok, f"client_recv={data!r}, x_internal_hop={hop!r}, x_keep={keep!r}"


def req_connection_nominated_hop_stripped_request() -> tuple[bool, str]:
    """c2s: a client Connection header nominates X-Internal-Hop; the proxy must
    NOT forward that connection-local header upstream, while ordinary headers
    reach the server. Locks finding #2 (request direction)."""
    captured: dict = {}

    class _Capture(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            captured["x_internal_hop"] = self.headers.get("X-Internal-Hop")
            captured["x_keep"] = self.headers.get("X-Keep")
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    remote = _serve(_Capture)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        s = socket.create_connection(("127.0.0.1", tp), timeout=5)
        s.sendall(
            b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
            b"Connection: keep-alive, X-Internal-Hop\r\n"
            b"X-Internal-Hop: leaked-secret\r\n"
            b"X-Keep: ok\r\n"
            b"Content-Length: 2\r\n\r\n{}")
        s.settimeout(5)
        buf = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                buf += d
        except socket.timeout:
            pass
        s.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = (captured.get("x_internal_hop") is None
          and captured.get("x_keep") == "ok"
          and buf.count(b"HTTP/1.1 200") == 1)
    return ok, (f"upstream_x_internal_hop={captured.get('x_internal_hop')!r}, "
                f"upstream_x_keep={captured.get('x_keep')!r}, "
                f"responses={buf.count(b'HTTP/1.1 200')}")


def r2_duplicate_identical_content_length_rejected() -> tuple[bool, str]:
    """Any duplicate Content-Length header line is malformed per RFC 7230,
    even if the two values are identical."""
    resp, _ = _raw(
        b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
        b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
    status = resp.split(b"\r\n", 1)[0] if resp else b""
    ok = status.startswith(b"HTTP/1.1 4")
    return ok, f"status={status!r}"


def req_header_crlf_inject_no_desync() -> tuple[bool, str]:
    """Client header CRLF injection cannot desync framing: the injected header
    is parsed as a separate header, hop/framing headers are stripped before the
    upstream, and the proxy's request-target is fixed to remote.path. The two
    pipelined requests are forwarded separately — green lock."""
    _Counting.paths = []
    remote = _serve(_Counting)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        s = socket.create_connection(("127.0.0.1", tp), timeout=5)
        s.sendall(
            b"POST /mcp HTTP/1.1\r\nHost: x\r\n"
            b"X-Evil: a\r\nContent-Length: 0\r\n\r\n"
            b"POST /smuggled HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        s.settimeout(5)
        buf = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                buf += d
        except socket.timeout:
            pass
        s.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    # Both requests reach the upstream as separate requests, but always to the
    # configured remote.path ("/") — no path injection.
    ok = len(_Counting.paths) == 2 and all(p == "/" for p in _Counting.paths) and buf.count(b"HTTP/1.1 200") == 2
    return ok, f"upstream_paths={_Counting.paths}, responses={buf.count(b'HTTP/1.1 200')}"


def req_expect_100_continue_safe() -> tuple[bool, str]:
    """A client Expect: 100-continue request is forwarded header+body; the
    upstream's final response reaches the client. Green lock."""
    class Echo(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    remote = _serve(Echo)
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{"x":1}',
                  headers={"Expect": "100-continue"})
        r = c.getresponse()
        data = r.read()
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    ok = r.status == 200 and data == b'{"x":1}'
    return ok, f"status={r.status}, data={data!r}"


# ── R3 · slowloris / thread survival ───────────────────────────────
def r3_handler_timeout() -> tuple[bool, str]:
    tmp = Path(LOG_DIR); tmp.mkdir(parents=True, exist_ok=True)
    log = SessionLog(tmp / "probe.jsonl")
    cls = _make_handler(urlsplit("http://127.0.0.1:1/"), log)
    log.close()
    t = getattr(cls, "timeout", None)
    return t is not None, f"handler.timeout={t}"


def r3_survives_abort() -> tuple[bool, str]:
    remote = _serve(_Counting)
    _Counting.paths = []
    rp = remote.server_address[1]
    tap, tp, _ = _start_tap(f"http://127.0.0.1:{rp}/")
    try:
        s = socket.create_connection(("127.0.0.1", tp), timeout=5)
        s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\npartial")
        s.close()
        c = http.client.HTTPConnection("127.0.0.1", tp, timeout=5)
        c.request("POST", "/mcp", body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
        status = c.getresponse().status
        c.close()
    finally:
        tap.shutdown(); tap.server_close(); remote.shutdown(); remote.server_close()
    return status == 200, f"post_abort_request_status={status}"


CASES = [
    ("R1 unbounded response → memory/disk DoS", r1_unbounded_response),
    ("R2 chunked request smuggling (TE, no CL)", r2_chunked_smuggling),
    ("R2 duplicate Content-Length rejected", r2_duplicate_content_length),
    ("R2 duplicate identical Content-Length rejected", r2_duplicate_identical_content_length_rejected),
    ("RF conflicting response Content-Length dropped", rf_response_conflicting_content_length),
    ("RF comma-folded response Content-Length dropped", rf_comma_folded_content_length),
    ("RF lying-short Content-Length forces close (no hang)", rf_lying_short_content_length),
    ("RF bare-LF header smuggling normalized (CL dropped)", rf_bare_lf_header_smuggling),
    ("RF chunked upstream de-chunked (no marker leak)", rf_chunked_upstream_dechunked),
    ("RF SSE response close-delimited (no client hang)", rf_sse_close_delimited),
    ("RF Content-Type substring can't flip to SSE (CL kept)", rf_content_type_no_sse_flip),
    ("RF duplicate Content-Type can't flip to SSE (CL kept)", rf_duplicate_content_type_safe),
    ("RF oversized SSE event memory-bounded (relay sacred)", rf_sse_oversized_event_bounded),
    ("SSE terminated oversized event dropped (log bounded)", sse_terminated_oversized_event_dropped),
    ("SSE oversized metadata event dropped (log bounded)", sse_oversized_event_with_metadata_dropped),
    ("RF 1xx Processing skipped (final response reaches client)", rf_1xx_processing_skipped),
    ("RF 101 upgrade refused (502, no garbage, no hang)", rf_101_upgrade_refused),
    ("RF 204 No Content drops hostile Content-Length", rf_204_no_content_drops_cl),
    ("RF chunked trailers not forwarded (TE stripped)", rf_chunked_trailers_not_forwarded),
    ("RF pipeline closes after ambiguous body (no desync)", rf_pipeline_closes_after_ambiguous_body),
    ("RF Connection-nominated hop stripped from response", rf_connection_nominated_hop_stripped_response),
    ("REQ Connection-nominated hop stripped from request", req_connection_nominated_hop_stripped_request),
    ("REQ header CRLF inject cannot desync framing", req_header_crlf_inject_no_desync),
    ("REQ Expect: 100-continue forwarded safely", req_expect_100_continue_safe),
    ("R3 handler defines a socket timeout", r3_handler_timeout),
    ("R3 server survives a client aborting mid-request", r3_survives_abort),
]


def run() -> int:
    all_ok = True
    rows = []
    for name, fn in CASES:
        try:
            ok, detail = fn()
        except Exception as exc:  # a crash is a failure, not a pass
            ok, detail = False, f"exception: {type(exc).__name__}: {exc}"
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")
        rows.append((name, ok, detail))

    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w", encoding="utf-8") as fh:
        fh.write("# http-relay red-team — findings\n\n")
        fh.write("| row | result | detail |\n|---|---|---|\n")
        for name, ok, detail in rows:
            fh.write(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
