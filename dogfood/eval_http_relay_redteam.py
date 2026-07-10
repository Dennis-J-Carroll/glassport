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
    ("RF conflicting response Content-Length dropped", rf_response_conflicting_content_length),
    ("RF comma-folded response Content-Length dropped", rf_comma_folded_content_length),
    ("RF lying-short Content-Length forces close (no hang)", rf_lying_short_content_length),
    ("RF bare-LF header smuggling normalized (CL dropped)", rf_bare_lf_header_smuggling),
    ("RF chunked upstream de-chunked (no marker leak)", rf_chunked_upstream_dechunked),
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
