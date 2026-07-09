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
