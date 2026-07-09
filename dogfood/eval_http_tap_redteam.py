"""Streamable-HTTP tap red-team grill.

Runs the real `glassport.adapters.mcp_http.run_http_tap` against hostile local
"remote" servers and asserts integrity/DoS invariants on the forwarded bytes and
the JSONL session log. No live network is used.

Run: PYTHONPATH=src python dogfood/eval_http_tap_redteam.py
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from glassport.adapters.mcp_http import run_http_tap

LOG_DIR = "dogfood/logs/http-tap-redteam"
FINDINGS = "dogfood/findings/http-tap-redteam.md"


def _free_port() -> int:
    with socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler) as s:
        return s.server_address[1]


def _start_server(handler) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, t


def _stop_server(srv: socketserver.TCPServer) -> None:
    srv.shutdown()
    srv.server_close()


def _start_tap(remote_url: str) -> tuple[threading.Thread, int, Path]:
    """Start run_http_tap in a thread and return (thread, local_port, log_dir)."""
    log_dir = Path(LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    # Isolate this test's log file from prior tests in the same grill.
    for old in log_dir.glob("*_http_*.jsonl"):
        old.unlink()
    ready = threading.Event()
    box: list = []
    t = threading.Thread(
        target=run_http_tap,
        args=(remote_url, log_dir),
        kwargs={"bind": "127.0.0.1", "port": 0, "ready": ready, "server_box": box},
        daemon=True,
    )
    t.start()
    ready.wait(timeout=5.0)
    if not box:
        raise RuntimeError("http tap failed to start")
    port = box[0].server_address[1]
    return t, port, log_dir, box[0]


def _latest_log(log_dir: Path) -> Path | None:
    files = sorted(log_dir.glob("*_http_*.jsonl"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def _read_log(log_path: Path) -> list[dict]:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# ---------------------------------------------------------------------------
# H1 — Multi-line data: events lose their newline separators in the log
# ---------------------------------------------------------------------------
def h1_multiline_data_corrupted() -> tuple[bool, str]:
    """SSE allows multiple data: lines per event; they must be joined with '\n'.
    The tap joins them with no separator, altering the logged frame."""

    class Remote(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: {\"a\":1}\ndata: {\"b\":2}\n\n")
            self.wfile.flush()

        def log_message(self, *args):
            pass

    remote_srv, remote_port, _ = _start_server(Remote)
    tap_thread, tap_port, log_dir, httpd = _start_tap(f"http://127.0.0.1:{remote_port}")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{tap_port}/") as resp:
            forwarded = resp.read()
    finally:
        httpd.shutdown()
        _stop_server(remote_srv)

    log_path = _latest_log(log_dir)
    entries = _read_log(log_path) if log_path else []
    s2c = [e for e in entries if e.get("dir") == "s2c"]
    raw = s2c[0].get("raw") if s2c else None
    corrupted = raw == '{"a":1}{"b":2}'
    ok = not corrupted
    detail = f"forwarded={forwarded!r}, log_raw={raw!r}, entries={len(s2c)}"
    return ok, detail


# ---------------------------------------------------------------------------
# H2 — event:/id:/comment SSE fields are dropped from the log
# ---------------------------------------------------------------------------
def h2_nondata_fields_dropped() -> tuple[bool, str]:
    """The forwarded byte stream is faithful, but the log only keeps data:
    lines. event:, id:, retry:, and comments disappear from the analysis view."""

    class Remote(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"event: tool_result\nid: 42\n:comment\ndata: ok\n\n")
            self.wfile.flush()

        def log_message(self, *args):
            pass

    remote_srv, remote_port, _ = _start_server(Remote)
    tap_thread, tap_port, log_dir, httpd = _start_tap(f"http://127.0.0.1:{remote_port}")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{tap_port}/") as resp:
            forwarded = resp.read()
    finally:
        httpd.shutdown()
        _stop_server(remote_srv)

    log_path = _latest_log(log_dir)
    entries = _read_log(log_path) if log_path else []
    s2c = [e for e in entries if e.get("dir") == "s2c"]
    text = json.dumps(s2c)
    preserved = "tool_result" in text or "42" in text or "comment" in text
    ok = preserved
    detail = f"forwarded={forwarded!r}, log_contains_nondata={preserved}"
    return ok, detail


# ---------------------------------------------------------------------------
# H3 — SSE stream that never sends \n\n writes nothing to the log
# ---------------------------------------------------------------------------
def h3_unterminated_sse_dropped() -> tuple[bool, str]:
    """_stream_sse buffers until it sees \n\n. A hostile server that streams
    forever without a double newline forwards bytes to the client but never
    produces a log entry and grows the buffer without bound."""

    class Remote(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            # send 256k of data without a terminating double newline
            for _ in range(1024):
                self.wfile.write(b"data: x" * 64 + b"\n")
                self.wfile.flush()

        def log_message(self, *args):
            pass

    remote_srv, remote_port, _ = _start_server(Remote)
    tap_thread, tap_port, log_dir, httpd = _start_tap(f"http://127.0.0.1:{remote_port}")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{tap_port}/") as resp:
            forwarded = resp.read()
    finally:
        httpd.shutdown()
        _stop_server(remote_srv)

    log_path = _latest_log(log_dir)
    entries = _read_log(log_path) if log_path else []
    s2c = [e for e in entries if e.get("dir") == "s2c"]
    # With a bounded buffer the tap flushes the partial stream rather than
    # growing forever, so some s2c entry must have been written.
    logged = len(s2c) > 0
    ok = logged and len(forwarded) > 0
    detail = f"forwarded_bytes={len(forwarded)}, s2c_entries={len(s2c)}"
    return ok, detail


# ---------------------------------------------------------------------------
# H5 — Leading UTF-8 BOM drops the first SSE event from the log
# ---------------------------------------------------------------------------
def h5_bom_drops_event() -> tuple[bool, str]:
    """A malicious SSE stream can start with a UTF-8 BOM. The proxy forwards the
    BOM bytes faithfully, but the framing parser does not strip it, so the first
    `data:` line does not start with `b'data:'` and the event is not logged."""

    class Remote(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"\xef\xbb\xbfdata: bom_event\n\n")
            self.wfile.flush()

        def log_message(self, *args):
            pass

    remote_srv, remote_port, _ = _start_server(Remote)
    tap_thread, tap_port, log_dir, httpd = _start_tap(f"http://127.0.0.1:{remote_port}")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{tap_port}/") as resp:
            forwarded = resp.read()
    finally:
        httpd.shutdown()
        _stop_server(remote_srv)

    log_path = _latest_log(log_dir)
    entries = _read_log(log_path) if log_path else []
    s2c = [e for e in entries if e.get("dir") == "s2c"]
    logged = any("bom_event" in json.dumps(e) for e in s2c)
    ok = logged
    detail = (f"forwarded_starts_with_bom={forwarded.startswith(bytes([0xef, 0xbb, 0xbf]))}, "
              f"s2c_entries={len(s2c)}")
    return ok, detail


# ---------------------------------------------------------------------------
# H6 — SSE events terminated by \r\n\r\n are not split at all
# ---------------------------------------------------------------------------
def h6_crlf_terminator_not_split() -> tuple[bool, str]:
    """The SSE spec permits events to end with \r\n\r\n. The parser only scans
    for \n\n, so CRLF-terminated events are buffered forever and never logged."""

    class Remote(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: ok\r\n\r\n")
            self.wfile.flush()

        def log_message(self, *args):
            pass

    remote_srv, remote_port, _ = _start_server(Remote)
    tap_thread, tap_port, log_dir, httpd = _start_tap(f"http://127.0.0.1:{remote_port}")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{tap_port}/") as resp:
            forwarded = resp.read()
    finally:
        httpd.shutdown()
        _stop_server(remote_srv)

    log_path = _latest_log(log_dir)
    entries = _read_log(log_path) if log_path else []
    s2c = [e for e in entries if e.get("dir") == "s2c"]
    # A spec-compliant parser must recognize \r\n\r\n terminators.
    logged = len(s2c) > 0
    ok = logged
    detail = f"forwarded={forwarded!r}, s2c_entries={len(s2c)}"
    return ok, detail


# ---------------------------------------------------------------------------
# H4 — Upstream exception message reaches the client in the 502 body
# ---------------------------------------------------------------------------
def h4_exception_message_to_client() -> tuple[bool, str]:
    """When the remote is unreachable, _relay sends a 502 whose body contains
    str(exc). The exception string can carry attacker-controlled bytes if the
    remote URL or error is crafted."""
    closed_port = _free_port()
    tap_thread, tap_port, log_dir, httpd = _start_tap(f"http://127.0.0.1:{closed_port}")
    body = b""
    status = None
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{tap_port}/", data=b"{}")
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read()
    finally:
        httpd.shutdown()

    # The 502 body must be a generic message; exception details are for stderr.
    leaked = status == 502 and b"Connection refused" in body
    ok = not leaked
    detail = f"status={status}, body={body!r}"
    return ok, detail


def run() -> int:
    checks = [
        ("H1 multi-line data: loses newline separator", h1_multiline_data_corrupted()),
        ("H2 event:/id:/comment lines dropped from log", h2_nondata_fields_dropped()),
        ("H3 unterminated SSE stream never logged", h3_unterminated_sse_dropped()),
        ("H5 leading BOM drops first SSE event", h5_bom_drops_event()),
        ("H6 CRLF terminator \\r\\n\\r\\n not split", h6_crlf_terminator_not_split()),
        ("H4 upstream exception reaches client", h4_exception_message_to_client()),
    ]

    lines = ["# http-tap red-team — findings", "",
             "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, (ok, detail) in checks:
        all_ok = all_ok and ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")

    lines += ["", "## Source defects", "",
              "* `_stream_sse` joins multiple `data:` lines with `b\"\".join(...)`, "
              "dropping the mandatory `\\n` separator between them. The logged frame "
              "is therefore not the frame the client parsed (H1).",
              "",
              "* `_stream_sse` discards `event:`, `id:`, `retry:`, and comment lines "
              "when extracting a payload for the log. The relay is byte-faithful, "
              "but the analysis view is not (H2).",
              "",
              "* `_stream_sse` buffers all SSE bytes until `\\n\\n` appears. A server "
              "that never sends the terminator forwards bytes correctly but never "
              "produces a log entry, and the buffer grows without bound (H3).",
              "",
              "* `_stream_sse` does not strip a leading UTF-8 BOM before looking for "
              "`data:` lines, so a BOM-prefixed event is forwarded but dropped from "
              "the log (H5).",
              "",
              "* `_stream_sse` only scans for bare `\\n\\n` event terminators; the "
              "SSE-specified `\\r\\n\\r\\n` terminator is never matched, so CRLF-only "
              "streams are forwarded but never logged (H6).", 
              "",
              "* `_relay` sends `str(exc)` in the 502 response body when the upstream "
              "connection fails. That exception string can include attacker-controlled "
              "bytes from the remote URL or transport error (H4).",
              ""]

    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
