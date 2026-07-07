"""Streamable-HTTP MITM tap (roadmap H2.01).

glassport listens locally and forwards client<->remote over MCP's
Streamable-HTTP transport, logging every JSON-RPC message into the same JSONL
the stdio tap writes (`SessionLog` is transport-neutral). The tap stays dumb —
it frames at the JSON-RPC-message boundary (a POST body; an SSE `data:` event)
but never interprets method/id/params — and fail-open: SSE bytes reach the
client as they arrive, independent of framing/logging. A logging failure never
alters, delays, or kills a live session.

Passive tap only: gate-over-HTTP and the streaming *detector* path are separate
later increments. Detectors still consume the full JSONL after the session.
"""

from __future__ import annotations

import http.client
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from glassport.tap import SessionLog

# hop-by-hop headers (RFC 7230 §6.1) plus Host/Content-Length, which the proxy
# recomputes — never forwarded verbatim.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host",
        "content-length"}


def _connect(remote) -> http.client.HTTPConnection:
    if remote.scheme == "https":
        return http.client.HTTPSConnection(
            remote.hostname, remote.port or 443, timeout=30)
    return http.client.HTTPConnection(
        remote.hostname, remote.port or 80, timeout=30)


def _req_headers(headers, remote) -> dict:
    out = {k: v for k, v in headers.items() if k.lower() not in _HOP}
    out["Host"] = remote.netloc
    return out


def _stream_sse(resp, wfile, log: SessionLog) -> None:
    """Forward an SSE response byte-for-byte to the client as it arrives, and
    (separately) cut complete events to log each `data:` payload as one s2c
    frame. Forwarding never waits on framing — the relay is sacred."""
    buf = b""
    while True:
        chunk = resp.read(256)
        if not chunk:
            break
        try:
            wfile.write(chunk)
            wfile.flush()
        except Exception:
            break  # client hung up; stop streaming
        buf += chunk
        while b"\n\n" in buf:
            event, buf = buf.split(b"\n\n", 1)
            data = b"".join(
                ln[5:].lstrip() for ln in event.split(b"\n")
                if ln.startswith(b"data:"))
            if data:
                log.record("s2c", data)


def _make_handler(remote, log: SessionLog):
    class _ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args, **kwargs):  # keep the proxy quiet
            pass

        def _relay(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            if body:
                log.record("c2s", body)   # dumb: one POST body = one frame
            try:
                conn = _connect(remote)
                conn.request(method, remote.path or "/", body=body or None,
                             headers=_req_headers(self.headers, remote))
                resp = conn.getresponse()
            except Exception as exc:
                # glassport's own transport failure — surface it plainly, never
                # fabricate a JSON-RPC reply.
                msg = f"glassport: upstream error: {exc}".encode()
                self.send_response(502)
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                try:
                    self.wfile.write(msg)
                except Exception:
                    pass
                return

            ctype = resp.getheader("Content-Type", "")
            self.send_response(resp.status)
            streaming = "text/event-stream" in ctype
            for k, v in resp.getheaders():
                if k.lower() in _HOP:
                    continue
                if streaming and k.lower() == "content-length":
                    continue
                self.send_header(k, v)
            if streaming:
                self.end_headers()
                _stream_sse(resp, self.wfile, log)
            else:
                data = resp.read()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    log.record("s2c", data)
                try:
                    self.wfile.write(data)
                except Exception:
                    pass
            conn.close()

        def do_POST(self):
            self._relay("POST")

        def do_GET(self):
            self._relay("GET")

        def do_DELETE(self):
            self._relay("DELETE")

    return _ProxyHandler


def run_http_tap(remote_url: str, log_dir: Path, bind: str = "127.0.0.1",
                 port: int = 0, *, ready: "threading.Event | None" = None,
                 server_box: "list | None" = None) -> None:
    """Start the local Streamable-HTTP MITM proxy and serve until shut down.

    `ready` is set once the server is bound; `server_box` (if given) receives
    the server so a caller/test can read `server_address` and `shutdown()`.
    """
    remote = urlsplit(remote_url)
    log_dir = Path(log_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = log_dir / f"{stamp}_http_{os.getpid()}.jsonl"
    log = SessionLog(log_path)
    httpd = ThreadingHTTPServer((bind, port), _make_handler(remote, log))
    if server_box is not None:
        server_box.append(httpd)
    print(f"[glassport] http tap on http://{bind}:{httpd.server_address[1]} "
          f"-> {remote_url}", file=sys.stderr)
    print(f"[glassport] session log: {log_path}", file=sys.stderr)
    if ready is not None:
        ready.set()
    try:
        httpd.serve_forever()
    finally:
        log.close()
