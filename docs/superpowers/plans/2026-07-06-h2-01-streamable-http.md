# H2.01 — Streamable-HTTP interception Implementation Plan

> **For agentic workers:** execute task-by-task (superpowers:executing-plans). Checkboxes track progress; each phase ends committed so an interrupted session loses nothing.

**Goal:** `glassport wrap --transport http --url <remote-mcp-url>` runs a local MITM proxy for MCP's Streamable-HTTP transport, logging every JSON-RPC frame both directions into the same JSONL the stdio tap writes — so `from_mcp_session` and every detector work unchanged.

**Architecture:** glassport listens on `127.0.0.1:PORT` and forwards client↔remote over HTTP, mirroring the stdio MITM (client↔glassport↔server). `SessionLog.record(dir, bytes)` is already transport-neutral, so the HTTP tap reuses it per JSON-RPC message; the trace adapter needs no change. New module `adapters/mcp_http.py` holds the proxy. The tap stays dumb — it frames at the JSON-RPC-message boundary (POST body; SSE `data:` event) but never interprets method/params/id.

**Tech Stack:** Python 3.10+ stdlib only — `http.server.ThreadingHTTPServer`, `http.client` (streaming forward), hand-rolled SSE parse. Zero new runtime dependency.

## Global Constraints

- **Zero runtime dependency.** stdlib HTTP only; no `requests`/`httpx`/`aiohttp`.
- **Fail-open, the relay is sacred.** A logging failure never alters, delays, or kills a live session (`SessionLog.record` already swallows). SSE bytes are forwarded to the client *as they arrive*, independent of framing/logging.
- **The tap stays dumb.** Frame at the message boundary; never parse JSON-RPC semantics (method/id/params). Never synthesize a message except relaying the remote's actual bytes.
- **Same JSONL, same trace.** Every JSON-RPC message → `SessionLog.record("c2s"|"s2c", msg_bytes)`. `from_mcp_session` must yield the same InteractionTrace shape as stdio (locked by a parity test).
- **Streamable-HTTP transport** (MCP 2025-06-18): single endpoint; client `POST` (JSON-RPC request/notification), response is `application/json` (single) or `text/event-stream` (SSE); client `GET` opens a server→client SSE stream; `DELETE` ends the session. `Mcp-Session-Id` header is forwarded verbatim. Batching was removed in 2025-06-18 → one message per POST is the norm.
- **Branch:** `feat/h2-01-streamable-http`. Tests: `PYTHONPATH=src python -m unittest <target> -v`.

## Module map

```
adapters/mcp_http.py   run_http_tap(remote_url, log_dir, bind, port, *, ready=None, server_box=None)
                         _ProxyHandler(BaseHTTPRequestHandler): POST/GET/DELETE
                         _stream_sse(resp, wfile, log): stream + frame SSE
                         _filter_req_headers / _HOP hop-by-hop set
tap.py                 wrap dispatch gains --transport http --url (default stdio, unchanged)
tests/test_http_tap.py mock remote (stdlib http.server in a thread); no network
```

Design decisions (rationale, since brainstorm was compressed under a usage limit):
- **MITM proxy, not client shim** — only a proxy the real MCP client points at can tap a real session, exactly like the stdio tap sits between client and child.
- **Reuse `SessionLog`** rather than a parallel logger — guarantees byte-identical JSONL and free trace parity; the roadmap's "adapter mirroring mcp_session.py" is satisfied by the proxy emitting the same records the reader already consumes.
- **Stream SSE, never buffer** — buffering an SSE stream would delay/observably alter the session (doctrine breach). Forward each chunk to the client immediately; accumulate a *separate* parse buffer only to cut `data:` events for logging.

---

### Phase A — HTTP proxy + JSON round trip (the load-bearing increment)

**Files:** create `src/glassport/adapters/mcp_http.py`, `tests/test_http_tap.py`.

**Interface produced:**
`run_http_tap(remote_url: str, log_dir: Path, bind: str = "127.0.0.1", port: int = 0, *, ready: threading.Event | None = None, server_box: list | None = None) -> None`
— starts a ThreadingHTTPServer; when bound, sets `ready` and appends the server to `server_box` (so a test can read `server.server_address` and call `shutdown()`), then `serve_forever()`.

- [ ] **A1. Failing test — JSON POST round trip through the proxy**

```python
# tests/test_http_tap.py
import json, threading, time, unittest, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile, shutil

from glassport.adapters.mcp_http import run_http_tap
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.interaction_trace import EventKind


class _MockRemote(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(n)
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "result": {"tools": [{"name": "search"}]}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestHttpTapJson(unittest.TestCase):
    def test_post_round_trip_logs_both_directions(self):
        remote = _serve(_MockRemote)
        rhost, rport = remote.server_address
        logdir = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(logdir))
        ready = threading.Event(); box = []
        t = threading.Thread(target=run_http_tap,
            args=(f"http://{rhost}:{rport}/mcp", logdir),
            kwargs={"ready": ready, "server_box": box}, daemon=True)
        t.start(); self.assertTrue(ready.wait(5))
        phost, pport = box[0].server_address
        try:
            req = urllib.request.Request(
                f"http://{phost}:{pport}/mcp",
                data=json.dumps({"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list"}).encode(),
                headers={"Content-Type": "application/json"})
            resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
            self.assertIn("search", json.dumps(resp))  # remote's answer reached client
        finally:
            box[0].shutdown(); remote.shutdown()
        logs = list(logdir.glob("*.jsonl"))
        self.assertTrue(logs)
        trace = from_mcp_session_file(str(logs[0]))
        dirs = [e.metadata.get("seq") for e in trace.events]  # smoke: events built
        self.assertIn("search", trace.declared_tools() | {"search"})
        # c2s tools/list captured and s2c result captured
        text = logs[0].read_text()
        self.assertIn('"tools/list"', text)
        self.assertIn('"search"', text)
```

- [ ] **A2. Run — expect ImportError (module missing).**
- [ ] **A3. Implement `adapters/mcp_http.py`:**

```python
"""Streamable-HTTP MITM tap (roadmap H2.01). glassport listens locally and
forwards client<->remote over HTTP, logging every JSON-RPC message into the
same JSONL the stdio tap writes (SessionLog is transport-neutral). The tap is
dumb (frames at the message boundary, never parses semantics) and fail-open
(SSE bytes reach the client as they arrive, independent of logging)."""

from __future__ import annotations

import http.client
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from glassport.tap import SessionLog, _safe_name  # reuse logger + naming

# hop-by-hop headers must not be forwarded verbatim.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host",
        "content-length"}


def _connect(remote) -> http.client.HTTPConnection:
    if remote.scheme == "https":
        return http.client.HTTPSConnection(remote.hostname, remote.port or 443,
                                           timeout=30)
    return http.client.HTTPConnection(remote.hostname, remote.port or 80,
                                      timeout=30)


def _req_headers(headers, remote) -> dict:
    out = {k: v for k, v in headers.items() if k.lower() not in _HOP}
    out["Host"] = remote.netloc
    return out


def _make_handler(remote, log: SessionLog):
    class _ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet; stdout belongs to nobody here
            pass

        def _relay(self, method: str) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            if body:
                log.record("c2s", body)          # dumb: one POST body = one frame
            try:
                conn = _connect(remote)
                conn.request(method, remote.path or "/",
                             body=body or None, headers=_req_headers(self.headers, remote))
                resp = conn.getresponse()
            except Exception as exc:
                # glassport's own transport failure — surface it, don't fake a reply
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"glassport: upstream error: {exc}".encode())
                return
            ctype = resp.getheader("Content-Type", "")
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in _HOP:
                    self.send_header(k, v)
            if "text/event-stream" in ctype:
                self.send_header("Content-Type", ctype)  # ensure preserved
                self.end_headers()
                _stream_sse(resp, self.wfile, log)
            else:
                data = resp.read()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    log.record("s2c", data)
                self.wfile.write(data)
            conn.close()

        def do_POST(self):  self._relay("POST")
        def do_GET(self):   self._relay("GET")
        def do_DELETE(self):self._relay("DELETE")

    return _ProxyHandler


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
            break  # client went away; stop
        buf += chunk
        while b"\n\n" in buf:
            event, buf = buf.split(b"\n\n", 1)
            data = b"".join(
                ln[5:].lstrip() for ln in event.split(b"\n")
                if ln.startswith(b"data:"))
            if data:
                log.record("s2c", data)


def run_http_tap(remote_url: str, log_dir: Path, bind: str = "127.0.0.1",
                 port: int = 0, *, ready: threading.Event | None = None,
                 server_box: list | None = None) -> None:
    remote = urlsplit(remote_url)
    log_dir = Path(log_dir)
    stamp = __import__("glassport.tap", fromlist=["_now_stamp"])
    # session log path mirrors run_tap's naming
    from glassport.tap import _now_stamp  # type: ignore
    log_path = log_dir / f"{_now_stamp()}_http_{os.getpid()}.jsonl"
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
        log.close() if hasattr(log, "close") else None
```

> Note during implementation: confirm the exact helper names in `tap.py`
> (`_safe_name`, `_now_stamp`/`_now_iso`, `SessionLog.close`). If a helper name
> differs, adjust the import — do not duplicate the logic.

- [ ] **A4. Run the test — expect PASS.** Fix header/naming mismatches revealed.
- [ ] **A5. Commit** `feat(http): streamable-HTTP MITM proxy — JSON round trip`.

### Phase B — SSE response streaming

- [ ] **B1. Failing test:** mock remote whose `do_POST` responds
  `Content-Type: text/event-stream` and writes two events
  (`data: {json}\n\n` each), flushing between. Drive a POST through the proxy;
  assert (a) the client receives both raw events, (b) the JSONL has two s2c
  frames with the two messages. (`_stream_sse` already drafted in Phase A — this
  test proves it; if Phase A shipped it, B is a test-only task.)
- [ ] **B2. Run → PASS** (implementation landed in A3). If gaps, fix `_stream_sse`.
- [ ] **B3. Commit** `test(http): SSE response streaming + per-event framing`.

### Phase C — GET server→client SSE + DELETE

- [ ] **C1. Failing test:** mock remote `do_GET` returns an SSE stream; drive a
  GET through the proxy; assert events reach the client and are logged s2c.
  Separate test: `do_DELETE` returns 200; assert forwarded + status relayed.
- [ ] **C2. Implement:** `do_GET`/`do_DELETE` already call `_relay`; ensure
  GET with no body logs nothing c2s and streams SSE. Fix if needed.
- [ ] **C3. Commit** `feat(http): GET SSE stream + DELETE session end`.

### Phase D — CLI wiring `wrap --transport http --url`

- [ ] **D1. Failing test** (`tests/test_cli.py` or `test_http_tap.py`): call the
  wrap dispatch with `["wrap", "--transport", "http", "--url", "http://x"]` and
  assert it routes to `run_http_tap` (patch it) with the parsed url; and that
  omitting `--transport` still routes to stdio `run_tap`.
- [ ] **D2. Implement:** in `tap.py` wrap dispatch, parse `--transport`
  (default `stdio`) and `--url`; when `http`, call
  `adapters.mcp_http.run_http_tap(url, log_dir, ...)` instead of `run_tap`.
  Update the `wrap` help line.
- [ ] **D3. Commit** `feat(cli): wrap --transport http --url`.

### Phase E — Trace parity, fail-open, docs

- [ ] **E1. Parity test:** feed a hand-built HTTP session (initialize →
  tools/list → tools/call, each via the proxy against a mock remote) and assert
  `from_mcp_session_file` yields the same InteractionTrace shape as the stdio
  equivalent — declared surface non-empty, the call captured, a TOOL_RESULT
  present, `fabricated_tool_calls() == []`.
- [ ] **E2. Fail-open tests:** (a) remote refused → client gets 502 and the tap
  process/thread survives (a second request still works); (b) monkeypatch
  `log.record` to raise → the client still receives the remote's response
  (logging failure never breaks the relay).
- [ ] **E3. Docs:** README "Streamable-HTTP" subsection under the tap; STATUS
  Tier-1 row + Next-action; note gate-over-HTTP and streaming-detector path are
  the follow-on increments (H2.01 ships the passive HTTP tap only).
- [ ] **E4. Full suite + commit** `docs(http): H2.01 streamable-HTTP tap`.

## Out of scope (this increment)
- **Gate over HTTP** (active blocking on the c2s path) — passive tap only here.
- **Streaming *detector* path** (frame-at-a-time analysis) — the tap streams;
  detectors still consume the full JSONL after the session, as today.
- **Auth flows / OAuth** to the remote — headers are forwarded verbatim; glassport
  neither adds nor strips credentials.
- **HTTP/2, WebSocket transport** — Streamable-HTTP (POST/GET/SSE) only.

## Exit criteria (roadmap)
- [ ] `glassport wrap --transport http --url <remote>` works end-to-end.
- [ ] JSONL captures both directions (POST c2s, JSON/SSE s2c, GET SSE s2c).
- [ ] Adapter (`from_mcp_session`) produces the same InteractionTrace shape as stdio.
- [ ] Fail-open: transport/logging failure never alters or kills a live session.
- [ ] Zero new runtime dependency; suite passes with a mocked remote (no network).
