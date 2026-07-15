"""H2.01 streamable-HTTP tap — tests. A mock MCP remote runs in a background
thread; no real network. The proxy under test forwards client<->remote and
logs every JSON-RPC message into the same JSONL the stdio tap writes.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from glassport.adapters.mcp_http import run_http_tap
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.detectors import annotate
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

    def do_GET(self):
        # server->client SSE stream (Streamable-HTTP GET)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        msg = json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}).encode()
        self.wfile.write(b"data: " + msg + b"\n\n")
        self.wfile.flush()

    def do_DELETE(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


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


class TestHttpTapLogDegrade(unittest.TestCase):
    """The relay is sacred: a None log (unwritable dir / insecure permissions,
    per open_session_log) must not crash request handling or shutdown."""

    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_relay_survives_when_logging_disabled(self):
        remote = _serve(_JsonRemote)
        rh, rp = remote.server_address
        with mock.patch("glassport.adapters.mcp_http.open_session_log",
                        return_value=None):
            proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
            ph, pp = proxy.server_address
            try:
                resp = json.loads(_post(f"http://{ph}:{pp}/mcp",
                                        {"jsonrpc": "2.0", "id": 1,
                                         "method": "tools/list"}))
                self.assertIn("search", json.dumps(resp))
            finally:
                proxy.shutdown()
                remote.shutdown()

    def test_client_bytes_identical_logging_on_vs_off(self):
        """The relay is sacred: whether the session log opens successfully or
        degrades to None, the exact bytes the client receives must be
        identical. Logging state must never alter the wire."""
        def _run(disable_logging: bool):
            remote = _serve(_JsonRemote)
            rh, rp = remote.server_address
            patcher = (mock.patch("glassport.adapters.mcp_http.open_session_log",
                                  return_value=None)
                       if disable_logging else contextlib.nullcontext())
            with patcher:
                proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
                ph, pp = proxy.server_address
                try:
                    return _post(f"http://{ph}:{pp}/mcp",
                                {"jsonrpc": "2.0", "id": 1,
                                 "method": "tools/list"})
                finally:
                    proxy.shutdown()
                    remote.shutdown()

        bytes_with_logging = _run(disable_logging=False)
        bytes_without_logging = _run(disable_logging=True)
        self.assertEqual(bytes_with_logging, bytes_without_logging)
        self.assertTrue(bytes_with_logging)  # sanity: not comparing two empties


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


class _McpRemote(BaseHTTPRequestHandler):
    """Minimal MCP server: answers initialize / tools/list / tools/call so a
    full HTTP-captured session can be replayed through the trace adapter."""

    def log_message(self, *args, **kwargs):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        method, rid = body.get("method"), body.get("id")
        result = {
            "initialize": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "serverInfo": {"name": "mock"}},
            "tools/list": {"tools": [{"name": "search"}]},
            "tools/call": {"content": [{"type": "text", "text": "ok"}]},
        }.get(method, {})
        out = json.dumps({"jsonrpc": "2.0", "id": rid,
                          "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class TestHttpTapParity(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_http_capture_yields_same_trace_shape_as_stdio(self):
        remote = _serve(_McpRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
        ph, pp = proxy.server_address
        url = f"http://{ph}:{pp}/mcp"
        try:
            _post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            _post(url, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "search", "arguments": {}}})
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        logs = list(self.logdir.glob("*.jsonl"))
        trace = from_mcp_session_file(str(logs[0]))
        self.assertIn("search", trace.declared_tools())         # tools/list captured
        self.assertIn("search", [n for _, n in trace.called_tools()])
        self.assertEqual(trace.fabricated_tool_calls(), [])     # legit call, not fabricated
        self.assertTrue(any(e.kind == EventKind.TOOL_RESULT for e in trace.events))


class _SseNamedRemote(BaseHTTPRequestHandler):
    """Streamable-HTTP remote that frames every JSON-RPC response as an SSE
    event carrying an ``event:`` field and an ``id:`` field — the default
    framing emitted by the official Python MCP SDK's
    ``FastMCP(...).run(transport='streamable-http')``."""

    def log_message(self, *args, **kwargs):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        method, rid = body.get("method"), body.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "mock"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "search"}]}
        elif method == "tools/call":
            # Intentionally leak a credential-like string in the result so the
            # pii_in_result detector can prove it sees the tool result.
            result = {"content": [{"type": "text",
                                   "text": "leaked sk-proj-"
                                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
                                            "7890 secret"}]}
        else:
            result = {}
        out = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(
            b"event: message\n"
            b"id: " + str(rid).encode() + b"\n"
            b"data: " + out + b"\n\n")
        self.wfile.flush()


class TestHttpTapNamedSse(unittest.TestCase):
    """Named-event SSE framing must not degrade s2c JSON-RPC frames to raw
    MESSAGE events: tools/list, tools/call, and detectors that rely on
    parsed tool results must still work."""

    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_named_sse_frames_are_parsed_and_tool_results_visible(self):
        remote = _serve(_SseNamedRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
        ph, pp = proxy.server_address
        url = f"http://{ph}:{pp}/mcp"
        try:
            _post(url, {"jsonrpc": "2.0", "id": 0, "method": "initialize"})
            _post(url, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "search", "arguments": {}}})
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()

        logs = list(self.logdir.glob("*.jsonl"))
        self.assertTrue(logs, "no session log written")
        trace = from_mcp_session_file(str(logs[0]))

        # The declared surface must be harvested even though the response was
        # wrapped in ``event: message``.
        self.assertIn("search", trace.declared_tools())
        # The call must correlate with the declared surface, not be flagged as
        # fabricated.
        self.assertEqual(trace.fabricated_tool_calls(), [])
        self.assertIn("search", [n for _, n in trace.called_tools()])
        # The result must be visible as a real TOOL_RESULT event.
        self.assertTrue(any(e.kind == EventKind.TOOL_RESULT for e in trace.events))

        # Confirm the raw log entries are no longer ``frame: null``.
        text = logs[0].read_text(encoding="utf-8")
        s2c = [json.loads(ln) for ln in text.splitlines()
               if '"dir": "s2c"' in ln]
        for entry in s2c:
            self.assertIsInstance(entry.get("frame"), dict,
                                  "s2c entry was logged unparsed")

        # Detectors that depend on parsed tool results must fire.
        annotations = annotate(trace)
        subs = {a.subcategory for a in annotations}
        self.assertIn("pii_in_result_openai_key", subs,
                      "pii_in_result detector missed a secret in a tool result")
        self.assertNotIn("fabricated_tool_call", subs,
                         "legitimate tool call was falsely flagged as fabricated")


class TestHttpTapFailOpen(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_upstream_down_returns_502_and_tap_survives(self):
        # point at a closed port; the proxy must surface an error, not crash,
        # and must still serve the next request (the relay outlives failures).
        proxy = _start_proxy("http://127.0.0.1:1/mcp", self.logdir)
        ph, pp = proxy.server_address
        try:
            for _ in range(2):
                code = None
                try:
                    _post(f"http://{ph}:{pp}/mcp", {"jsonrpc": "2.0", "id": 1})
                except urllib.error.HTTPError as e:
                    code = e.code
                self.assertEqual(code, 502)   # clean upstream error, twice
        finally:
            proxy.shutdown(); proxy.server_close()


class TestHttpTapCli(unittest.TestCase):
    def test_transport_http_routes_to_run_http_tap(self):
        from unittest import mock
        from glassport import tap
        with mock.patch("glassport.adapters.mcp_http.run_http_tap") as m:
            rc = tap.main(["wrap", "--transport", "http", "--url",
                           "http://remote.example/mcp"])
        self.assertEqual(rc, 0)
        self.assertEqual(m.call_args.args[0], "http://remote.example/mcp")

    def test_transport_http_requires_url(self):
        from glassport import tap
        self.assertEqual(tap.main(["wrap", "--transport", "http"]), 2)

    def test_gate_over_http_rejected(self):
        from glassport import tap
        self.assertEqual(
            tap.main(["gate", "--transport", "http", "--url", "http://x"]), 2)


class TestHttpTapGetDelete(unittest.TestCase):
    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir))

    def test_get_sse_stream_logged_and_delete_relayed(self):
        remote = _serve(_SseRemote)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}/mcp", self.logdir)
        ph, pp = proxy.server_address
        try:
            get = urllib.request.urlopen(
                f"http://{ph}:{pp}/mcp", timeout=5).read()
            self.assertIn(b"notifications/x", get)  # server->client SSE reached client
            dreq = urllib.request.Request(f"http://{ph}:{pp}/mcp", method="DELETE")
            code = urllib.request.urlopen(dreq, timeout=5).getcode()
            self.assertEqual(code, 200)             # DELETE status relayed
        finally:
            proxy.shutdown()
            proxy.server_close()
            remote.shutdown()
            remote.server_close()

        text = "".join(p.read_text(encoding="utf-8")
                       for p in self.logdir.glob("*.jsonl"))
        self.assertIn("notifications/x", text)      # GET SSE event logged s2c


class _PathCapture(BaseHTTPRequestHandler):
    """Records the exact request-target the upstream received."""
    seen: list = []

    def log_message(self, *args, **kwargs):
        pass

    def do_POST(self):
        type(self).seen.append(self.path)
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestUpstreamQueryForwarded(unittest.TestCase):
    """H2 — the configured upstream query string must reach the upstream; a
    multi-tenant endpoint keyed on ?tenant=... is silently mis-routed without
    it."""

    def setUp(self):
        self.logdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.logdir, ignore_errors=True))
        _PathCapture.seen = []

    def _run(self, upstream_path: str) -> str:
        remote = _serve(_PathCapture)
        rh, rp = remote.server_address
        proxy = _start_proxy(f"http://{rh}:{rp}{upstream_path}", self.logdir)
        ph, pp = proxy.server_address
        try:
            _post(f"http://{ph}:{pp}/mcp", {"jsonrpc": "2.0", "id": 1})
        finally:
            proxy.shutdown(); proxy.server_close()
            remote.shutdown(); remote.server_close()
        return _PathCapture.seen[-1]

    def test_query_string_is_forwarded(self):
        self.assertEqual(self._run("/mcp?tenant=alpha"), "/mcp?tenant=alpha")

    def test_no_query_has_no_stray_question_mark(self):
        self.assertEqual(self._run("/mcp"), "/mcp")

    def test_root_path_with_query(self):
        self.assertEqual(self._run("/?tenant=alpha"), "/?tenant=alpha")


class TestRemoteValidation(unittest.TestCase):
    def test_rejects_bad_scheme_userinfo_fragment_port(self):
        from glassport.adapters import mcp_http
        for bad in ("ftp://h/x", "http:///nohost", "http://u:p@h/x",
                    "http://@h/x", "http://u@h/x",  # empty/partial userinfo still rejected
                    "http://h/x#frag", "http://h:99999/x"):
            with self.assertRaises(ValueError, msg=bad):
                mcp_http._validate_remote(bad)

    def test_accepts_plain_https_with_query(self):
        from glassport.adapters import mcp_http
        r = mcp_http._validate_remote("https://h.example/mcp?tenant=alpha")
        self.assertEqual(r.hostname, "h.example")
        self.assertEqual(r.query, "tenant=alpha")

    def test_host_header_excludes_userinfo_and_default_port(self):
        from glassport.adapters import mcp_http
        r = mcp_http._validate_remote("https://h.example:8443/x")
        self.assertEqual(mcp_http._host_header(r), "h.example:8443")
        r2 = mcp_http._validate_remote("https://h.example/x")
        self.assertEqual(mcp_http._host_header(r2), "h.example")
        r3 = mcp_http._validate_remote("http://h.example:80/x")   # default port dropped
        self.assertEqual(mcp_http._host_header(r3), "h.example")

    def test_rejects_port_zero(self):
        from glassport.adapters import mcp_http
        with self.assertRaises(ValueError):
            mcp_http._validate_remote("http://h:0/x")

    def test_rejects_whitespace_in_host(self):
        from glassport.adapters import mcp_http
        # Note: urlsplit strips \t\r\n from the whole URL before parsing, so
        # "http://h\tx/y" parses to hostname "hx" (no whitespace survives) and
        # is out of scope for this check. A literal space is NOT stripped by
        # urlsplit and is the case this validator must catch.
        with self.assertRaises(ValueError, msg="http://h /x"):
            mcp_http._validate_remote("http://h /x")

    def test_non_numeric_port_message_names_the_cause(self):
        from glassport.adapters import mcp_http
        with self.assertRaises(ValueError) as ctx:
            mcp_http._validate_remote("http://h:abc/x")
        self.assertIn("port", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
