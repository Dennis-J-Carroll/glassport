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


# Own line cap for the 1xx header sweep, so _discard_headers depends on ZERO
# underscore-prefixed http.client symbols (which "may change" across CPython).
_MAX_1XX_LINE = 65536
_MAX_1XX_HEADER_LINES = 100


def _validate_remote(url: str):
    """Parse and strictly validate the upstream URL before the proxy binds.
    A security tool must parse its own configuration narrowly: reject any
    scheme but http/https, require a host, and refuse embedded credentials
    or a fragment (neither belongs in a proxy target and both are silent
    footguns). Returns the SplitResult; raises ValueError on anything off."""
    r = urlsplit(url)
    if r.scheme not in ("http", "https"):
        raise ValueError(
            f"remote scheme {r.scheme or '(none)'!r} unsupported: use http or https")
    if not r.hostname:
        raise ValueError("remote URL has no host")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in r.hostname):
        raise ValueError("remote URL host contains whitespace or control characters")
    if r.username or r.password:
        raise ValueError("remote URL must not embed credentials (user:pass@)")
    if r.fragment:
        raise ValueError("remote URL must not contain a fragment")
    try:
        port = r.port                    # property raises ValueError if unparseable/out of range
    except ValueError as exc:
        raise ValueError(f"remote URL has an invalid port: {exc}")
    if port == 0:
        raise ValueError("remote URL port 0 is not allowed")
    return r


def _host_header(remote) -> str:
    """Host header from hostname (+ explicit non-default port), never raw
    netloc — netloc can carry userinfo the proxy must not forward upstream."""
    host = remote.hostname or ""
    if ":" in host:                      # IPv6 literal
        host = f"[{host}]"
    default = 443 if remote.scheme == "https" else 80
    if remote.port and remote.port != default:
        return f"{host}:{remote.port}"
    return host


def _discard_headers(fp) -> None:
    """Read and drop one header block (up to the blank line) from a raw file
    object, tolerating CRLF and bare-LF terminators. Local replacement for the
    nonpublic stdlib header-reader so behavior is stable across the 3.10–3.13
    matrix. Bounded so a hostile upstream cannot stream infinite fake 1xx
    headers to pin the thread."""
    for _ in range(_MAX_1XX_HEADER_LINES):
        line = fp.readline(_MAX_1XX_LINE + 1)
        if len(line) > _MAX_1XX_LINE:
            raise http.client.LineTooLong("1xx header line")
        if line in (b"\r\n", b"\n", b""):
            return
    raise http.client.HTTPException("glassport: too many 1xx header lines")


class _Sk1xxResponse(http.client.HTTPResponse):
    """HTTPResponse that swallows *all* 1xx informational responses, not just
    100 Continue. A hostile or chatty upstream that emits 102 Processing (or
    any other 1xx) before the final response must not make the proxy hand the
    client the informational status as if it were the reply."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_status = None

    def _read_status(self):
        if self._cached_status is not None:
            s, self._cached_status = self._cached_status, None
            return s
        return super()._read_status()

    def begin(self):
        # Skip every 1xx informational status and its headers; stop at the
        # final response. 101 Switching Protocols is NOT informational-then-
        # continue: it re-tasks the connection to another protocol. Glassport
        # strips Upgrade, so a well-behaved upstream never sends 101 — but a
        # hostile one can, and the bytes after it are not HTTP. Refuse rather
        # than misparse upgraded-protocol bytes as a status line (this raises
        # out through getresponse() into _relay's 502 path).
        while True:
            status_tuple = super()._read_status()
            code = status_tuple[1]
            if code == 101:
                raise http.client.HTTPException(
                    "glassport: upstream protocol upgrade (101) is unsupported")
            if not (100 <= code < 200):
                self._cached_status = status_tuple
                break
            _discard_headers(self.fp)
        return super().begin()


class _HTTPConnection(http.client.HTTPConnection):
    response_class = _Sk1xxResponse


class _HTTPSConnection(http.client.HTTPSConnection):
    response_class = _Sk1xxResponse


def _connect(remote) -> http.client.HTTPConnection:
    if remote.scheme == "https":
        return _HTTPSConnection(
            remote.hostname, remote.port or 443, timeout=30)
    return _HTTPConnection(
        remote.hostname, remote.port or 80, timeout=30)


def _req_headers(headers, remote) -> dict:
    out = {k: v for k, v in headers.items() if k.lower() not in _HOP}
    out["Host"] = _host_header(remote)
    return out


def _upstream_target(remote) -> str:
    """Request-target for the upstream: the configured path PLUS its query
    string. Dropping the query silently mis-routes multi-tenant endpoints
    that key on it (e.g. `/mcp?tenant=alpha` → `/mcp`). The query is fixed
    per-proxy (it's the configured upstream), so it is forwarded verbatim."""
    target = remote.path or "/"
    if remote.query:
        target += "?" + remote.query
    return target


_MAX_SSE_BUF = 256 * 1024  # cap per-event buffering to avoid unbounded growth
_MAX_LOGGED_BODY = 1_000_000  # cap what a single request/response frame logs
_RELAY_CHUNK = 65536          # stream bodies in bounded chunks, never all at once
_HANDLER_TIMEOUT = 30         # drop a stalled client so it can't pin a thread


def _log_sse_event(event: bytes, log: SessionLog, *, partial: bool = False) -> None:
    """Log one SSE event. data: lines are joined with \\n; if the event carries
    event:/id:/retry: fields (or is an over-limit partial flush) the full event
    text is logged as raw so transport metadata is not silently discarded."""
    if not event or event.strip() == b"":
        return
    lines = event.split(b"\n")
    data_lines: list[bytes] = []
    has_meta = partial
    for raw in lines:
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if raw.startswith(b"data:"):
            data_lines.append(raw[5:].lstrip(b" "))
        elif raw.startswith((b"event:", b"id:", b"retry:")):
            has_meta = True
        # comment lines (": ...") and empty lines are ignored for framing
    if not data_lines:
        # no data payload: log the raw event text so comments/metadata survive
        log.record("s2c", event)
        return
    payload = b"\n".join(data_lines)
    if has_meta:
        # Preserve metadata by logging the full reconstructed event text.
        log.record("s2c", event)
    else:
        log.record("s2c", payload)


def _stream_sse(resp, wfile, log: SessionLog) -> None:
    """Forward an SSE response byte-for-byte to the client as it arrives, and
    (separately) cut complete events to log each `data:` payload as one s2c
    frame. Forwarding never waits on framing — the relay is sacred."""
    buf = b""
    first_chunk = True     # only the very first chunk of the stream can carry a BOM
    dropped_oversize = False  # emitted the runaway-drop note for the current overflow
    while True:
        chunk = resp.read(4096)
        if not chunk:
            # A trailing partial is a stream that ended mid-event — keep it for
            # forensics. But if we're mid-runaway (already dropped), the tail is
            # part of the unframeable flood; don't log it.
            if buf.strip() and not dropped_oversize:
                _log_sse_event(buf, log, partial=True)
            break
        try:
            wfile.write(chunk)
            wfile.flush()
        except Exception:
            break  # client hung up; stop streaming
        # Strip a leading UTF-8 BOM only at true stream start. `first_chunk`
        # disarms after the first read regardless, so BOM bytes that arrive
        # mid-stream stay verbatim in the log — matching what the client got.
        if first_chunk:
            if chunk.startswith(b"\xef\xbb\xbf"):
                chunk = chunk[3:]
            first_chunk = False
        buf += chunk
        # Drain all complete SSE events. Terminators: \\n\\n, \\r\\r, \\r\\n\\r\\n.
        while True:
            term: tuple[int, bytes] | None = None
            for t in (b"\r\n\r\n", b"\n\n", b"\r\r"):
                i = buf.find(t)
                if i != -1 and (term is None or i < term[0]):
                    term = (i, t)
            if term is None:
                break
            event, buf = buf[:term[0]], buf[term[0] + len(term[1]):]
            if dropped_oversize:
                # This event is the tail of an unterminated overflow run that
                # already emitted its drop-note. Discard it and leave overflow
                # mode so subsequent normal events are logged again.
                dropped_oversize = False
            elif len(event) > _MAX_SSE_BUF:
                # A single terminated event must not balloon the session log.
                # Forwarding is already byte-exact; drop the log frame.
                log.record("s2c", b'{"glassport":"sse_frame_dropped_oversize"}')
            else:
                _log_sse_event(event, log)
                dropped_oversize = False
        # Bound both memory and disk: a hostile server that never sends a
        # terminator cannot grow the buffer, and cannot make the tap write its
        # runaway stream to the log either — one note per overflow, then drop.
        if len(buf) > _MAX_SSE_BUF:
            if not dropped_oversize:
                log.record("s2c", b'{"glassport":"sse_frame_dropped_oversize"}')
                dropped_oversize = True
            buf = b""


def _make_handler(remote, log: SessionLog):
    class _ProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # A stalled client (slowloris) must not pin a ThreadingHTTPServer thread
        # forever; the request socket is dropped after this many idle seconds.
        timeout = _HANDLER_TIMEOUT

        def log_message(self, *args, **kwargs):  # keep the proxy quiet
            pass

        def _reject(self, code: int, why: str) -> None:
            """Refuse a request we cannot frame unambiguously, and close the
            connection so any pipelined bytes are never reparsed as a request."""
            self.close_connection = True
            msg = ("glassport: " + why).encode()
            self.send_response(code)
            self.send_header("Content-Length", str(len(msg)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(msg)
            except Exception:
                pass
            note = why.replace(" ", "_")
            log.record("c2s", ('{"glassport":"rejected_%s"}' % note).encode())

        def _read_client_body(self):
            """Return (body_for_upstream, framing_ok). Rejects ambiguous framing
            (Transfer-Encoding, duplicate/invalid Content-Length) rather than
            guess a length the upstream would read differently — the request
            smuggling vector. Bounds what is logged; streams the rest upstream."""
            if self.headers.get("Transfer-Encoding") is not None:
                self._reject(400, "transfer-encoding not supported")
                return None, False
            cls = self.headers.get_all("Content-Length") or []
            if len(cls) > 1:
                self._reject(400, "duplicate content-length")
                return None, False
            if cls and not cls[0].strip().isdigit():
                self._reject(400, "invalid content-length")
                return None, False
            length = int(cls[0]) if cls else 0
            head = self.rfile.read(min(length, _MAX_LOGGED_BODY)) if length else b""
            rest = length - len(head)
            if head:
                log.record("c2s", head)   # one request body = one frame (bounded)
                if rest > 0:
                    log.record("c2s", b'{"glassport":"c2s_body_truncated_oversize"}')
            if rest <= 0:
                return (head or None), True

            def _stream():
                yield head
                left = rest
                while left > 0:
                    chunk = self.rfile.read(min(_RELAY_CHUNK, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                    yield chunk
            return _stream(), True

        def _relay(self, method: str) -> None:
            body, ok = self._read_client_body()
            if not ok:
                return
            try:
                conn = _connect(remote)
                conn.request(method, _upstream_target(remote), body=body or None,
                             headers=_req_headers(self.headers, remote))
                resp = conn.getresponse()
            except Exception as exc:
                # glassport's own transport failure — surface it plainly, never
                # fabricate a JSON-RPC reply, and never echo attacker-controlled
                # exception text back to the client.
                print(f"[glassport] upstream error: {exc}", file=sys.stderr)
                msg = b"glassport: upstream unavailable"
                self.send_response(502)
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                try:
                    self.wfile.write(msg)
                except Exception:
                    pass
                return

            ctype = resp.getheader("Content-Type", "")
            all_ct = [v for k, v in resp.getheaders() if k.lower() == "content-type"]
            self.send_response(resp.status)
            # Match the *media type*, not any substring; also require exactly one
            # unambiguous Content-Type header. Duplicate or conflicting CT lines
            # default to non-streaming so an upstream cannot inject a second
            # Content-Type to flip a JSON body onto the SSE path.
            streaming = (
                len(all_ct) == 1
                and ctype.split(";", 1)[0].strip().lower() == "text/event-stream"
            )
            for k, v in resp.getheaders():
                if k.lower() in _HOP:
                    continue
                if streaming and k.lower() == "content-length":
                    continue
                self.send_header(k, v)
            if streaming:
                # An SSE response carries no Content-Length and the proxy strips
                # the upstream's Transfer-Encoding (a _HOP header), so the only
                # honest framing left is close-delimiting: mark the connection to
                # close so that when the upstream ends the stream the client gets
                # a prompt EOF instead of hanging on a kept-alive socket waiting
                # for events that will never come.
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
                _stream_sse(resp, self.wfile, log)
            else:
                # Non-SSE response: stream to the client in bounded chunks so a
                # hostile upstream cannot balloon memory, and log at most
                # _MAX_LOGGED_BODY bytes (plus a note) so it cannot balloon the
                # session log either. Preserve the upstream's own framing only
                # when it is unambiguous: a single, purely-numeric Content-Length
                # with no Transfer-Encoding. Duplicate CL header *lines*, a single
                # comma-folded CL value ("5, 50"), any non-digit token, or CL
                # paired with TE all desync the client from the bytes we actually
                # read, so we drop CL and close-delimit instead — the relay is
                # still sacred (every byte reaches the client).
                clen = resp.getheader("Content-Length")
                te = resp.getheader("Transfer-Encoding")
                all_cl = [v for k, v in resp.getheaders() if k.lower() == "content-length"]
                declared: int | None = None
                bodiless = resp.status in (204, 304)
                if (clen is not None and te is None and not bodiless
                        and len(all_cl) == 1 and clen.strip().isdigit()):
                    declared = int(clen.strip())
                    self.send_header("Content-Length", clen.strip())
                else:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                head, total = b"", 0
                while True:
                    chunk = resp.read(_RELAY_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    try:
                        self.wfile.write(chunk)
                    except Exception:
                        break  # client hung up; stop copying
                    if len(head) < _MAX_LOGGED_BODY:
                        head += chunk[: _MAX_LOGGED_BODY - len(head)]
                # A hostile upstream can declare a Content-Length larger than the
                # body it actually sends, then close. We can't verify the length
                # before sending headers without buffering the whole body (that
                # would reintroduce the R1 memory DoS), but once the stream ends
                # we know the truth: if the bytes forwarded don't match what we
                # promised, close the connection so the client gets a prompt EOF
                # instead of hanging forever on a kept-alive socket waiting for a
                # body that will never arrive.
                if declared is not None and total != declared:
                    self.close_connection = True
                if head:
                    log.record("s2c", head)   # one response body = one frame (bounded)
                    if total > len(head):
                        log.record("s2c", b'{"glassport":"s2c_body_truncated_oversize"}')
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
    remote = _validate_remote(remote_url)
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
