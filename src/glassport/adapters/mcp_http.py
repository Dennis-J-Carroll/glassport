"""Streamable-HTTP MITM tap (roadmap H2.01).

glassport listens locally and forwards client<->remote over MCP's
Streamable-HTTP transport, logging every JSON-RPC message into the same JSONL
the stdio tap writes (`SessionLog` is transport-neutral). The tap stays dumb —
it frames at the JSON-RPC-message boundary (a POST body; an SSE `data:` event)
but never interprets method/id/params — and fail-open: SSE bytes reach the
client as they arrive, independent of framing/logging. A logging failure never
alters, delays, or kills a live session.

The optional observer API isolates live analysis and wire captures per HTTP
session epoch. It folds complete frames before completing client delivery;
analysis failures still fail open.

Enforcement is off unless a journal in gate mode is supplied (`glassport gate
--transport http`). With one, and ONLY then, a frame whose analysis proves a
severity-3 tools/call against an observed declared surface is answered locally
with a JSON-RPC error and never forwarded: no upstream connection is opened for
it at all. Missing *evidence* — missing, partial or malformed declarations, a
faulted detector pass, a lost or stale epoch, a call with no JSON-RPC id —
forwards, with the would-block recorded. A request gate mode cannot *read*
(oversized, encoded, not exactly one unambiguous JSON object) or whose
Host/Origin is not the loopback proxy is refused before connecting. Passive
wrap and observation mode keep byte-for-byte identical behavior, because with
`journal=None` (or a journal in observe mode) the enforcement branch is never
reachable.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from glassport.tap import SessionLog, _loads, open_session_log

# hop-by-hop headers (RFC 7230 §6.1) plus Host/Content-Length, which the proxy
# recomputes — never forwarded verbatim.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host",
        "content-length"}


# An RFC 7230 token, lowercased — the only shape a Connection-nominated field
# name can legitimately take. Anything else in the list is ignored (we never
# ADD a header to the drop set on a malformed token, only skip it).
_HOP_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")


def _hop_headers(pairs) -> set[str]:
    """The static hop-by-hop set plus any field a Connection header nominates.
    HTTP (RFC 7230 §6.1) lets a connection mark extra headers as hop-by-hop by
    listing them in Connection; those must not be forwarded end-to-end. `pairs`
    is an iterable of (name, value) header tuples (request or response)."""
    drop = set(_HOP)
    for k, v in pairs:
        if k.lower() == "connection":
            for tok in v.split(","):
                name = tok.strip().lower()
                if name and _HOP_TOKEN_RE.match(name):
                    drop.add(name)
    return drop


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
    if r.username is not None or r.password is not None:
        # `is not None` (not truthiness): a stray empty userinfo like "http://@h/x"
        # yields username="" — falsy but still an embedded-credential shape we reject.
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
    drop = _hop_headers(headers.items())
    out = {k: v for k, v in headers.items() if k.lower() not in drop}
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
# Gate mode reads a whole POST body before deciding, and refuses (413) any
# body larger than this rather than forward bytes it never analysed. Observe
# and passive modes keep streaming past _MAX_LOGGED_BODY unchanged.
GATE_MAX_BODY = 4 * 1024 * 1024
_GATE_DRAIN_LIMIT = 4 * GATE_MAX_BODY
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
_CREDENTIAL_HEADERS = ("authorization", "cookie", "proxy-authorization")
_HANDLER_TIMEOUT = 30         # drop a stalled client so it can't pin a thread


def _extract_sse_meta(event: bytes) -> dict[str, str]:
    """Return the transport metadata fields of an SSE event.

    Only ``event:``, ``id:``, and ``retry:`` are captured; values are
    stripped of the optional leading space and returned as strings. Unknown
    fields are ignored, matching the framing logic in `_log_sse_event`.
    """
    meta: dict[str, str] = {}
    for raw in event.split(b"\n"):
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if raw.startswith(b"event:"):
            meta["event"] = raw[6:].lstrip(b" ").decode("utf-8", errors="replace")
        elif raw.startswith(b"id:"):
            meta["id"] = raw[3:].lstrip(b" ").decode("utf-8", errors="replace")
        elif raw.startswith(b"retry:"):
            meta["retry"] = raw[6:].lstrip(b" ").decode("utf-8", errors="replace")
    return meta


def _log_sse_event(event: bytes, log: SessionLog, *, partial: bool = False) -> None:
    """Log one SSE event. data: lines are joined with \\n.

    If the event carries event:/id:/retry: fields, the JSON-RPC payload in
    the data: lines is still logged as a structured frame, and the SSE
    metadata is preserved in a separate ``sse_meta`` field. Over-limit
    partial flushes continue to be logged raw for forensics.
    """
    if not event or event.strip() == b"":
        return
    lines = event.split(b"\n")
    data_lines: list[bytes] = []
    has_meta = False
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
    if partial:
        # Preserve the full raw text for an unterminated/overflow event.
        log.record("s2c", event)
    elif has_meta:
        # Preserve metadata separately so the data payload stays parseable.
        log.record("s2c", payload, metadata=_extract_sse_meta(event))
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


def _observe_call(lease, method, *args, **kwargs):
    """Optional analysis must never acquire control over passive delivery."""
    try:
        return getattr(lease, method)(*args, **kwargs)
    except Exception:
        try:
            lease.loss('http_analysis_failed')
        except Exception:
            pass
        return None


def _journal_call(journal, method, *args, **kwargs):
    """Decision recording never gains control over passive delivery either.

    A journal write failure is exactly as fail-open as an analysis failure: the
    relay forwards, and the absent record is the honest evidence of absence.
    """
    try:
        return getattr(journal, method)(*args, **kwargs)
    except Exception:
        return None


def _lease_epoch(lease):
    """The observed epoch a decision belongs to, or None when unroutable."""
    epoch = getattr(getattr(lease, "context", None), "epoch", None)
    return epoch if isinstance(epoch, str) and epoch else None


_NO_ID = object()   # sentinel: this frame cannot be answered locally


def _blockable_id(observation):
    """The exact JSON-RPC id a synthesized block must echo, or :data:`_NO_ID`.

    The id is read from the folded event's metadata, which holds the value the
    wire carried with its original type — so a numeric id comes back numeric
    and a string id comes back a string, never normalized between the two.

    MCP defines ``tools/call`` as a request that expects a result. A
    ``tools/call``-shaped frame carrying no id is therefore a notification
    shape the method is not allowed to take: non-conformant, with nothing to
    correlate a synthetic error to, and JSON-RPC forbids answering a
    notification at all. Rather than block something it cannot answer — which
    would drop a call silently, with no error visible to the client — the relay
    treats that as a malformed request and forwards it, the would-block still
    recorded. Same for an id of any type JSON-RPC does not permit (null, a
    float, an object): glassport does not invent a correlation the client never
    established. (``type(...) is int`` also excludes bool, which JSON has no
    concept of but Python's json module would never produce here anyway.)
    """
    event = getattr(observation, "event", None)
    metadata = getattr(event, "metadata", None)
    rid = metadata.get("jsonrpc_id") if isinstance(metadata, dict) else None
    return rid if type(rid) is int or type(rid) is str else _NO_ID


def _gate_verdict(journal, observation) -> bool:
    """Should this frame be refused? Computed BEFORE anything is recorded.

    This is the single decision point for enforcement, and it is deliberately
    a pure read: it opens no file, writes no record, and swallows every error
    into False. Nothing that happens after it — a journal write failure, an
    unwritable directory, a raising ``record_intent`` — may change the answer,
    which is what keeps "recording is fail-open" from quietly becoming
    "enforcement is fail-open".
    """
    if journal is None:
        return False
    try:
        if not journal.evaluate(observation):
            return False
    except Exception:
        return False
    return _blockable_id(observation) is not _NO_ID


def _observe_json_response(resp, wfile, lease, cap, *, expected=None, interpret=True):
    """Bounded lookahead: fold a complete JSON body before completing delivery."""
    head = bytearray()
    complete = False
    read_error = None
    try:
        while len(head) <= cap:
            chunk = resp.read(min(_RELAY_CHUNK, cap + 1 - len(head)))
            if not chunk:
                complete = expected is None or len(head) == expected
                break
            head.extend(chunk)
    except Exception as exc:
        read_error = exc
        head.extend(getattr(exc, 'partial', b''))
    if head or not complete:
        _observe_call(lease, "record", "s2c", bytes(head[:cap]),
                      incomplete=not complete or not interpret)
    # Even a failed upstream read may have provided bytes before failure.
    # Flush that prefix before surfacing the read error and closing transport.
    wfile.write(head)
    total = len(head)
    if read_error is not None:
        raise read_error
    if not complete:
        while True:
            chunk = resp.read(_RELAY_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            wfile.write(chunk)
    return total


def _observe_sse(resp, wfile, lease, cap):
    """Observe frames before forwarding their completing chunk; bound lookahead.

    Every normal event has exact raw bytes in wire_b64. Oversize events retain
    a bounded prefix, then discard interpretation through their terminator.
    """
    buf = b""
    overflow = False
    first = True
    try:
        while True:
            chunk = resp.read1(4096)
            if not chunk:
                if buf and not overflow:
                    _observe_call(lease, "record", "s2c", buf, incomplete=True, wire_bytes=buf)
                return
            buf += chunk
            while True:
                terms = [(i, t) for t in (b"\r\n\r\n", b"\n\n", b"\r\r")
                         if (i := buf.find(t)) >= 0]
                if not terms:
                    break
                i, term = min(terms, key=lambda item: item[0])
                raw, buf = buf[:i + len(term)], buf[i + len(term):]
                if overflow:
                    overflow = False
                    continue
                event = raw[:-len(term)]
                if first and event.startswith(b"\xef\xbb\xbf"):
                    event = event[3:]
                first = False
                if len(raw) > cap:
                    _observe_call(lease, "record", "s2c", raw[:cap], incomplete=True, wire_bytes=raw[:cap])
                    continue
                data, meta = [], {}
                for line in event.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n"):
                    field, colon, value = line.partition(b":")
                    if value.startswith(b" "):
                        value = value[1:]
                    if field == b"data":
                        data.append(value)
                    elif field in (b"id", b"event", b"retry"):
                        meta[field.decode()] = value.decode("utf-8", errors="replace")
                _observe_call(lease, "record", "s2c", b"\n".join(data) if data else event,
                             event_id=meta.get("id") if data else None,
                             metadata=meta or None, wire_bytes=raw,
                             transport_only=not data or (meta.get("event") or "message") != "message")
            if len(buf) > cap:
                if not overflow:
                    _observe_call(lease, "record", "s2c", buf[:cap], incomplete=True, wire_bytes=buf[:cap])
                    overflow = True
                    first = False
                # Preserve a possible terminator crossing the next chunk.
                buf = buf[-3:]
            wfile.write(chunk)
            wfile.flush()
    except Exception:
        if buf and not overflow:
            _observe_call(lease, "record", "s2c", buf[:cap], incomplete=True, wire_bytes=buf[:cap])
        raise


def _gate_body_problem(body: bytes):
    """(status, reason) when gate mode must refuse this POST body, else None.

    Enforcement is only as good as the analyser's reading of the request. A
    body it cannot read as exactly one JSON object -- the same object any
    conforming upstream parser would read -- is refused, never forwarded:
    batches, duplicate keys (first-wins vs last-wins parsers disagree), a
    BOM, invalid UTF-8, trailing data, or a non-object.
    """
    try:
        frame = _loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return 400, "request body is not one unambiguous JSON object"
    if not isinstance(frame, dict):
        return 400, "request body is not one JSON-RPC object"
    return None


def _make_handler(remote, log: SessionLog, observer=None, journal=None):
    # Refusing what cannot be inspected is enforcement; observation stays
    # byte-transparent, so only a journal in gate mode arms these checks.
    gate_mode = journal is not None and getattr(journal, "mode", None) == "gate"
    # The cap must equal what the observer analyses: a body the observer
    # would fold as incomplete can never be proved, so it would forward.
    gate_cap = GATE_MAX_BODY if observer is None else min(
        GATE_MAX_BODY, observer.limits.max_frame_bytes)

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

        def _send_block(self, observation) -> None:
            """Answer a refused tools/call locally, in glassport's own voice.

            The client gets an ordinary 200 carrying a JSON-RPC error — the
            same shape a server's own error would take, so a conforming client
            surfaces it through its normal error path — with the request's
            exact id echoed back so it correlates. `-32000` matches the stdio
            gate's convention, but the marker is `http_gate_blocked` rather
            than the stdio gate's `gate_blocked`: two independent enforcement
            paths must stay distinguishable in a log.

            Nothing attacker-influenced is echoed. The client already knows
            which call it made (the id says so), and the tool name and declared
            surface are both influenced by the other side of a session this
            response is trying to keep honest; the wire log and the decision
            journal carry that evidence instead.
            """
            body = json.dumps({
                "jsonrpc": "2.0",
                "id": _blockable_id(observation),
                "error": {
                    "code": -32000,
                    "message": ("glassport gate: tools/call blocked — the "
                                "requested tool is outside the surface this "
                                "server declared"),
                    "data": {"glassport": "http_gate_blocked"},
                },
            }, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass   # client hung up; the block already happened

        def _local_request_ok(self) -> bool:
            """Loopback proxies must not be drivable by a web page (DNS
            rebinding): Host must name this proxy, and Origin, if sent, must
            be this proxy's own origin. Non-browser clients send no Origin."""
            bound, port = self.server.server_address[:2]
            if not (bound.startswith("127.") or bound in ("::1", "localhost")):
                return True   # explicitly exposed: the operator owns access
            allowed = {f"{h}:{port}" for h in _LOOPBACK_HOSTS}
            hosts = self.headers.get_all("Host") or []
            if len(hosts) != 1 or hosts[0].strip().lower() not in allowed:
                return False
            origins = self.headers.get_all("Origin") or []
            if not origins:
                return True
            return (len(origins) == 1
                    and origins[0].strip().lower() in {"http://" + a for a in allowed})

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
            if gate_mode and self.command == "POST":
                encoding = (self.headers.get("Content-Encoding") or "").strip().lower()
                if encoding not in ("", "identity"):
                    self._reject(415, "content-encoding not supported in gate mode")
                    return None, False
                if length > gate_cap:
                    # Drain a bounded amount so the client can read the 413
                    # instead of a reset; past that, just close.
                    left = length if length <= _GATE_DRAIN_LIMIT else 0
                    while left > 0:
                        chunk = self.rfile.read(min(_RELAY_CHUNK, left))
                        if not chunk:
                            break
                        left -= len(chunk)
                    self._reject(413, "request body exceeds gate inspection limit")
                    return None, False
                head = self.rfile.read(length) if length else b""
                problem = (_gate_body_problem(head) if len(head) == length
                           else (400, "request body shorter than content-length"))
                if problem is not None:
                    self._reject(*problem)
                    return None, False
            else:
                head = self.rfile.read(min(length, _MAX_LOGGED_BODY)) if length else b""
            rest = length - len(head)
            if getattr(self, "_observation_lease", None) is not None and head:
                self._c2s_observation = _observe_call(
                    self._observation_lease, "record", "c2s", head, incomplete=rest > 0)
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
            self._observation_lease = None
            self._c2s_observation = None
            if gate_mode and not self._local_request_ok():
                self._reject(403, "origin or host not allowed")
                return
            if gate_mode:
                # Nothing a caller sends may weaken enforcement for later
                # calls. The observer answers ambiguous credentials and an
                # unverifiable resume by retiring or resetting the session's
                # epoch, which would switch enforcement off for the whole
                # session; refuse such a request before it is observed.
                names = [k.lower() for k in self.headers.keys()]
                if any(names.count(n) > 1 for n in _CREDENTIAL_HEADERS):
                    self._reject(400, "ambiguous credentials")
                    return
                if "last-event-id" in names and (
                        observer is None
                        or not observer.resume_verifiable(list(self.headers.items()))):
                    self._reject(400, "cannot verify the resume point")
                    return
            # Delivery phase flags. Recording reads them; nothing branches on
            # them, so the forwarded bytes are identical with journal=None.
            intent = None
            delivery = ("unknown", "handler_aborted", None)
            request_sent = completed = False
            if observer is not None:
                try:
                    self._observation_lease = observer.begin(method, list(self.headers.items()))
                except Exception:
                    pass  # optional analysis cannot break passive transport
            conn = resp = None
            try:
                body, ok = self._read_client_body()
                if not ok:
                    # Ambiguous framing: refused locally, never begun upstream.
                    delivery = ("not_attempted", "framing_rejected", None)
                    if journal is not None:
                        epoch = _lease_epoch(self._observation_lease)
                        if epoch is not None:
                            intent = _journal_call(journal, "record_intent", epoch,
                                                   self._c2s_observation)
                    return
                if journal is not None:
                    # ORDER IS LOAD-BEARING. The verdict is computed first,
                    # from analysis alone; recording comes second and cannot
                    # revise it; acting on it comes third. Anything that
                    # reordered these — deriving `enforce` from the returned
                    # intent, say — would silently convert every journal
                    # failure into a forward of a call glassport had already
                    # proved should not be forwarded.
                    enforce = _gate_verdict(journal, self._c2s_observation)
                    # Intent is persisted BEFORE the upstream request begins, so
                    # a crash mid-delivery still leaves what analysis concluded.
                    epoch = _lease_epoch(self._observation_lease)
                    if epoch is not None:
                        intent = _journal_call(journal, "record_intent", epoch,
                                               self._c2s_observation,
                                               enforce=enforce)
                    delivery = ("not_attempted", "not_begun", None)
                    if enforce:
                        # Refused. `conn` is still None and stays None: no
                        # socket is opened, so not one byte of this request can
                        # reach upstream. The finally block below records the
                        # terminal outcome, exactly as on every other path.
                        delivery = ("blocked", "http_gate_blocked", 200)
                        self._send_block(self._c2s_observation)
                        return
                try:
                    conn = _connect(remote)
                    conn.request(method, _upstream_target(remote), body=body or None,
                                 headers=_req_headers(self.headers, remote))
                    request_sent = True
                    resp = conn.getresponse()
                except Exception as exc:
                    # Classify BEFORE the finally closes conn (close() clears
                    # .sock and would destroy the zero-bytes-sent proof). A
                    # missing socket means connect/DNS failed, so nothing was
                    # written. For HTTPS, connect() assigns .sock before the TLS
                    # handshake, so a handshake failure reads as an established
                    # socket and is classified 'unknown' — deliberately
                    # conservative, not a bug to "fix".
                    if not request_sent:
                        delivery = (("not_sent", "connect_failed", None)
                                    if getattr(conn, "sock", None) is None
                                    else ("unknown", "send_indeterminate", None))
                    else:
                        # request() already returned: the send completed and the
                        # response state is indeterminate. Never 'not_sent'.
                        delivery = ("unknown", "response_indeterminate", None)
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

                # A complete request left the local socket and upstream
                # answered. Not evidence that a remote tool executed.
                delivery = ("sent", "upstream_response", resp.status)
                if self._observation_lease is not None:
                    _observe_call(self._observation_lease, "response", resp.status, resp.getheaders())
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
                resp_drop = _hop_headers(resp.getheaders())
                for k, v in resp.getheaders():
                    if k.lower() in resp_drop:
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
                    if self._observation_lease is None:
                        _stream_sse(resp, self.wfile, log)
                    else:
                        _observe_sse(resp, self.wfile, self._observation_lease,
                                     min(_MAX_SSE_BUF, observer.limits.max_frame_bytes))
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
                    if self._observation_lease is not None:
                        total = _observe_json_response(resp, self.wfile, self._observation_lease,
                            min(_MAX_LOGGED_BODY, observer.limits.max_frame_bytes), expected=declared,
                            interpret=(len(all_ct) == 1 and ctype.split(';', 1)[0].strip().lower()
                                       == 'application/json'))
                        head = b""
                    else:
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
                completed = True
            finally:
                # Close-delimited responses may own the socket after getresponse()
                # has detached it from conn. Release both owners on every exit.
                try:
                    if resp is not None:
                        resp.close()
                finally:
                    try:
                        if conn is not None:
                            conn.close()
                    finally:
                        if self._observation_lease is not None:
                            _observe_call(self._observation_lease, "release")
                        if intent is not None:
                            # Exactly one terminal record per intent, on every
                            # exit path — including a client disconnect that
                            # unwinds mid-delivery. A response whose body
                            # transfer then failed is 'failed', not 'sent'.
                            if delivery[0] == "sent" and not completed:
                                delivery = ("failed", "body_transfer_failed", delivery[2])
                            _journal_call(journal, "record_delivery", intent,
                                          delivery[0], code=delivery[1], status=delivery[2])

        def do_POST(self):
            self._relay("POST")

        def do_GET(self):
            self._relay("GET")

        def do_DELETE(self):
            self._relay("DELETE")

    return _ProxyHandler


class _NullLog:
    """No-op stand-in for a disabled session log. open_session_log() returns
    None on an unwritable dir or an unverifiable/non-private file mode, but
    every request-handling path in this module calls log.record()/log.close()
    unconditionally (unlike stdio's pump(), which already checks for None) —
    the relay is sacred, so a disabled log must not crash request handling
    or shutdown."""

    def record(self, *args, **kwargs) -> None:
        pass

    def close(self) -> None:
        pass


def run_http_tap(remote_url: str, log_dir: Path, bind: str = "127.0.0.1",
                 port: int = 0, *, ready: "threading.Event | None" = None,
                 server_box: "list | None" = None, observer=None,
                 journal=None) -> None:
    """Start the local Streamable-HTTP MITM proxy and serve until shut down.

    `ready` is set once the server is bound; `server_box` (if given) receives
    the server so a caller/test can read `server_address` and `shutdown()`.
    `journal` (opt-in, requires `observer`) records candidate decisions and
    delivery outcomes into their own per-epoch files. A journal in observation
    mode never changes what is forwarded or when; a journal in gate mode is the
    only thing that enables enforcement, and then only for the narrow proved
    case described in the module docstring.
    """
    remote = _validate_remote(remote_url)
    log_dir = Path(log_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = log_dir / f"{stamp}_http_{os.getpid()}.jsonl"
    # An explicitly observed proxy has one capture per opaque epoch. Never
    # create a second multiplexed capture that a single-session reader could
    # accidentally interpret as a combined declaration surface.
    log = (open_session_log(log_path) or _NullLog()) if observer is None else _NullLog()
    journal = journal if observer is not None else None
    httpd = ThreadingHTTPServer((bind, port),
                                _make_handler(remote, log, observer, journal))
    if server_box is not None:
        server_box.append(httpd)
    print(f"[glassport] http tap on http://{bind}:{httpd.server_address[1]} "
          f"-> {remote_url}", file=sys.stderr)
    if observer is None:
        print(f"[glassport] session log: {log_path}", file=sys.stderr)
    else:
        print(f"[glassport] session logs: {observer.log_dir} (one per epoch)", file=sys.stderr)
        if journal is not None:
            from glassport.decision_journal import MODE_GATE
            gating = getattr(journal, "mode", None) == MODE_GATE
            print(f"[glassport] decision journal: {journal.dir} "
                  + ("(GATE: proved out-of-surface tools/call is blocked; "
                     "everything else forwards)" if gating else
                     "(observation only; nothing is blocked)"),
                  file=sys.stderr)
    if ready is not None:
        ready.set()
    try:
        httpd.serve_forever()
    finally:
        try:
            httpd.server_close()
        finally:
            log.close()
            if observer is not None:
                observer.close()
            if journal is not None:
                journal.close()
