"""
console.py — the glassport web console ("Glassport Console").

    glassport serve --http [--port N] [--bind HOST] [--audit PATH]
                    [--log-dir DIR]

A browser-based observability surface over the same data the curses TUI
shows: stdlib http.server for the page and JSON endpoints, a hand-rolled
RFC 6455 WebSocket for live ViewModel pushes, adapters/streaming.py for
O(new bytes) ingest. The frontend is one self-contained HTML file
(console_html.CONSOLE_HTML) — no CDN, no external requests, works
air-gapped.

Security posture (deliberate, tested):
  * Binds 127.0.0.1 unless --bind is given explicitly.
  * WebSocket handshake enforces an Origin check. Cross-origin
    WebSocket is NOT covered by the browser same-origin policy: without
    this check any web page you visit could connect to
    ws://127.0.0.1:<port>/ws and read your session streams. Absent
    Origin (curl, scripts) is allowed — that's a local process, which
    could read the log files directly anyway.
  * Session names are confined to the log dir: bare *.jsonl filenames
    only, no separators, must exist.
  * There is NO gate-toggle endpoint. A state-changing localhost
    endpoint would be reachable by CSRF from any website; the web
    console observes, the terminal (tui --gate-control) acts.

Zero dependencies. Pure stdlib.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from glassport import tui
from glassport.adapters.streaming import StreamingSession

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
POLL_SECS = 0.25                 # ingest tick, same cadence as the TUI
PING_EVERY_TICKS = 120           # ~30s: detect stale connections
MAX_ROWS = 1000                  # plan 3.3 timeline bound
MAX_FINDINGS = 100               # plan 3.3 findings bound


# ─────────────────────────────────────────────────────────────────
# WebSocket primitives (RFC 6455) — pure, tested against RFC vectors
# ─────────────────────────────────────────────────────────────────

def ws_accept(key: str) -> str:
    """Sec-WebSocket-Accept for a Sec-WebSocket-Key."""
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def ws_encode_text(text: str) -> bytes:
    """One unmasked FIN text frame (server→client frames are unmasked)."""
    payload = text.encode("utf-8")
    n = len(payload)
    if n <= 125:
        head = bytes([0x81, n])
    elif n <= 0xFFFF:
        head = bytes([0x81, 126]) + struct.pack(">H", n)
    else:
        head = bytes([0x81, 127]) + struct.pack(">Q", n)
    return head + payload


def ws_encode_control(opcode: int, payload: bytes = b"") -> bytes:
    return bytes([0x80 | opcode, len(payload)]) + payload


class WSDecoder:
    """Incremental client→server frame decoder. feed(bytes) returns the
    complete frames as (opcode, unmasked_payload). Client frames are
    masked per RFC; unmasked ones are tolerated (payload passes as-is).
    Fragmentation (FIN=0) is not supported — our client never fragments;
    a fragmented frame surfaces as opcode 0 the caller treats as close.
    """

    def __init__(self) -> None:
        self._buf = b""

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        self._buf += data
        out: list[tuple[int, bytes]] = []
        while True:
            buf = self._buf
            if len(buf) < 2:
                return out
            opcode = buf[0] & 0x0F
            masked = bool(buf[1] & 0x80)
            n = buf[1] & 0x7F
            pos = 2
            if n == 126:
                if len(buf) < 4:
                    return out
                n = struct.unpack(">H", buf[2:4])[0]
                pos = 4
            elif n == 127:
                if len(buf) < 10:
                    return out
                n = struct.unpack(">Q", buf[2:10])[0]
                pos = 10
            mask = b""
            if masked:
                if len(buf) < pos + 4:
                    return out
                mask = buf[pos:pos + 4]
                pos += 4
            if len(buf) < pos + n:
                return out
            payload = buf[pos:pos + n]
            if masked:
                payload = bytes(b ^ mask[i % 4]
                                for i, b in enumerate(payload))
            self._buf = buf[pos + n:]
            out.append((opcode, payload))


# ─────────────────────────────────────────────────────────────────
# Guards
# ─────────────────────────────────────────────────────────────────

def origin_ok(origin: str | None, host_header: str) -> bool:
    """Accept absent Origin (non-browser callers) or an Origin whose
    authority equals the Host header — i.e. pages this server itself
    served. Everything else is another site's page doing cross-origin
    WebSocket; reject."""
    if origin is None:
        return True
    netloc = urlparse(origin).netloc
    return bool(netloc) and netloc == host_header


def safe_session(name: str, log_dir: Path) -> Path | None:
    """Confine a client-supplied session name to the log dir: a bare
    *.jsonl filename that exists. None for anything else."""
    if not name or name != Path(name).name or not name.endswith(".jsonl"):
        return None
    p = (Path(log_dir) / name)
    return p if p.is_file() else None


# ─────────────────────────────────────────────────────────────────
# ViewModel payload — the TUI's view-model, JSON-shaped and bounded
# ─────────────────────────────────────────────────────────────────

def tool_heatmap(trace) -> list[dict]:
    """Per-tool risk aggregate for the console heatmap."""
    from glassport.interaction_trace import EventKind, PartKind, \
        AnnotationKind
    fabricated = {n for _, n in trace.fabricated_tool_calls()}
    sev_by_event: dict[str, int] = {}
    for a in trace.annotations:
        if a.kind != AnnotationKind.INFO:
            sev_by_event[a.event_id] = max(
                sev_by_event.get(a.event_id, 0), a.severity)
    stats: dict[str, dict] = {}
    call_event_tool: dict[str, str] = {}
    for e in trace.events:
        if e.kind == EventKind.TOOL_CALL:
            for p in e.parts:
                if p.kind == PartKind.TOOL_USE:
                    name = p.content.get("name", "?")
                    call_event_tool[e.id] = name
                    s = stats.setdefault(name, {
                        "tool": name, "calls": 0, "errors": 0,
                        "max_severity": 0, "fabricated": name in fabricated})
                    s["calls"] += 1
                    s["max_severity"] = max(s["max_severity"],
                                            sev_by_event.get(e.id, 0))
        elif e.kind == EventKind.TOOL_RESULT:
            name = e.metadata.get("tool_name")
            if name in stats:
                for p in e.parts:
                    if p.kind == PartKind.TOOL_RESULT and \
                            p.content.get("is_error"):
                        stats[name]["errors"] += 1
                stats[name]["max_severity"] = max(
                    stats[name]["max_severity"],
                    sev_by_event.get(e.id, 0))
    return sorted(stats.values(),
                  key=lambda s: (-s["max_severity"], -s["calls"]))


def vm_payload(session: StreamingSession, live: bool,
               max_rows: int = MAX_ROWS,
               max_findings: int = MAX_FINDINGS) -> dict:
    """The TUI view-model as bounded, wire-ready JSON."""
    vm = tui.build_view_model(session.trace, live)
    rows = [asdict(r) for r in vm.rows[-max_rows:]]
    findings = [asdict(f) for f in vm.findings[:max_findings]]
    return {
        "title": vm.title,
        "live": vm.live,
        "declared": vm.declared,
        "counters": vm.counters,
        "gate_on": vm.gate_on,
        "gate_override": tui.read_gate_override(session.path),
        "rows": rows,
        "collapsed_rows": max(0, len(vm.rows) - max_rows),
        "first_row_index": max(0, len(vm.rows) - max_rows),
        "findings": findings,
        "more_findings": max(0, len(vm.findings) - max_findings),
        "heatmap": tool_heatmap(session.trace),
        "tail_only": session.tail_only,
    }


# ─────────────────────────────────────────────────────────────────
# HTTP + WS server
# ─────────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "ConsoleServer"

    def log_message(self, format, *args):     # noqa: A002 — stdlib name
        pass                                   # stderr stays quiet

    # ── helpers ─────────────────────────────────────────────────
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # the page is same-origin only; be explicit about it
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, code: int = 200) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False,
                                    default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, code: int, message: str) -> None:
        self._json({"error": message}, code=code)

    def _session_arg(self, qs: dict) -> Path | None:
        name = (qs.get("session") or [""])[0]
        return safe_session(name, self.server.log_dir)

    def _trace_for(self, path: Path):
        from glassport import detectors
        from glassport.adapters.mcp_session import from_mcp_session_file
        trace = from_mcp_session_file(path)
        detectors.annotate(trace)
        return trace

    # ── routes ──────────────────────────────────────────────────
    def do_GET(self) -> None:                 # noqa: N802 (stdlib name)
        try:
            url = urlparse(self.path)
            qs = parse_qs(url.query)
            route = url.path.rstrip("/") or "/"

            if route in ("/", "/console"):
                from glassport.console_html import CONSOLE_HTML
                self._send(200, CONSOLE_HTML.encode("utf-8"),
                           "text/html; charset=utf-8")
                return
            if route == "/ws":
                self._websocket()
                return
            if route == "/api/sessions":
                entries = tui.list_sessions(self.server.log_dir)
                self._json([{"name": e.path.name, "frames": e.frames,
                             "mtime": e.mtime, "live": e.live}
                            for e in entries])
                return
            if route == "/api/audit":
                self._api_audit()
                return
            if route in ("/api/advise", "/api/sarif",
                         "/api/drift", "/api/report"):
                p = self._session_arg(qs)
                if p is None:
                    self._error(400, "invalid or missing session")
                    return
                if route == "/api/advise":
                    from glassport.advise import render_advisory
                    trace = self._trace_for(p)
                    self._send(200, render_advisory(
                        None, trace.annotations,
                        min_severity=1).encode("utf-8"),
                        "text/markdown; charset=utf-8")
                elif route == "/api/sarif":
                    from glassport.sarif import render_session_sarif
                    trace = self._trace_for(p)
                    self._send(200, render_session_sarif(
                        trace, session_path=str(p)).encode("utf-8"),
                        "application/json; charset=utf-8")
                elif route == "/api/drift":
                    lines = tui.build_drift_lines(p, self.server.log_dir)
                    self._json([{"severity": s, "text": t}
                                for s, t in lines])
                else:
                    from glassport.report import render_html
                    trace = self._trace_for(p)
                    self._send(200, render_html(
                        trace, source_name=p.name).encode("utf-8"),
                        "text/html; charset=utf-8")
                return
            self._error(404, "not found")
        except BrokenPipeError:
            pass
        except Exception as exc:              # noqa: BLE001 — render tick
            try:
                self._error(500, f"{type(exc).__name__}")
            except Exception:
                pass

    def _api_audit(self) -> None:
        audit_dir = self.server.audit_dir
        if audit_dir is None:
            self._json({"available": False})
            return
        report = self.server.audit_report()
        if report is None:
            self._json({"available": False})
            return
        # rule + location only; Finding.detail embeds matched source
        # (attacker-controlled) and never leaves the server
        self._json({
            "available": True,
            "score": report.score,
            "grade": report.grade,
            "rubric_version": report.rubric_version,
            "findings": [{"rule": f.rule, "severity": f.severity,
                          "path": f.path, "line": f.line,
                          "count": f.count}
                         for f in report.findings],
        })

    # ── WebSocket ───────────────────────────────────────────────
    def _websocket(self) -> None:
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if not origin_ok(origin, host):
            self._send(403, b"cross-origin websocket rejected",
                       "text/plain")
            return
        key = self.headers.get("Sec-WebSocket-Key")
        if self.headers.get("Upgrade", "").lower() != "websocket" \
                or not key:
            self._error(400, "not a websocket upgrade")
            return
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept(key))
        self.end_headers()
        self.wfile.flush()
        self._ws_loop()

    def _ws_loop(self) -> None:
        sock = self.connection
        sock.settimeout(POLL_SECS)
        decoder = WSDecoder()
        attached: dict[str, StreamingSession] = {}
        dirty: set[str] = set()          # needs a push (first or changed)
        ticks = 0
        awaiting_pong = False
        while True:
            # ── input ────────────────────────────────────────────
            try:
                data = sock.recv(65536)
                if not data:
                    return
                frames = decoder.feed(data)
            except TimeoutError:
                frames = []
            except OSError:
                return
            for opcode, payload in frames:
                if opcode == 8:              # close
                    try:
                        sock.sendall(ws_encode_control(8))
                    except OSError:
                        pass
                    return
                if opcode == 9:              # ping -> pong
                    sock.sendall(ws_encode_control(10, payload))
                    continue
                if opcode == 10:             # pong
                    awaiting_pong = False
                    continue
                if opcode != 1:
                    return                   # binary/fragment: not ours
                try:
                    msg = json.loads(payload)
                except ValueError:
                    continue
                name = msg.get("attach")
                if isinstance(name, str):
                    p = safe_session(name, self.server.log_dir)
                    if p is not None and name not in attached:
                        attached[name] = StreamingSession(p)
                        attached[name].poll()
                        dirty.add(name)
                    elif p is None:
                        sock.sendall(ws_encode_text(json.dumps(
                            {"type": "error",
                             "error": "unknown session"})))
                name = msg.get("detach")
                if isinstance(name, str):
                    attached.pop(name, None)
                    dirty.discard(name)

            # ── ingest + push ───────────────────────────────────
            for name, session in attached.items():
                if session.poll():
                    dirty.add(name)
            try:
                for name in sorted(dirty):
                    session = attached.get(name)
                    if session is None:
                        continue
                    live = self._is_live(session.path)
                    sock.sendall(ws_encode_text(json.dumps(
                        {"type": "vm", "session": name,
                         "vm": vm_payload(session, live)},
                        ensure_ascii=False, default=str)))
                dirty.clear()
                ticks += 1
                if ticks % PING_EVERY_TICKS == 0:
                    if awaiting_pong:
                        return               # stale: no pong since last
                    awaiting_pong = True
                    sock.sendall(ws_encode_control(9, b"glassport"))
            except OSError:
                return

    @staticmethod
    def _is_live(path: Path) -> bool:
        try:
            return (time.time() - path.stat().st_mtime) \
                < tui.LIVE_WINDOW_SECS
        except OSError:
            return False


class ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, log_dir: Path, host: str = "127.0.0.1",
                 port: int = 8080, audit_dir: Path | None = None) -> None:
        self.log_dir = Path(log_dir)
        self.audit_dir = audit_dir
        self._audit_report = None
        self._audit_ran = False
        self._audit_lock = threading.Lock()
        super().__init__((host, port), _Handler)

    @property
    def host(self) -> str:
        return str(self.server_address[0])

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def audit_report(self):
        """Static audit of --audit PATH, run once, thread-safe."""
        with self._audit_lock:
            if not self._audit_ran:
                self._audit_ran = True
                if self.audit_dir is not None:
                    try:
                        from glassport.audit import audit_path
                        self._audit_report = audit_path(self.audit_dir)
                    except Exception:        # noqa: BLE001
                        self._audit_report = None
            return self._audit_report


def main(argv: list[str]) -> int:
    import sys
    host, port = "127.0.0.1", 8080
    log_dir = None
    audit_dir = None
    args = list(argv)
    i = 0
    try:
        while i < len(args):
            a = args[i]
            if a == "--port":
                port = int(args[i + 1]); i += 2
            elif a == "--bind":
                host = args[i + 1]; i += 2
            elif a == "--log-dir":
                log_dir = Path(args[i + 1]); i += 2
            elif a == "--audit":
                audit_dir = Path(args[i + 1]); i += 2
            else:
                raise ValueError(a)
    except (IndexError, ValueError):
        print("usage: glassport serve --http [--port N] [--bind HOST] "
              "[--log-dir DIR] [--audit PATH]", file=sys.stderr)
        return 2
    if log_dir is None:
        from glassport.tap import DEFAULT_LOG_DIR
        log_dir = DEFAULT_LOG_DIR
    server = ConsoleServer(log_dir, host=host, port=port,
                           audit_dir=audit_dir)
    print(f"[glassport] console: http://{server.host}:{server.port}"
          f"/console · log dir: {log_dir}"
          + (" · bound beyond loopback — anyone on the network can "
             "read your session streams" if host != "127.0.0.1" else ""),
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
