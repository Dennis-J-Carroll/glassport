#!/usr/bin/env python3
"""
glassport_tap — M0 of the Glassport active proxy.

A passive stdio man-in-the-middle for MCP servers. Drop it between any
MCP client (Claude Desktop, Cursor, Claude Code) and any stdio MCP
server. It relays every byte faithfully and logs every JSON-RPC frame
to a JSONL session file.

    The glass before the port. Observe first. Enforce later.

Usage (wrap mode — replaces the server command in your MCP config):

    {
      "mcpServers": {
        "exa": {
          "command": "python3",
          "args": ["/path/to/glassport_tap.py", "--", "npx", "exa-mcp-server"]
        }
      }
    }

Usage (summarize mode — read a session log after the fact):

    python3 glassport_tap.py summarize ~/.glassport/sessions/<file>.jsonl

Design constraints honored:
  * Zero dependencies. Pure stdlib. Runs in Termux.
  * Byte-faithful relay. The tap must NEVER alter, reorder, or delay
    frames beyond pipe latency. If logging fails, relaying continues.
  * Newline-delimited JSON framing per MCP stdio transport. Lines that
    don't parse as JSON are relayed verbatim and logged as raw.
  * Crash-isolated: a logging bug must not kill the session.

Frame log schema (one JSON object per line):
  {
    "schema_version": "0.1",
    "seq":  int,            # monotonic per session, both directions
    "ts":   str,            # ISO 8601 UTC
    "dir":  "c2s" | "s2c",  # client→server or server→client
    "frame": dict | null,   # parsed JSON-RPC frame, if parseable
    "raw":  str | null      # raw line, only when parsing failed
  }

This log is the precursor wire format for InteractionTrace: the
from_mcp_session() adapter consumes exactly these records, and the
summarize command routes through that same adapter — one code path
from wire to report.

Author: Dennis J. Carroll · 2026 (skeleton drafted with Claude)
"""
from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "0.1"
DEFAULT_LOG_DIR = Path(os.environ.get("GLASSPORT_LOG_DIR",
                                      Path.home() / ".glassport" / "sessions"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────
# Session logger — append-only JSONL, thread-safe, failure-isolated.
# ─────────────────────────────────────────────────────────────────
class SessionLog:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        # line-buffered text append; survives abrupt termination well
        self._fh = open(path, "a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()
        self._seq = 0
        self.path = path

    def record(self, direction: str, line: bytes,
               gate: dict | None = None) -> None:
        """Log one wire line. Never raises — relay must outlive logging.

        `gate` marks frames the gate acted on: {"action": "blocked"} on a
        c2s frame the server never received, {"action": "injected"} on an
        s2c frame the server never sent. Optional field — schema 0.1 logs
        without it stay readable, readers without it stay correct.
        """
        try:
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            frame, raw = None, None
            try:
                frame = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                raw = text
            with self._lock:
                self._seq += 1
                entry = {
                    "schema_version": SCHEMA_VERSION,
                    "seq": self._seq,
                    "ts": _now_iso(),
                    "dir": direction,
                    "frame": frame,
                    "raw": raw,
                }
                if gate is not None:
                    entry["gate"] = gate
                self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # logging is best-effort; the relay is sacred

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────
# Gate — M5. Active enforcement on the c2s path. Opt-in, last, on
# purpose: it ships only because the passive detectors came first.
# ─────────────────────────────────────────────────────────────────
class Gate:
    """
    Blocks c2s tools/call frames that name a tool outside the server's
    declared surface. Everything else relays untouched.

    The gate only blocks what the wire can prove. Until a tools/list
    response has been seen there is no declaration to violate — but a
    pipelined client may fire tools/call before that response lands, so
    the gate HOLDS such calls (blocking the c2s pump; stdio backpressure
    is the flow control a real client expects anyway) until the surface
    arrives or `hold_timeout` expires. On timeout it fails open and the
    forwarded frame is logged with a "gate_skipped" marker, so the log
    still shows enforcement was impossible. The latest tools/list result
    IS the contract: a server that re-declares a smaller surface shrinks
    what it may be asked to do.

    A blocked request never reaches the server; the client receives a
    synthesized JSON-RPC error (code -32000) whose error.data carries
    {"glassport": "gate_blocked"} so callers can tell the gate's voice
    from the server's. Both the blocked frame and the injected response
    are logged with a "gate" marker — the session log records what each
    side actually saw, and they legitimately differ.
    """

    def __init__(self, hold_timeout: float = 2.0) -> None:
        self._lock = threading.Lock()
        self._declared: set[str] | None = None   # None until tools/list seen
        self._surface_known = threading.Event()
        self._hold_timeout = hold_timeout
        self.blocked_count = 0

    def observe_s2c(self, line: bytes) -> None:
        """Harvest tool declarations from server output. Never raises."""
        try:
            frame = json.loads(line)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return
        if not isinstance(frame, dict):
            return
        result = frame.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            names = {t["name"] for t in result["tools"]
                     if isinstance(t, dict) and "name" in t}
            with self._lock:
                self._declared = names
            self._surface_known.set()

    def check_c2s(self, line: bytes
                  ) -> tuple[str, bytes | None, dict | None]:
        """
        Decide one client→server line. Returns (action, response, info):
        action "forward" relays the line untouched; "block" drops it,
        sends `response` (bytes, or None for id-less calls) back to the
        client, and logs `info` on the blocked entry.
        """
        try:
            frame = json.loads(line)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return ("forward", None, None)   # not ours to judge
        if not isinstance(frame, dict) or frame.get("method") != "tools/call":
            return ("forward", None, None)

        name = (frame.get("params") or {}).get("name")
        with self._lock:
            declared = self._declared
        if declared is None:
            # pipelined client: hold the call until the tools/list
            # response lands; the s2c pump will wake us via observe_s2c
            self._surface_known.wait(timeout=self._hold_timeout)
            with self._lock:
                declared = self._declared
            if declared is None:
                # server never declared a surface — fail open, visibly
                return ("forward", None,
                        {"action": "gate_skipped",
                         "reason": "no_surface_timeout", "tool": name})
        if name in declared:
            return ("forward", None, None)

        self.blocked_count += 1
        rid = frame.get("id")
        response = None
        if rid is not None:
            response = (json.dumps({
                "jsonrpc": "2.0", "id": rid,
                "error": {
                    "code": -32000,
                    "message": (f"glassport gate: tools/call '{name}' "
                                f"blocked — not in the declared tool "
                                f"surface"),
                    "data": {"glassport": "gate_blocked", "tool": name,
                             "declared": sorted(declared)},
                },
            }, ensure_ascii=False) + "\n").encode("utf-8")
        info = {"action": "blocked", "tool": name,
                "declared": sorted(declared)}
        return ("block", response, info)


# ─────────────────────────────────────────────────────────────────
# Pump — moves lines from one fd to another, tapping each line.
# ─────────────────────────────────────────────────────────────────
def pump(src, dst, log: SessionLog | None, direction: str,
         gate: Gate | None = None, client_write=None,
         dst_lock: threading.Lock | None = None) -> None:
    """
    Read newline-delimited lines from src, write them unmodified to dst,
    and tap each into the session log. Binary-safe; preserves the exact
    bytes including the newline.

    With a gate: c2s lines are checked before forwarding — a blocked
    line never reaches dst, and the synthesized error goes back to the
    client via client_write. s2c lines feed the gate's view of the
    declared surface. dst_lock serializes client-bound writes so an
    injected error can't interleave with a real server response.
    """
    try:
        for line in iter(src.readline, b""):
            gate_info = None   # marker for forwarded-but-noteworthy frames
            if gate is not None and direction == "c2s":
                action, response, info = gate.check_c2s(line)
                if action == "block" and info is not None:
                    if log is not None:
                        log.record(direction, line, gate=info)
                    if response is not None and client_write is not None:
                        client_write(response)
                        if log is not None:
                            log.record("s2c", response,
                                       gate={"action": "injected",
                                             "tool": info["tool"]})
                    continue
                gate_info = info   # e.g. gate_skipped fail-open
            elif gate is not None and direction == "s2c":
                gate.observe_s2c(line)
            if dst_lock is not None:
                with dst_lock:
                    dst.write(line)
                    dst.flush()
            else:
                dst.write(line)
                dst.flush()
            if log is not None:
                log.record(direction, line, gate=gate_info)
    except (BrokenPipeError, ValueError, OSError):
        pass  # one side hung up; let the session wind down
    finally:
        try:
            dst.close()
        except Exception:
            pass


def pump_stderr(src, dst) -> None:
    """Pass the child's stderr through untouched (no framing assumed)."""
    try:
        for chunk in iter(lambda: src.read(4096), b""):
            dst.write(chunk)
            dst.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass


# ─────────────────────────────────────────────────────────────────
# Tap mode — spawn the real server and sit in the middle.
# ─────────────────────────────────────────────────────────────────
def run_tap(server_cmd: list[str], log_dir: Path,
            gate: Gate | None = None) -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = "".join(c if c.isalnum() else "_" for c in server_cmd[0])[:32]
    log_path = log_dir / f"{stamp}_{safe_name}_{os.getpid()}.jsonl"
    # The relay is sacred: a logging failure must never alter, delay, or kill
    # a live session. If the log dir is unwritable, disable logging and relay
    # anyway — pump() already tolerates a None log.
    try:
        log = SessionLog(log_path)
    except OSError as exc:
        print(f"[glassport] logging disabled ({exc}); relay continues",
              file=sys.stderr)
        log = None

    # Announce on stderr only — stdout belongs to the protocol.
    print(f"[glassport] tapping: {shlex.join(server_cmd)}", file=sys.stderr)
    print(f"[glassport] session log: {log_path}", file=sys.stderr)
    if gate is not None:
        print("[glassport] GATE ACTIVE: tools/call frames outside the "
              "declared surface will be blocked", file=sys.stderr)

    try:
        child = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,  # unbuffered — frames must not sit in a buffer
        )
    except FileNotFoundError:
        print(f"[glassport] command not found: {server_cmd[0]}", file=sys.stderr)
        return 127

    stdin_b = sys.stdin.buffer
    stdout_b = sys.stdout.buffer

    # One lock for everything client-bound: real server responses and
    # gate-injected errors must never interleave mid-line.
    out_lock = threading.Lock()

    def client_write(data: bytes) -> None:
        with out_lock:
            stdout_b.write(data)
            stdout_b.flush()

    threads = [
        threading.Thread(target=pump, daemon=True,
                         args=(stdin_b, child.stdin, log, "c2s"),
                         kwargs={"gate": gate, "client_write": client_write}),
        threading.Thread(target=pump, daemon=True,
                         args=(child.stdout, stdout_b, log, "s2c"),
                         kwargs={"gate": gate, "dst_lock": out_lock}),
        threading.Thread(target=pump_stderr, daemon=True,
                         args=(child.stderr, sys.stderr.buffer)),
    ]
    for t in threads:
        t.start()

    # Forward termination signals to the child so configs behave normally.
    def _forward(sig, _frame):
        try:
            child.send_signal(sig)
        except Exception:
            pass
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, _forward)

    rc = child.wait()
    time.sleep(0.1)  # let pumps drain their last lines
    if log is not None:
        log.close()
    log_note = str(log_path) if log is not None else "(logging disabled)"
    suffix = f"; blocked {gate.blocked_count} call(s)" \
        if gate is not None and gate.blocked_count else ""
    print(f"[glassport] session ended (exit {rc}){suffix}; "
          f"log: {log_note}", file=sys.stderr)
    return rc


# ─────────────────────────────────────────────────────────────────
# Summarize mode — M2. Declared vs called vs delta, computed on an
# InteractionTrace via adapters/mcp_session.py so this CLI and the
# Understanding Layer read the wire through one code path.
# ─────────────────────────────────────────────────────────────────
def summarize(log_path: Path, as_json: bool = False, as_sarif: bool = False) -> int:
    """
    Render the declared/called/fabricated delta for one session log.

    The log is first lifted into an InteractionTrace by the
    from_mcp_session adapter; everything printed here is derived from
    the trace, never from the raw JSONL. Tap mode stays standalone —
    only summarize requires the Understanding Layer modules.

    With as_json the same facts are emitted as one JSON object, so an
    agent can shell out to `glassport summarize --json` and parse the
    result instead of scraping the human rendering.
    """
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import context_violations
    from glassport.interaction_trace import PartKind

    trace = from_mcp_session_file(log_path)

    if as_sarif:
        from glassport.detectors import annotate
        from glassport.sarif import render_session_sarif
        annotate(trace)            # mutates trace.annotations in place
        base = "" if os.path.isabs(str(log_path)) else str(log_path.parent)
        print(render_session_sarif(trace, log_path.name, base=base))
        return 0

    seq_of = {e.id: e.metadata.get("seq", -1) for e in trace.events}
    # one event per parsed frame; raw wire lines carry the unparsed flag
    frames = sum(1 for e in trace.events if not e.metadata.get("unparsed"))
    declared = trace.declared_tools()
    called = [(seq_of[eid], name) for eid, name in trace.called_tools()]
    fabricated = [(seq_of[eid], name)
                  for eid, name in trace.fabricated_tool_calls()]
    unused = sorted(declared - {n for _, n in called})

    # Two distinct failure modes, kept apart: a JSON-RPC *protocol* error
    # (the `error` member — malformed/unknown method) versus a valid
    # tools/call *result* carrying isError=true (the tool ran, the
    # operation failed). Conflating them inflates the protocol-error count
    # with ordinary denied-access / validation results.
    errors: list[tuple[int, str]] = []          # protocol errors (seq, message)
    tool_errors: list[tuple[int, str]] = []     # isError results (seq, message)
    for e in trace.events:
        for p in e.parts:
            if p.kind == PartKind.ERROR:
                errors.append((e.metadata.get("seq", -1),
                               str(e.metadata.get("error_message", p.content))))
            elif p.kind == PartKind.TOOL_RESULT and p.content.get("is_error"):
                out = p.content.get("output")
                msg = out.get("message", str(out)) if isinstance(out, dict) \
                    else str(out)
                tool_errors.append((e.metadata.get("seq", -1), msg))

    violations = sorted(context_violations(trace),
                        key=lambda a: (a.metadata.get("seq") or 0))

    if as_json:
        print(json.dumps({
            "session": log_path.name,
            "frames_parsed": frames,
            "declared_tools": sorted(declared),
            "called_tools": [n for _, n in called],
            "unused_declared": unused,
            "fabricated_calls": [{"seq": s, "tool": n}
                                 for s, n in fabricated],
            "protocol_errors": [{"seq": s, "message": m}
                                for s, m in errors],
            "tool_errors": [{"seq": s, "message": m}
                            for s, m in tool_errors],
            "context_violations": [
                {"severity": a.severity, "subcategory": a.subcategory,
                 "seq": a.metadata.get("seq"), "explanation": a.explanation}
                for a in violations],
        }, indent=2, ensure_ascii=False))
        return 0

    print(f"session: {log_path.name}")
    print(f"frames parsed:    {frames}")
    print(f"declared tools:   {sorted(declared) or '— (no tools/list seen)'}")
    print(f"called tools:     {[n for _, n in called] or '—'}")
    print(f"unused declared:  {unused or '—'}")
    if fabricated:
        print(f"FABRICATED CALLS: {fabricated}   <-- calls outside the "
              f"declared surface")
    else:
        print("fabricated calls: none")
    if errors:
        print(f"protocol errors:  {errors}")
    if tool_errors:
        print(f"tool errors:      {tool_errors}   <-- server-side isError "
              f"results (the tool ran, the operation failed)")

    if violations:
        print("CONTEXT VIOLATIONS:")
        for a in violations:
            print(f"  [sev {a.severity}] seq {a.metadata.get('seq')} "
                  f"{a.subcategory}: {a.explanation}")
    else:
        print("context violations: none")
    return 0


# ─────────────────────────────────────────────────────────────────
# Detect mode — run every behavioral detector over one session log
# and print the findings. Exit 1 when anything was found (grep-style)
# so scripts and CI can branch on the result.
# ─────────────────────────────────────────────────────────────────
def _cmd_detect(log_path: Path, as_sarif: bool = False) -> int:
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import annotate

    trace = from_mcp_session_file(log_path)
    annotations = annotate(trace)
    if as_sarif:
        from glassport.sarif import render_session_sarif
        base = "" if os.path.isabs(str(log_path)) else str(log_path.parent)
        print(render_session_sarif(trace, log_path.name, base=base))
        return 0
    if not annotations:
        print(f"detect: {log_path.name} — no findings")
        return 0
    print(f"detect: {log_path.name} — {len(annotations)} finding(s)\n")
    for a in sorted(annotations,
                    key=lambda x: (-x.severity, x.metadata.get("seq") or 0)):
        sev_label = {1: "INFO", 2: "WARN", 3: "HIGH"}.get(
            a.severity, str(a.severity))
        print(f"  [{sev_label}] seq={a.metadata.get('seq', '?')} "
              f"{a.subcategory}: {a.explanation}")
    return 1


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
USAGE = """\
glassport — passive MCP stdio proxy

  wrap (default):  glassport [wrap] [--log-dir DIR] -- <server command...>
  gate:            glassport gate [--log-dir DIR] -- <server command...>
                   (active: blocks tools/call outside the declared surface)
  audit:           glassport audit <path> [--json] | audit --rubric
                   (static, pre-deployment: reads source, never runs it)
  summarize:       glassport summarize [--json|--sarif] <session.jsonl>
  detect:          glassport detect [--sarif] <session.jsonl>
                   (run all behavioral detectors; exit 1 if findings,
                    or emit SARIF 2.1.0 with --sarif)
  report:          glassport report <session.jsonl> [-o out.html]
  watch:           glassport watch [log-dir] [--json]
  serve:           glassport serve [--log-dir DIR]
                   (expose glassport itself as a queryable MCP server)
  tui:             glassport tui [session.jsonl] [--log-dir DIR]
                   (live curses inspector; no argument = session picker)

(`python3 glassport_tap.py ...` from a clone works identically.)
"""


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0

    # "wrap" stays the passive default forever; "gate" is the opt-in
    # enforcing sibling it was reserved for (M5)
    gate: Gate | None = None
    if argv[0] == "wrap":
        argv = argv[1:]
    elif argv[0] == "gate":
        gate = Gate()
        argv = argv[1:]
    if not argv:
        print(USAGE)
        return 2

    if argv[0] == "summarize":
        args = argv[1:]
        as_json = "--json" in args
        as_sarif = "--sarif" in args
        args = [a for a in args if not a.startswith("--")]
        if len(args) != 1:
            print("usage: glassport summarize [--json|--sarif] <session.jsonl>",
                  file=sys.stderr)
            return 2
        return summarize(Path(args[0]), as_json=as_json, as_sarif=as_sarif)

    if argv[0] == "detect":
        args = argv[1:]
        as_sarif = "--sarif" in args
        args = [a for a in args if not a.startswith("--")]
        if len(args) != 1:
            print(USAGE)
            return 2
        return _cmd_detect(Path(args[0]), as_sarif=as_sarif)

    if argv[0] == "serve":
        # glassport as a queryable MCP audit server. Lazy import.
        from glassport import server as server_mod
        return server_mod.main(argv[1:])

    if argv[0] == "report":
        # M3 — static HTML render. Lazy import keeps tap mode import-light.
        from glassport import report as report_mod
        return report_mod.main(argv[1:])

    if argv[0] == "watch":
        # M4 — drift across sessions. Same lazy-import contract.
        from glassport import watch as watch_mod
        return watch_mod.main(argv[1:])

    if argv[0] == "audit":
        # static pre-deployment audit; standalone module, no trace deps
        from glassport import audit as audit_mod
        return audit_mod.main(argv[1:])

    if argv[0] == "tui":
        # live/replay curses inspector. Same lazy-import contract.
        from glassport import tui as tui_mod
        return tui_mod.main(argv[1:])

    log_dir = DEFAULT_LOG_DIR
    if argv[0] == "--log-dir":
        log_dir = Path(argv[1])
        argv = argv[2:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print(USAGE)
        return 2
    return run_tap(argv, log_dir, gate=gate)


def cli() -> None:
    """Console-script entry point (``glassport`` command)."""
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    cli()
