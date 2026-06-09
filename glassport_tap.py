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

    def record(self, direction: str, line: bytes) -> None:
        """Log one wire line. Never raises — relay must outlive logging."""
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
                self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # logging is best-effort; the relay is sacred

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────
# Pump — moves lines from one fd to another, tapping each line.
# ─────────────────────────────────────────────────────────────────
def pump(src, dst, log: SessionLog | None, direction: str) -> None:
    """
    Read newline-delimited lines from src, write them unmodified to dst,
    and tap each into the session log. Binary-safe; preserves the exact
    bytes including the newline.
    """
    try:
        for line in iter(src.readline, b""):
            dst.write(line)
            dst.flush()
            if log is not None:
                log.record(direction, line)
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
def run_tap(server_cmd: list[str], log_dir: Path) -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = "".join(c if c.isalnum() else "_" for c in server_cmd[0])[:32]
    log_path = log_dir / f"{stamp}_{safe_name}_{os.getpid()}.jsonl"
    log = SessionLog(log_path)

    # Announce on stderr only — stdout belongs to the protocol.
    print(f"[glassport] tapping: {shlex.join(server_cmd)}", file=sys.stderr)
    print(f"[glassport] session log: {log_path}", file=sys.stderr)

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

    threads = [
        threading.Thread(target=pump, daemon=True,
                         args=(stdin_b, child.stdin, log, "c2s")),
        threading.Thread(target=pump, daemon=True,
                         args=(child.stdout, stdout_b, log, "s2c")),
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
    log.close()
    print(f"[glassport] session ended (exit {rc}); "
          f"log: {log_path}", file=sys.stderr)
    return rc


# ─────────────────────────────────────────────────────────────────
# Summarize mode — M2. Declared vs called vs delta, computed on an
# InteractionTrace via adapters/mcp_session.py so this CLI and the
# Understanding Layer read the wire through one code path.
# ─────────────────────────────────────────────────────────────────
def summarize(log_path: Path) -> int:
    """
    Render the declared/called/fabricated delta for one session log.

    The log is first lifted into an InteractionTrace by the
    from_mcp_session adapter; everything printed here is derived from
    the trace, never from the raw JSONL. Tap mode stays standalone —
    only summarize requires the Understanding Layer modules.
    """
    try:
        from adapters.mcp_session import from_mcp_session_file
        from interaction_trace import PartKind
    except ImportError:
        # Allow summarize to work when the tap is invoked from another
        # cwd or imported as a module: the repo root is this file's dir.
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            from adapters.mcp_session import from_mcp_session_file
            from interaction_trace import PartKind
        except ImportError:
            print("[glassport] summarize needs interaction_trace.py and "
                  "adapters/mcp_session.py alongside this script.\n"
                  "[glassport] tap mode is standalone; summarize is not.",
                  file=sys.stderr)
            return 1

    trace = from_mcp_session_file(log_path)

    seq_of = {e.id: e.metadata.get("seq", -1) for e in trace.events}
    # one event per parsed frame; raw wire lines carry the unparsed flag
    frames = sum(1 for e in trace.events if not e.metadata.get("unparsed"))
    declared = trace.declared_tools()
    called = [(seq_of[eid], name) for eid, name in trace.called_tools()]
    fabricated = [(seq_of[eid], name)
                  for eid, name in trace.fabricated_tool_calls()]
    unused = sorted(declared - {n for _, n in called})

    errors: list[tuple[int, str]] = []          # (seq, message)
    for e in trace.events:
        for p in e.parts:
            if p.kind == PartKind.ERROR:
                errors.append((e.metadata.get("seq", -1),
                               str(e.metadata.get("error_message", p.content))))
            elif p.kind == PartKind.TOOL_RESULT and p.content.get("is_error"):
                out = p.content.get("output")
                msg = out.get("message", str(out)) if isinstance(out, dict) \
                    else str(out)
                errors.append((e.metadata.get("seq", -1), msg))

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
    return 0


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
USAGE = """\
glassport_tap — passive MCP stdio proxy (M0)

  tap (default):   glassport_tap.py [--log-dir DIR] -- <server command...>
  summarize:       glassport_tap.py summarize <session.jsonl>
"""


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0

    if argv[0] == "summarize":
        if len(argv) != 2:
            print(USAGE)
            return 2
        return summarize(Path(argv[1]))

    log_dir = DEFAULT_LOG_DIR
    if argv[0] == "--log-dir":
        log_dir = Path(argv[1])
        argv = argv[2:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print(USAGE)
        return 2
    return run_tap(argv, log_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
