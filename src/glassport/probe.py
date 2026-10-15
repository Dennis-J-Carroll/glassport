"""
glassport probe — one command from "server command" to "HTML report".

    glassport probe [--call NAME JSON]... [--log-dir DIR] [--timeout S]
                    [--startup-timeout S] [-o out.html] [--json] [--open]
                    -- <server command...>

`wrap` is passive: with no client attached nothing happens. `probe` is the
missing client. It launches the server behind the real tap (so the session
log is byte-for-byte what `wrap` would record), drives initialize ->
notifications/initialized -> tools/list, optionally exercises tools named
with --call, then runs the detectors and writes the report.

List-only by default: no tool runs unless you name it with --call.

A server that dies, errors, or hangs mid-handshake still gets a report —
the partial trace is the finding — but it is marked INCOMPLETE with the
stage it stopped at, and never reads as CLEAN. Exit codes:

    0  handshake complete, no findings
    1  handshake complete, detector findings
    2  usage error, or no session log to analyze
    3  handshake incomplete (takes priority over 1)
"""
from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

PROTOCOL_VERSION = "2025-06-18"
_BOOT = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
         "from glassport.tap import cli; cli()")
_STDERR_TAIL = 4096

USAGE = ("usage: glassport probe [--call NAME JSON]... [--log-dir DIR] "
         "[--timeout S] [--startup-timeout S] [-o out.html] [--json] [--open] "
         "-- <server command...>")


@dataclass
class ProbeResult:
    cmd: list[str]
    handshake: dict[str, Any]
    log_path: Optional[Path]
    report_path: Optional[Path]
    declared_tools: list[str] = field(default_factory=list)
    called_tools: list[str] = field(default_factory=list)
    findings: int = 0
    max_severity: int = 0
    stderr_tail: str = ""
    exit_code: int = 2

    def to_json(self) -> dict:
        return {
            "cmd": self.cmd,
            "handshake": self.handshake,
            "log": str(self.log_path) if self.log_path else None,
            "report": str(self.report_path) if self.report_path else None,
            "declared": self.declared_tools,
            "called": self.called_tools,
            "findings": self.findings,
            "max_severity": self.max_severity,
            "stderr_tail": self.stderr_tail,
            "exit_code": self.exit_code,
        }


def _rpc(rid: Optional[int], method: str, params: Optional[dict] = None) -> dict:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        msg["id"] = rid
    if params is not None:
        msg["params"] = params
    return msg


class _Client:
    """Line-oriented JSON-RPC client over the tap's stdio, with deadlines."""

    def __init__(self, proc: subprocess.Popen):
        self.proc = proc
        self.inbox: queue.Queue = queue.Queue()
        self.stderr: list[str] = []
        self.eof = False
        threading.Thread(target=self._read_stdout, daemon=True).start()
        self._stderr_thread = threading.Thread(target=self._read_stderr,
                                               daemon=True)
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            try:
                self.inbox.put(json.loads(raw))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue    # the tap logged it; the client just skips it
        self.inbox.put(None)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            self.stderr.append(raw.decode("utf-8", "replace"))

    def send(self, msg: dict) -> bool:
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
            return True
        except (BrokenPipeError, OSError, ValueError):
            return False

    def request(self, rid: int, method: str, params: Optional[dict],
                timeout: float) -> tuple[Optional[dict], Optional[str]]:
        """Send a request and wait for its response.
        Returns (response, None) or (None, "exited" | "timeout")."""
        if self.eof or not self.send(_rpc(rid, method, params)):
            return None, "exited"
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, "timeout"
            try:
                msg = self.inbox.get(timeout=remaining)
            except queue.Empty:
                return None, "timeout"
            if msg is None:
                self.eof = True
                return None, "exited"
            # server notifications and server->client requests are logged
            # by the tap; the probe only waits on its own response
            if isinstance(msg, dict) and msg.get("id") == rid and \
                    ("result" in msg or "error" in msg):
                return msg, None

    def shutdown(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            _signal_group(self.proc, signal.SIGTERM)
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                _signal_group(self.proc, getattr(signal, "SIGKILL",
                                                 signal.SIGTERM))
                self.proc.wait()
        self._stderr_thread.join(timeout=2.0)


def _signal_group(proc: subprocess.Popen, sig: int) -> None:
    """Signal the tap *and* the server it spawned (npx -> node chains
    otherwise outlive a killed tap)."""
    try:
        if os.name == "posix":
            os.killpg(proc.pid, sig)
        else:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           capture_output=True, check=False)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _spawn_tap(cmd: list[str], log_dir: Path) -> subprocess.Popen:
    # Run the tap from the same interpreter with this package importable,
    # so a source checkout and an installed wheel behave the same. The path
    # goes onto the tap's sys.path, never into PYTHONPATH: the tap's env is
    # inherited by the server, and an injected site-packages there would
    # shadow a Python server's own deps — the session must be exactly what
    # `wrap` records. stdin/stdout stay binary: nothing is re-encoded.
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    return subprocess.Popen(
        [sys.executable, "-c", _BOOT, pkg_parent, "wrap",
         "--log-dir", str(log_dir), "--", *cmd],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=(os.name == "posix"),
    )


def _drive(client: _Client, calls: list[tuple[str, dict]],
           startup_timeout: float, timeout: float) -> dict[str, Any]:
    """Run the handshake. Returns {completed, failed_at, reason}."""
    def fail(stage: str, reason: str) -> dict[str, Any]:
        return {"completed": False, "failed_at": stage, "reason": reason}

    resp, err = client.request(1, "initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        # strict servers reject an initialize without clientInfo
        "clientInfo": {"name": "glassport-probe", "version": _version()},
    }, startup_timeout)
    if err or resp is None:
        return fail("initialize", err or "exited")
    if "error" in resp:
        return fail("initialize", "error_response")
    client.send(_rpc(None, "notifications/initialized"))

    resp, err = client.request(2, "tools/list", {}, timeout)
    if err or resp is None:
        return fail("tools_list", err or "exited")
    if "error" in resp:
        return fail("tools_list", "error_response")

    # A call answered with an error is a complete exchange — whether it
    # *should* have been called is the detectors' question, not ours.
    for rid, (name, args) in enumerate(calls, start=3):
        _, err = client.request(rid, "tools/call",
                                {"name": name, "arguments": args}, timeout)
        if err:
            return fail("call", err)
    return {"completed": True, "failed_at": None, "reason": None}


def _version() -> str:
    from glassport import __version__
    return __version__


def _find_log(log_dir: Path, tap_pid: int) -> Optional[Path]:
    # The tap names its log `<stamp>_<server>_<tap pid>.jsonl`. Matching on
    # our own tap's pid never picks up a concurrent session in a shared log
    # dir (a live `wrap`, a parallel survey probe) — and unlike parsing
    # stderr, the server can't spoof it.
    files = sorted(log_dir.glob(f"*_{tap_pid}.jsonl"),
                   key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def probe(cmd: list[str], calls: Optional[list[tuple[str, dict]]] = None,
          log_dir: Optional[Path] = None, out_path: Optional[Path] = None,
          startup_timeout: float = 60.0, timeout: float = 15.0) -> ProbeResult:
    """Drive `cmd` through the tap, analyze the session, write the report.

    startup_timeout bounds `initialize` (a first-run npx download fetches the
    package before the server can answer); timeout bounds each later step.
    """
    from glassport import detectors
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.interaction_trace import AnnotationKind
    from glassport.report import render_html
    from glassport.tap import DEFAULT_LOG_DIR

    log_dir = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)

    proc = _spawn_tap(cmd, log_dir)
    client = _Client(proc)
    try:
        handshake = _drive(client, list(calls or []), startup_timeout, timeout)
    finally:
        client.shutdown()

    # the tap exits 127 when the server binary is missing: nothing ever ran
    if not handshake["completed"] and handshake["failed_at"] == "initialize" \
            and handshake["reason"] == "exited" and proc.returncode == 127:
        handshake["failed_at"] = "spawn"

    stderr_tail = "".join(client.stderr)[-_STDERR_TAIL:]
    log_path = _find_log(log_dir, proc.pid)
    result = ProbeResult(cmd=list(cmd), handshake=handshake, log_path=log_path,
                         report_path=None, stderr_tail=stderr_tail)
    if log_path is None:
        # the tap refuses a missing binary before opening a log; that is
        # still "handshake incomplete" (3), not a probe usage error (2)
        if handshake["failed_at"] == "spawn":
            result.exit_code = 3
        return result   # otherwise exit_code 2: nothing to analyze

    trace = from_mcp_session_file(log_path, server_name=Path(cmd[0]).name)
    trace.metadata["handshake"] = handshake
    # INFO annotations never drive the report's verdict; the exit code
    # must agree with the headline
    found = [a for a in detectors.annotate(trace)
             if a.kind != AnnotationKind.INFO]

    report_path = Path(out_path) if out_path else log_path.with_suffix(".html")
    report_path.write_text(render_html(trace, source_name=log_path.name),
                           encoding="utf-8")

    result.report_path = report_path
    result.declared_tools = sorted(trace.declared_tools())
    result.called_tools = [name for _, name in trace.called_tools()]
    result.findings = len(found)
    result.max_severity = max((a.severity for a in found), default=0)
    result.exit_code = 3 if not handshake["completed"] else (1 if found else 0)
    return result


def _render_text(res: ProbeResult) -> str:
    hs = res.handshake
    lines = []
    if hs["completed"]:
        lines.append(f"handshake: complete · {len(res.declared_tools)} tool(s) "
                     f"declared · {len(res.called_tools)} called")
    else:
        lines.append(f"handshake: INCOMPLETE at {hs['failed_at']} "
                     f"({hs['reason']})")
    lines.append(f"findings: {res.findings}"
                 + (f" (max severity {res.max_severity})" if res.findings else ""))
    lines.append(f"log:    {res.log_path}")
    lines.append(f"report: {res.report_path}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if "--" not in argv:
        print(USAGE, file=sys.stderr)
        return 2
    sep = argv.index("--")
    opts, cmd = argv[:sep], argv[sep + 1:]
    if not cmd:
        print(USAGE, file=sys.stderr)
        return 2

    calls: list[tuple[str, dict]] = []
    log_dir: Optional[Path] = None
    out: Optional[Path] = None
    as_json = do_open = False
    timeouts = {"--timeout": 15.0, "--startup-timeout": 60.0}
    i = 0
    try:
        while i < len(opts):
            a = opts[i]
            if a == "--call":
                name, raw = opts[i + 1], opts[i + 2]
                args = json.loads(raw)
                if not isinstance(args, dict):
                    raise ValueError("--call arguments must be a JSON object")
                calls.append((name, args))
                i += 3
                continue
            if a in timeouts:
                timeouts[a] = float(opts[i + 1])
                if timeouts[a] <= 0:
                    raise ValueError(f"{a} must be positive")
            elif a == "--log-dir":
                log_dir = Path(opts[i + 1])
            elif a == "-o":
                out = Path(opts[i + 1])
            elif a == "--json":
                as_json = True
                i += 1
                continue
            elif a == "--open":
                do_open = True
                i += 1
                continue
            else:
                raise ValueError(f"unknown option {a}")
            i += 2
    except (IndexError, ValueError) as exc:
        print(f"probe: {exc}" if str(exc) else USAGE, file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    res = probe(cmd, calls=calls, log_dir=log_dir, out_path=out,
                startup_timeout=timeouts["--startup-timeout"],
                timeout=timeouts["--timeout"])
    if res.report_path is None:
        print("probe: no session log was written; nothing to analyze",
              file=sys.stderr)
    if as_json:
        print(json.dumps(res.to_json(), indent=2))
    else:
        print(_render_text(res))
    if do_open and res.report_path is not None:
        import webbrowser
        webbrowser.open(res.report_path.resolve().as_uri())
    return res.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
