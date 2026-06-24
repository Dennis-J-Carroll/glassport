"""
Reusable MCP stdio client for dogfooding glassport against real servers.

Launches a server behind `python glassport_tap.py`, drives the MCP
initialize/tools-list/tool-call handshake, and returns the raw responses
plus the glassport session log path for offline analysis.

Usage:
    from dogfood.driver import run_session

    result = run_session(
        name="filesystem",
        cmd=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        calls=[{"name": "read_file", "arguments": {"path": "/tmp/foo.txt"}}],
    )
    print(result.responses)
    print(result.log_path)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
TAP = ROOT / "glassport_tap.py"
LOG_DIR = ROOT / "dogfood" / "logs"


def _rpc(rid: int | None, method: str, params: dict[str, Any] | None = None) -> dict:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        msg["id"] = rid
    if params is not None:
        msg["params"] = params
    return msg


@dataclass
class SessionResult:
    name: str
    cmd: list[str]
    requests: list[dict]
    responses: list[dict]
    log_path: Path | None
    returncode: int | None
    stderr: str
    error: str | None


def run_session(
    name: str,
    cmd: list[str],
    calls: list[dict] | None = None,
    log_dir: Path = LOG_DIR,
    timeout: float = 30.0,
    env: dict[str, str] | None = None,
    protocol_version: str = "2025-06-18",
) -> SessionResult:
    """
    Run a server behind glassport tap, perform the MCP handshake, call the
    requested tools, and collect all server responses.

    `calls` is a list of {"name": str, "arguments": dict} dicts.
    """
    calls = calls or []
    session_log = log_dir / name
    session_log.mkdir(parents=True, exist_ok=True)

    tap_cmd = [
        sys.executable,
        str(TAP),
        "--log-dir",
        str(session_log),
        "--",
    ] + cmd

    merged_env = {**dict(os.environ), **(env or {})}

    requests: list[dict] = [
        _rpc(1, "initialize", {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "glassport-dogfood-driver", "version": "0.1.0"},
        }),
        _rpc(None, "notifications/initialized"),
        _rpc(2, "tools/list"),
    ]
    for i, call in enumerate(calls, start=3):
        requests.append(_rpc(i, "tools/call", call))

    payload = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in requests)

    proc = subprocess.Popen(
        tap_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=merged_env,
    )

    error: str | None = None
    responses: list[dict] = []
    stderr = ""
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None
        proc.stdin.write(payload)
        proc.stdin.close()

        # Read until EOF or timeout. Because some servers keep the pipe open,
        # we use a conservative deadline and then terminate if necessary.
        start = time.monotonic()
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                responses.append(json.loads(line))
            except json.JSONDecodeError:
                responses.append({"_parse_error": line})
            if time.monotonic() - start > timeout:
                break

        # Give the server a moment to finish any queued output, then terminate.
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        stderr = proc.stderr.read() if proc.stderr else ""

    except Exception as exc:  # pragma: no cover
        error = str(exc)
        proc.kill()
        proc.wait()
        stderr = proc.stderr.read() if proc.stderr else ""

    # Tap names files with a timestamp; pick the newest in the session dir.
    log_path: Path | None = None
    try:
        files = sorted(session_log.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if files:
            log_path = files[0]
    except Exception:
        pass

    return SessionResult(
        name=name,
        cmd=cmd,
        requests=requests,
        responses=responses,
        log_path=log_path,
        returncode=proc.returncode,
        stderr=stderr,
        error=error,
    )


def summarize_log(log_path: Path) -> dict:
    """Run `glassport summarize` on a session log."""
    proc = subprocess.run(
        [sys.executable, str(TAP), "summarize", str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"_stdout": proc.stdout, "_stderr": proc.stderr}


def detect_log(log_path: Path) -> dict:
    """Run `glassport detect` on a session log."""
    proc = subprocess.run(
        [sys.executable, str(TAP), "detect", str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"_stdout": proc.stdout, "_stderr": proc.stderr, "returncode": proc.returncode}


if __name__ == "__main__":
    # Sanity check: run filesystem server against /tmp
    res = run_session(
        name="filesystem-sanity",
        cmd=["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        calls=[{"name": "list_directory", "arguments": {"path": "/tmp"}}],
    )
    print("responses:", json.dumps(res.responses, indent=2))
    print("log:", res.log_path)
    if res.log_path:
        print("summary:", json.dumps(summarize_log(res.log_path), indent=2))
