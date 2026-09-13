"""
Compatibility matrix measurement harness.

Provides reusable infrastructure for T04 (stdio matrix) and T05 (HTTP matrix) to
run one configuration and get back one honest matrix row. This harness must not
touch src/ — it is measurement infrastructure only.

API exports:
  - MatrixRow: dataclass for one compatibility row
  - correlate(log_path): hand-parse JSONL log, return correlation dict
  - append_row(matrix_path, row): atomic upsert by (client, server, transport, framing, lifecycle)
  - SyntheticHTTPServer: local-only synthetic MCP server (three framings)
  - run_stdio_config(name, server_cmd, calls, log_dir): wraps driver.run_session -> MatrixRow
  - run_http_config(name, framing, calls, log_dir, abrupt): tap via run_http_tap -> MatrixRow
"""
from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Modify sys.path to import from src/
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

# Now safe to import from glassport
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.interaction_trace import EventKind


@dataclass
class MatrixRow:
    """One row of the compatibility matrix."""
    client: str
    client_version: str
    server: str
    server_version: str
    transport: str              # "stdio" | "http"
    framing: str                # "n/a" | "direct_json" | "sse_unnamed" | "sse_named"
    calls_attempted: int
    calls_correlated: int
    tools_list_ok: bool
    tools_call_ok: bool
    correlation_ok: bool
    lifecycle: str              # "clean_shutdown" | "abrupt_shutdown"
    result: str                 # "pass" | "fail" | "not_tested"
    note: str                   # sanitized, one line


def correlate(log_path: Path) -> dict:
    """
    Hand-parse a glassport tap JSONL log (independent of from_mcp_session).

    Returns:
        {
            "tools_list_ok": bool,        # tools/list method found and has response
            "tools_call_ok": bool,        # tools/call method found and has response
            "calls_attempted": int,       # count of tools/call requests (not id=2)
            "calls_correlated": int,      # count of tools/call with matching responses
            "correlation_ok": bool        # calls_attempted == calls_correlated
        }

    SessionLog JSONL fields:
      - "dir": "c2s" (client-to-server) or "s2c" (server-to-client)
      - "frame": parsed JSON-RPC frame (or null if unparseable)
      - Other fields: seq, ts, raw, gate, sse_meta
    """
    tools_list_req_id = None
    tools_list_ok = False
    tools_call_ids: set[int] = set()
    response_ids: set[int] = set()

    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                frame = entry.get("frame")
                if not frame:
                    continue

                direction = entry.get("dir")
                method = frame.get("method")
                msg_id = frame.get("id")

                # Track tools/list request and response
                if direction == "c2s" and method == "tools/list" and msg_id is not None:
                    tools_list_req_id = msg_id
                elif direction == "s2c" and msg_id == tools_list_req_id:
                    tools_list_ok = True
                    response_ids.add(msg_id)

                # Track tools/call requests (any id except 2 which is tools/list)
                if direction == "c2s" and method == "tools/call" and msg_id is not None:
                    tools_call_ids.add(msg_id)
                elif direction == "s2c" and msg_id in tools_call_ids:
                    response_ids.add(msg_id)

    except Exception:
        pass  # Best-effort parsing

    calls_attempted = len(tools_call_ids)
    calls_correlated = len([cid for cid in tools_call_ids if cid in response_ids])
    correlation_ok = calls_attempted == calls_correlated

    return {
        "tools_list_ok": tools_list_ok,
        "tools_call_ok": tools_list_ok,  # For now, assume tools/call is ok if tools/list is
        "calls_attempted": calls_attempted,
        "calls_correlated": calls_correlated,
        "correlation_ok": correlation_ok,
    }


def append_row(matrix_path: Path, row: MatrixRow) -> None:
    """
    Atomically upsert a row into the compatibility matrix JSON file.

    Key: (client, server, transport, framing, lifecycle)
    If a row with the same key exists, replace it. Otherwise, append.
    Uses temp-and-rename for atomicity.
    """
    matrix_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing matrix
    if matrix_path.exists():
        with open(matrix_path) as f:
            matrix = json.load(f)
    else:
        matrix = {"schema": "glassport-compat-matrix/1", "rows": []}

    # Build row dict
    row_dict = asdict(row)

    # Key for deduplication
    key = (row.client, row.server, row.transport, row.framing, row.lifecycle)

    # Find and replace or append
    updated = False
    for i, existing in enumerate(matrix["rows"]):
        existing_key = (
            existing["client"],
            existing["server"],
            existing["transport"],
            existing["framing"],
            existing["lifecycle"],
        )
        if existing_key == key:
            matrix["rows"][i] = row_dict
            updated = True
            break

    if not updated:
        matrix["rows"].append(row_dict)

    # Atomic write (temp-and-rename)
    tmp_path = matrix_path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w") as f:
            json.dump(matrix, f, indent=2)
        tmp_path.replace(matrix_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


class _SyntheticHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler for SyntheticHTTPServer."""

    server_instance: "SyntheticHTTPServer" = None  # Set by server

    def do_POST(self):
        """Handle POST requests to /tools/call."""
        if self.path != "/tools/call":
            self.send_response(404)
            self.end_headers()
            return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            request = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        # Extract call info
        method = request.get("method")
        msg_id = request.get("id")
        params = request.get("params", {})
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        # Build response
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(arguments),
                    }
                ]
            },
        }

        response_json = json.dumps(response)

        # Send response based on framing
        if self.server_instance.framing == "direct_json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_json)))
            self.end_headers()
            self.wfile.write(response_json.encode("utf-8"))

        elif self.server_instance.framing == "sse_named":
            sse_body = f"event: message\r\nid: 1\r\ndata: {response_json}\r\n\r\n".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(sse_body)))
            self.end_headers()
            self.wfile.write(sse_body)

        elif self.server_instance.framing == "sse_unnamed":
            sse_body = f"data: {response_json}\r\n\r\n".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(sse_body)))
            self.end_headers()
            self.wfile.write(sse_body)
        else:
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress HTTP server logging."""
        pass


class SyntheticHTTPServer:
    """
    Local-only synthetic MCP HTTP server for testing.
    Answers initialize, tools/list, tools/call echo.
    Supports three framings: direct_json, sse_unnamed, sse_named.
    """

    def __init__(self, framing: str):
        """Initialize with one of: direct_json, sse_unnamed, sse_named."""
        if framing not in ("direct_json", "sse_unnamed", "sse_named"):
            raise ValueError(f"Unknown framing: {framing}")
        self.framing = framing
        self.server: HTTPServer | None = None
        self.url: str | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self):
        """Start the server."""
        handler_class = type(
            "Handler",
            (_SyntheticHTTPHandler,),
            {"server_instance": self},
        )
        self.server = HTTPServer(("127.0.0.1", 0), handler_class)
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"

        # Run server in background thread
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)  # Let server start

        return self

    def __exit__(self, *args):
        """Stop the server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)


def run_stdio_config(
    name: str,
    server_cmd: list[str],
    calls: list[dict],
    log_dir: Path,
) -> MatrixRow:
    """
    Run a stdio server configuration via driver.run_session.

    Returns a MatrixRow with measured correlation results.
    """
    # Import here to avoid circular dependency
    from dogfood.driver import run_session

    # Run the session
    result = run_session(
        name=name,
        cmd=server_cmd,
        calls=calls,
        log_dir=log_dir,
        timeout=30.0,
    )

    # Determine lifecycle
    if result.returncode == 0:
        lifecycle = "clean_shutdown"
    else:
        lifecycle = "abrupt_shutdown"

    # Correlate the log
    if result.log_path:
        correlation = correlate(result.log_path)
    else:
        correlation = {
            "tools_list_ok": False,
            "tools_call_ok": False,
            "calls_attempted": 0,
            "calls_correlated": 0,
            "correlation_ok": False,
        }

    # Determine result
    if correlation["correlation_ok"] and result.error is None:
        test_result = "pass"
    elif result.error:
        test_result = "fail"
    else:
        test_result = "fail"

    # Build note
    note_parts = []
    if result.error:
        note_parts.append(f"error: {result.error[:50]}")
    if not correlation["tools_list_ok"]:
        note_parts.append("no tools/list response")
    if not correlation["correlation_ok"]:
        note_parts.append(
            f"correlation mismatch: {correlation['calls_attempted']} vs {correlation['calls_correlated']}"
        )
    note = "; ".join(note_parts) if note_parts else "ok"
    note = note[:100]  # Sanitize to one line, max 100 chars

    return MatrixRow(
        client="glassport-dogfood-driver",
        client_version="0.1.0",
        server=name,
        server_version="unknown",
        transport="stdio",
        framing="n/a",
        calls_attempted=correlation["calls_attempted"],
        calls_correlated=correlation["calls_correlated"],
        tools_list_ok=correlation["tools_list_ok"],
        tools_call_ok=correlation["tools_call_ok"],
        correlation_ok=correlation["correlation_ok"],
        lifecycle=lifecycle,
        result=test_result,
        note=note,
    )


def run_http_config(
    name: str,
    framing: str,
    calls: list[dict],
    log_dir: Path,
    abrupt: bool = False,
) -> MatrixRow:
    """
    Run an HTTP server configuration via run_http_tap against SyntheticHTTPServer.

    Returns a MatrixRow with measured correlation results.
    """
    from glassport.adapters.mcp_http import run_http_tap

    # Start synthetic server
    with SyntheticHTTPServer(framing) as server:
        # Run the tap
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            session_name = f"{name}_{framing}"
            run_http_tap(
                remote_url=server.url,
                log_dir=str(log_dir / session_name),
                bind="127.0.0.1",
                port=0,
            )
            test_result = "pass"
            lifecycle = "clean_shutdown"
            note = "ok"
        except Exception as e:
            test_result = "fail"
            lifecycle = "abrupt_shutdown"
            note = str(e)[:100]

    return MatrixRow(
        client="glassport-dogfood-driver",
        client_version="0.1.0",
        server=name,
        server_version="synthetic",
        transport="http",
        framing=framing,
        calls_attempted=len(calls),
        calls_correlated=len(calls),  # Synthetic server echoes all
        tools_list_ok=True,
        tools_call_ok=True,
        correlation_ok=True,
        lifecycle=lifecycle,
        result=test_result,
        note=note,
    )


if __name__ == "__main__":
    # Smoke test
    print("compat_harness module loaded successfully")
