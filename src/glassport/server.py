"""
server.py — glassport exposed as a queryable MCP server.

Usage:
    glassport serve [--log-dir DIR]

Add it to your MCP client config alongside the servers you are
monitoring, so the agent can interrogate its own session history:

    {
      "mcpServers": {
        "glassport": {
          "command": "glassport",
          "args": ["serve"]
        },
        "filesystem": {
          "command": "glassport",
          "args": ["gate", "--",
                   "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
        }
      }
    }

The target servers are wrapped by `glassport wrap`/`gate` and their
sessions land in the log dir; this server reads those same logs back.
Recursive in the right way: glassport watches the servers, the agent
watches glassport's findings.

Same zero-dependency philosophy as the tap: stdlib json over the MCP
stdio transport (newline-delimited JSON-RPC). Tool failures come back
as MCP tool results with isError, not protocol errors, so the agent
sees them as content it can reason about.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from dataclasses import asdict
from pathlib import Path

from glassport import __version__
from glassport.tap import DEFAULT_LOG_DIR

PROTOCOL_VERSION = "2025-03-26"

TOOLS = [
    {
        "name": "list_sessions",
        "description": ("List recent glassport session logs, "
                        "newest first. Returns a JSON array of paths."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer",
                          "description": "Max sessions to return (default 10)"},
            },
        },
    },
    {
        "name": "analyze_session",
        "description": (
            "Analyze a glassport session log. Returns declared tools, "
            "called tools, fabricated calls (tools called but never "
            "declared), and behavioral annotations from every detector."),
        "inputSchema": {
            "type": "object",
            "required": ["session_path"],
            "properties": {
                "session_path": {"type": "string",
                                 "description": "Path to a .jsonl session log"},
            },
        },
    },
    {
        "name": "audit_server",
        "description": ("Run the static AST audit on an MCP server source "
                        "file or directory. Reads source, never runs it."),
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string",
                         "description": "Server source file or directory"},
            },
        },
    },
    {
        "name": "get_gate_status",
        "description": ("Report the calls glassport gate blocked in a "
                        "session log."),
        "inputSchema": {
            "type": "object",
            "required": ["session_path"],
            "properties": {
                "session_path": {"type": "string"},
            },
        },
    },
    {
        "name": "watch_drift",
        "description": ("Compare all sessions in the log dir for "
                        "behavioral drift, grouped by server."),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _text(payload) -> dict:
    return {"content": [{"type": "text",
                         "text": json.dumps(payload, indent=2,
                                            ensure_ascii=False)}]}


def _resolve_session_path(raw, log_dir: Path) -> Path:
    """Resolve a session_path argument and confine it to log_dir.

    The `serve` tools read session logs an MCP client names. Opening the
    raw path would let a hostile client pass `/etc/passwd` or `../../.env`
    and read arbitrary host files. Resolve the path and require it to live
    inside the configured log directory; reject anything that escapes."""
    if not raw:
        raise ValueError("session_path is required")
    p = Path(raw).resolve()
    base = Path(log_dir).resolve()
    if not p.is_relative_to(base):
        raise ValueError(f"session_path escapes the log directory: {raw}")
    return p


def _call_tool(name: str, args: dict, log_dir: Path) -> dict:
    if name == "list_sessions":
        limit = args.get("limit", 10)
        paths = sorted(log_dir.glob("*.jsonl"), reverse=True)[:limit]
        return _text([str(p) for p in paths])

    if name == "analyze_session":
        from glassport.adapters.mcp_session import from_mcp_session_file
        from glassport.detectors import annotate
        path = _resolve_session_path(args.get("session_path"), log_dir)
        trace = from_mcp_session_file(path)
        anns = annotate(trace)
        seq_of = {e.id: e.metadata.get("seq") for e in trace.events}
        return _text({
            "session": path.name,
            "declared_tools": sorted(trace.declared_tools()),
            "called_tools": [n for _, n in trace.called_tools()],
            "fabricated_calls": [{"seq": seq_of.get(eid), "tool": n}
                                 for eid, n in trace.fabricated_tool_calls()],
            "annotations": [
                {"severity": a.severity, "subcategory": a.subcategory,
                 "seq": a.metadata.get("seq"), "explanation": a.explanation}
                for a in anns],
        })

    if name == "audit_server":
        from glassport import audit as audit_mod
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            audit_mod.main([args["path"], "--json"])
        return {"content": [{"type": "text", "text": buf.getvalue()}]}

    if name == "get_gate_status":
        blocked = []
        with open(_resolve_session_path(args.get("session_path"), log_dir),
                  encoding="utf-8") as fh:
            for raw in fh:
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                gate = entry.get("gate")
                if isinstance(gate, dict) and gate.get("action") == "blocked":
                    blocked.append(gate)
        return _text({"blocked_count": len(blocked), "blocked": blocked})

    if name == "watch_drift":
        from glassport.watch import watch_dir
        groups = watch_dir(log_dir)
        return _text({
            key: [{**row, "findings": [asdict(f) for f in row["findings"]]}
                  for row in rows]
            for key, rows in groups.items()})

    return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
            "isError": True}


def _handle(method: str, params: dict, log_dir: Path) -> dict:
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion",
                                          PROTOCOL_VERSION),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "glassport", "version": __version__},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name", "?")
        args = params.get("arguments") or {}
        try:
            return _call_tool(name, args, log_dir)
        except Exception as exc:
            # tool failure is content, not a protocol error — the agent
            # should see and reason about it like any other tool output
            return {"content": [{"type": "text",
                                 "text": f"{type(exc).__name__}: {exc}"}],
                    "isError": True}
    return {}   # ping and anything else id-bearing: empty result


def serve(in_stream, out_stream, log_dir: Path | None = None) -> int:
    """Speak MCP over the given line streams until EOF."""
    log_dir = log_dir or DEFAULT_LOG_DIR

    def send(obj: dict) -> None:
        out_stream.write(json.dumps(obj, ensure_ascii=False) + "\n")
        out_stream.flush()

    for raw in in_stream:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(req, dict):
            continue
        rid = req.get("id")
        if rid is None:
            continue   # notifications need no reply
        try:
            result = _handle(req.get("method", ""),
                             req.get("params") or {}, log_dir)
            send({"jsonrpc": "2.0", "id": rid, "result": result})
        except Exception as exc:
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32000, "message": str(exc)}})
    return 0


def main(argv: list[str]) -> int:
    args = list(argv)
    if "--http" in args:
        # web console mode — lazy import keeps MCP serve import-light
        from glassport import console
        args.remove("--http")
        return console.main(args)
    log_dir = DEFAULT_LOG_DIR
    if "--log-dir" in args:
        i = args.index("--log-dir")
        try:
            log_dir = Path(args[i + 1])
        except IndexError:
            print("usage: glassport serve [--log-dir DIR]", file=sys.stderr)
            return 2
        del args[i:i + 2]
    if args:
        print("usage: glassport serve [--log-dir DIR]", file=sys.stderr)
        return 2
    print(f"[glassport] serve: MCP audit server on stdio; "
          f"log dir: {log_dir}", file=sys.stderr)
    return serve(sys.stdin, sys.stdout, log_dir=log_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
