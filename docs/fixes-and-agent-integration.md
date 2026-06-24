# Glassport: Fix Plan & Agent Integration

---

## Part 1 — The Three Fixes

### Fix 1: Gate queuing — hold `tools/call` until `tools/list` response is seen

**Problem.**  
`Gate.check_c2s()` in `tap.py` contains this logic:

```python
if declared is None or name in declared:
    return ("forward", None, None)
```

`declared is None` means "no `tools/list` response seen yet." The intent is
"we can't enforce yet, so pass it through." In practice any pipelined client
(one that sends several requests before reading any responses) will send
`tools/call` frames before the `tools/list` response arrives, bypassing
enforcement entirely.

**Fix: queue and hold, then replay.**  
Add a `threading.Event` and a pending queue to `Gate`. When `check_c2s()`
sees a `tools/call` while `declared is None`, it parks the frame on the queue
and blocks (with a timeout). `observe_s2c()` sets the event when the
`tools/list` response arrives; the blocked call wakes up, checks the now-known
surface, and returns the right action.

```python
# Gate.__init__ additions
self._surface_known = threading.Event()
self._pending_timeout = 2.0   # seconds to wait for tools/list before failing open

# Gate.check_c2s — replace the `if declared is None` branch
if declared is None:
    # Wait briefly for the tools/list response to arrive
    self._surface_known.wait(timeout=self._pending_timeout)
    with self._lock:
        declared = self._declared
    if declared is None:
        # Timeout: server never sent a tools/list; log warning, fail open
        return ("forward", None, {"action": "gate_skipped", "reason": "no_surface_timeout"})

# Gate.observe_s2c — after updating self._declared
self._surface_known.set()
```

This means the gate holds the call in the pump thread (which is already a
daemon thread per session), so stdio backpressure is the natural flow control.
The client blocks waiting for a response — which is exactly what a real MCP
client already does.

**File:** `src/glassport/tap.py` — `Gate` class (lines ~130–210).

---

### Fix 2: Suppress `call_before_declaration` false positives on pipelined clients

**Problem.**  
`context_violations()` in `detectors.py` fires `call_before_declaration`
whenever a `tools/call` event is seen before any `tools/list` *response* has
been processed:

```python
elif first_surface is None:
    out.append(_ann(..., "call_before_declaration", ...))
```

A pipelined client sends all its requests (including both `tools/list` and
`tools/call`) before reading any responses. This is valid MCP — the client
*intends* to see the tool list, it just hasn't received it yet. The detector
currently cannot distinguish "client never asked for the list" from "client
asked but the response hadn't arrived in the log."

**Fix: track whether a `tools/list` request was sent, not just whether a
response was received.**

```python
# context_violations() — add to loop variables
tools_list_requested = False

# detect the request (c2s, method == "tools/list")
if e.kind == EventKind.MESSAGE and e.metadata.get("method") == "tools/list" \
        and e.metadata.get("dir") == "c2s":
    tools_list_requested = True

# replace the call_before_declaration branch
elif first_surface is None:
    if not tools_list_requested:
        # Client called a tool without ever requesting the tool list — real anomaly
        out.append(_ann(e, AnnotationKind.ANOMALY, "call_before_declaration",
                        f"tools/call '{name}' and no tools/list request was ever sent",
                        severity=1))
    # else: tools/list was requested; async ordering is not a violation — skip
```

This requires the adapter to preserve `dir` in event metadata, which
`adapters/mcp_session.py` already does via `e.metadata["dir"]`.

**File:** `src/glassport/detectors.py` — `context_violations()` (line ~128).

---

### Fix 3: Expose `glassport detect <session>` as a real subcommand

**Problem.**  
`glassport detect <session.jsonl>` falls through to the tap path and tries
to exec a subprocess named `detect`, producing:

```
[glassport] command not found: detect
```

`detectors.py` exists, `annotate()` is exported, but there is no CLI entry point.

**Fix: add a `detect` case to `main()` in `tap.py`.**

```python
# tap.py main() — add before the log_dir / default tap fallthrough
if argv[0] == "detect":
    if len(argv) != 2:
        print(USAGE)
        return 2
    return _cmd_detect(Path(argv[1]))
```

```python
def _cmd_detect(log_path: Path) -> int:
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import annotate

    trace = from_mcp_session_file(log_path)
    annotations = annotate(trace)
    if not annotations:
        print(f"detect: {log_path.name} — no findings")
        return 0
    print(f"detect: {log_path.name} — {len(annotations)} finding(s)\n")
    for a in sorted(annotations, key=lambda x: (x.severity * -1,
                                                  x.metadata.get("seq") or 0)):
        sev_label = {1: "INFO", 2: "WARN", 3: "HIGH"}.get(a.severity, str(a.severity))
        print(f"  [{sev_label}] seq={a.metadata.get('seq', '?')} "
              f"{a.subcategory}: {a.explanation}")
    return 0
```

Also update the `USAGE` string to include:

```
  detect:          glassport detect <session.jsonl>
                   (run all behavioral detectors; print annotated findings)
```

**File:** `src/glassport/tap.py` — `main()` function and `USAGE` string.

---

## Part 2 — Agent Integration

### The core idea

Glassport today is a *developer* tool — you run it manually, inspect logs after
the fact. To make it useful to an *agent*, it needs to be accessible as a tool
the agent can call during a session, not just a CLI you check afterward.

There are two integration layers:

1. **Transparent tap layer** — the agent's MCP servers are wrapped by glassport
   without the agent knowing. Security happens regardless of whether the agent
   cooperates.

2. **Queryable audit layer** — glassport exposes its own MCP server. The agent
   can actively query its own security posture: "what has the filesystem server
   actually done this session?" This is the layer you have to build.

---

### Architecture: glassport as a meta-MCP server

```
┌─────────────────────────────────────────────────────────┐
│  AGENT  (Claude Code, custom Agent SDK app, etc.)       │
│                                                         │
│  uses ──▶  filesystem-mcp  (via glassport tap)          │
│  uses ──▶  web-search-mcp  (via glassport tap)          │
│  uses ──▶  glassport-mcp   ◀── NEW                      │
│               │                                         │
│               ├── analyze_session(path)                 │
│               ├── list_sessions()                       │
│               ├── audit_server(path)                    │
│               └── get_gate_status(path)                 │
└─────────────────────────────────────────────────────────┘
         │                    │
   JSONL logs           JSONL logs
         │                    │
   ~/.glassport/sessions/
```

The agent's target MCP servers (filesystem, web search, whatever) are already
wrapped by `glassport tap` or `glassport gate`. Those sessions land in
`~/.glassport/sessions/`. The new `glassport serve` command exposes a second
MCP server the agent can *also* connect to — and use to interrogate those same
sessions.

This is recursive in the right way: glassport watches the servers, the agent
watches glassport's findings.

---

### `glassport serve` — the MCP server to build

**New subcommand.** Add to `tap.py`:

```python
if argv[0] == "serve":
    from glassport import server as server_mod   # new module
    return server_mod.main(argv[1:])
```

**New file: `src/glassport/server.py`.**

The server follows the same zero-dependency philosophy using only stdlib
`json` / `sys` / `threading`. It speaks the MCP stdio transport (newline-
delimited JSON-RPC) and declares these tools:

| Tool | Description |
|------|-------------|
| `list_sessions` | List session log paths under `~/.glassport/sessions/`, newest first |
| `analyze_session` | Run `summarize` + `detect` on a session; return structured JSON |
| `audit_server` | Run static AST audit on a server source path; return findings |
| `get_gate_status` | Report blocked calls from a gate session log |
| `watch_drift` | Compare the last N sessions for behavioral drift |

**Minimal server skeleton (zero-dependency):**

```python
# src/glassport/server.py
"""
Glassport as a queryable MCP server.

Usage:
    glassport serve [--log-dir DIR]

Add to your MCP client config alongside the servers you are monitoring:

    {
      "mcpServers": {
        "glassport": {
          "command": "glassport",
          "args": ["serve"]
        },
        "filesystem": {
          "command": "glassport",
          "args": ["gate", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
        }
      }
    }
"""
from __future__ import annotations

import json, os, sys, threading
from pathlib import Path
from glassport.tap import DEFAULT_LOG_DIR

TOOLS = [
    {
        "name": "list_sessions",
        "description": "List recent glassport session logs. Returns paths newest-first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max sessions to return (default 10)"}
            }
        }
    },
    {
        "name": "analyze_session",
        "description": (
            "Analyze a glassport session log. Returns declared tools, called tools, "
            "fabricated calls (tools called but never declared), and behavioral annotations."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["session_path"],
            "properties": {
                "session_path": {"type": "string", "description": "Path to a .jsonl session log"}
            }
        }
    },
    {
        "name": "audit_server",
        "description": "Run a static AST audit on an MCP server source file. No execution.",
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "description": "Path to server source file or directory"}
            }
        }
    },
    {
        "name": "get_gate_status",
        "description": "Report how many calls were blocked by glassport gate in a session.",
        "inputSchema": {
            "type": "object",
            "required": ["session_path"],
            "properties": {
                "session_path": {"type": "string"}
            }
        }
    },
]


def _handle(method: str, params: dict) -> dict:
    if method == "tools/list":
        return {"tools": TOOLS}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}

        if name == "list_sessions":
            log_dir = DEFAULT_LOG_DIR
            limit = args.get("limit", 10)
            paths = sorted(log_dir.glob("*.jsonl"), reverse=True)[:limit]
            return {"content": [{"type": "text",
                                  "text": json.dumps([str(p) for p in paths])}]}

        if name == "analyze_session":
            from glassport.adapters.mcp_session import from_mcp_session_file
            from glassport.detectors import annotate
            from glassport.interaction_trace import PartKind
            path = Path(args["session_path"])
            trace = from_mcp_session_file(path)
            anns = annotate(trace)
            result = {
                "session": path.name,
                "declared_tools": sorted(trace.declared_tools()),
                "called_tools": [n for _, n in trace.called_tools()],
                "fabricated_calls": [
                    {"seq": trace._event_seq(eid), "tool": n}
                    for eid, n in trace.fabricated_tool_calls()
                ],
                "annotations": [
                    {"severity": a.severity, "subcategory": a.subcategory,
                     "seq": a.metadata.get("seq"), "explanation": a.explanation}
                    for a in anns
                ],
            }
            return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}

        if name == "audit_server":
            from glassport import audit as audit_mod
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                audit_mod.main([args["path"], "--json"])
            return {"content": [{"type": "text", "text": buf.getvalue()}]}

        if name == "get_gate_status":
            path = Path(args["session_path"])
            blocked = []
            with open(path) as f:
                for line in f:
                    entry = json.loads(line)
                    if entry.get("gate", {}).get("action") == "blocked":
                        blocked.append(entry["gate"])
            return {"content": [{"type": "text",
                                  "text": json.dumps({"blocked_count": len(blocked),
                                                      "blocked": blocked})}]}

        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}

    return {}   # notifications, initialize, etc.


def main(argv: list[str]) -> int:
    def send(obj: dict) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            continue
        method = req.get("method", "")
        rid = req.get("id")
        params = req.get("params") or {}

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid,
                  "result": {"protocolVersion": "2025-03-26",
                             "capabilities": {"tools": {}},
                             "serverInfo": {"name": "glassport", "version": "0.1"}}})
            continue
        if rid is None:
            continue   # notifications
        try:
            result = _handle(method, params)
            send({"jsonrpc": "2.0", "id": rid, "result": result})
        except Exception as exc:
            send({"jsonrpc": "2.0", "id": rid,
                  "error": {"code": -32000, "message": str(exc)}})
    return 0
```

> **Note on zero-deps:** this uses only stdlib + glassport's own modules.
> If you want to use the official `mcp` Python SDK (which gives you proper
> async, schema validation, and lifecycle management), install it and rewrite
> `main()` using `@server.list_tools()` / `@server.call_tool()` decorators.
> The tool definitions and handler logic stay the same; only the transport
> wrapper changes.

---

### Wiring it up: Claude Desktop / Claude Code

**Claude Desktop** (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "glassport": {
      "command": "glassport",
      "args": ["serve"]
    },
    "filesystem": {
      "command": "glassport",
      "args": ["gate", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "web-search": {
      "command": "glassport",
      "args": ["wrap", "--", "npx", "exa-mcp-server"]
    }
  }
}
```

The agent now has three MCP servers: `filesystem` and `web-search` (both
transparently tapped/gated), plus `glassport` itself as a queryable audit
oracle.

> **Caveat — strict servers require `clientInfo`.** Glassport's tap is
> passive: it forwards the client's `initialize` frame verbatim and never
> synthesizes one. Real clients (Claude Desktop/Code) always send
> `params.clientInfo`, so this is invisible in normal use. But if you hand-wire
> a *minimal* stdio driver (e.g. a dogfood/eval harness) to a server behind
> the tap, omit `clientInfo` and strict servers — `@modelcontextprotocol/server-filesystem`
> among them — reject the handshake with a Zod validation error before any
> tool call. Send `params.clientInfo = {"name": ..., "version": ...}`.

**Claude Code** (`~/.claude/settings.json` under `mcpServers`):

```json
{
  "mcpServers": {
    "glassport": {
      "command": "glassport",
      "args": ["serve"],
      "type": "stdio"
    }
  }
}
```

---

### Wiring it up: Claude Agent SDK

For agents built with the Python Agent SDK, pass the glassport server as an
additional MCP server alongside your domain servers:

```python
import anthropic
from anthropic.types.beta.messages import MCPServerStdio

client = anthropic.Anthropic()

response = client.beta.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=4096,
    tools=[],
    mcp_servers=[
        # Your domain servers — all wrapped by glassport
        MCPServerStdio(
            name="filesystem",
            command="glassport",
            args=["gate", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"],
        ),
        # Glassport itself as a queryable audit server
        MCPServerStdio(
            name="glassport",
            command="glassport",
            args=["serve"],
        ),
    ],
    system="""You have access to a filesystem MCP server and a security
audit server (glassport). Before trusting any sequence of filesystem
operations, call glassport.list_sessions() and glassport.analyze_session()
on the most recent session to verify the server is behaving within its
declared surface.""",
    messages=[{"role": "user", "content": "..."}],
)
```

The system prompt pattern above is the key: **tell the agent it has a security
oracle and when to use it.** Without explicit instruction, agents will ignore
audit tools in favor of the task at hand.

---

### System prompt fragment to give agents security awareness

Add this to your agent's system prompt when glassport is in the MCP config:

```
## Security policy — MCP server integrity

You have access to `glassport` tools for verifying MCP server behavior.

Rules:
1. After connecting to any MCP server for the first time, call
   `glassport.list_sessions()` and `glassport.analyze_session()` on the
   most recent session for that server.

2. If `analyze_session` returns any `fabricated_calls` (tools called outside
   the declared surface), STOP using that server and report the finding.

3. If `analyze_session` returns annotations with severity 3, treat the server
   as untrusted and do not pass sensitive data to it.

4. Prefer servers wrapped with `glassport gate` over `glassport wrap` for
   any operation involving credentials, file writes, or network calls.
```

---

### `--json` flag for `summarize` (lightweight alternative)

If you don't want to run the full MCP server, add `--json` to `summarize`
so agents can shell out and parse structured output:

```bash
glassport summarize --json ~/.glassport/sessions/latest.jsonl
```

```json
{
  "session": "20260612T174246Z_python3.jsonl",
  "frames_parsed": 11,
  "declared_tools": ["web_search"],
  "called_tools": ["web_search", "exec_shell", "read_file"],
  "fabricated_calls": [
    {"seq": 5, "tool": "exec_shell"},
    {"seq": 6, "tool": "read_file"}
  ],
  "context_violations": [
    {"severity": 1, "subcategory": "call_before_declaration", "seq": 4}
  ]
}
```

**File:** `tap.py` `summarize()` — add `--json` branch that calls
`json.dumps(result)` instead of `print()`.

---

## Summary: implementation order

| Priority | Fix | File | Effort |
|----------|-----|------|--------|
| 1 | Gate queuing (hold calls until surface known) | `tap.py` — `Gate` class | ~30 lines |
| 2 | `glassport detect` subcommand | `tap.py` — `main()` | ~20 lines |
| 3 | `call_before_declaration` false-positive fix | `detectors.py` — `context_violations()` | ~10 lines |
| 4 | `summarize --json` flag | `tap.py` — `summarize()` | ~15 lines |
| 5 | `glassport serve` — MCP server | new `server.py` | ~120 lines |

Fix 1 is the highest-value correctness fix; Fix 5 is the largest feature lift
but is what enables genuine agent integration. Fixes 2–4 are mechanical cleanup.
