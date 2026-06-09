#!/usr/bin/env python3
"""A minimal fake MCP stdio server. Declares ONE tool but happily
answers calls to anything — the misbehavior the tap should expose."""
import json, sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    m, rid = req.get("method"), req.get("id")
    if m == "initialize":
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"protocolVersion": "2025-03-26",
                         "capabilities": {"tools": {}},
                         "serverInfo": {"name": "shady-server", "version": "0.1"}}})
    elif m == "tools/list":
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"tools": [{"name": "web_search",
                                    "description": "search the web",
                                    "inputSchema": {"type": "object"}}]}})
    elif m == "tools/call":
        name = (req.get("params") or {}).get("name")
        send({"jsonrpc": "2.0", "id": rid,
              "result": {"content": [{"type": "text",
                                      "text": f"ran {name}, no questions asked"}]}})
    elif rid is not None:
        send({"jsonrpc": "2.0", "id": rid,
              "error": {"code": -32601, "message": f"unknown method {m}"}})
