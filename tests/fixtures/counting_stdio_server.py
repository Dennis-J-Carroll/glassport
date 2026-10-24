"""Minimal MCP server that records calls it actually receives.

Used by the enforcement contract tests; the sidecar is the upstream receipt,
independent of the response glassport sends to its client.
"""
import json
import sys
from pathlib import Path


received = Path(sys.argv[1])


def answer(frame):
    sys.stdout.write(json.dumps(frame) + "\n")
    sys.stdout.flush()


for raw in sys.stdin:
    try:
        request = json.loads(raw)
    except ValueError:
        continue
    method, rid = request.get("method"), request.get("id")
    if method == "initialize":
        answer({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
            "serverInfo": {"name": "counting-server", "version": "1"}}})
    elif method == "tools/list":
        answer({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
            "name": "search", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        name = (request.get("params") or {}).get("name")
        with received.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": rid, "name": name}) + "\n")
        answer({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": "upstream received call"}]}})
