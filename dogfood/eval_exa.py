"""
Dogfood evaluation of the exa MCP server behind glassport.

Tests:
- Always: tools/list to observe the declared surface (even without API key).
- With EXA_API_KEY: benign search and fetch, plus adversarial inputs.
- Without EXA_API_KEY: document the blocker and still probe error paths.
- glassport analysis: summarize + detect on the session log.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dogfood.driver import run_session, summarize_log, detect_log


EXA_API_KEY = os.environ.get("EXA_API_KEY")
HAS_KEY = bool(EXA_API_KEY)


def run() -> dict:
    calls: list[dict] = []

    if HAS_KEY:
        # Benign calls.
        calls.append({"name": "web_search_exa", "arguments": {"query": "python asyncio", "numResults": 1}})
        calls.append({"name": "web_fetch_exa", "arguments": {"urls": ["https://example.com"], "maxCharacters": 500}})
    else:
        # Without a key, calling the real tools should fail at the API layer.
        calls.append({"name": "web_search_exa", "arguments": {"query": "python asyncio", "numResults": 1}})
        calls.append({"name": "web_fetch_exa", "arguments": {"urls": ["https://example.com"], "maxCharacters": 500}})

    # Adversarial / edge probes.
    calls.append({"name": "nonexistent_tool_xyz", "arguments": {"query": "python asyncio"}})
    # Schema violations on real tools.
    calls.append({"name": "web_search_exa", "arguments": {"query": ""}})  # empty required query
    calls.append({"name": "web_search_exa", "arguments": {"query": "a" * 5000}})  # oversized query
    calls.append({"name": "web_search_exa", "arguments": {"bad_param": "ignored"}})  # missing required query
    calls.append({"name": "web_search_exa", "arguments": {"query": 12345}})  # wrong type
    calls.append({"name": "web_fetch_exa", "arguments": {"urls": ["file:///etc/passwd"]}})  # non-HTTP URL scheme
    calls.append({"name": "web_fetch_exa", "arguments": {"urls": ["http://localhost:22"]}})  # localhost/SSRF-like
    calls.append({"name": "web_fetch_exa", "arguments": {"urls": []}})  # empty required array

    result = run_session(
        name="exa",
        cmd=["npx", "-y", "exa-mcp-server"],
        calls=calls,
        timeout=30.0,
        env={"EXA_API_KEY": EXA_API_KEY} if EXA_API_KEY else None,
    )

    summary = summarize_log(result.log_path) if result.log_path else {}
    detections = detect_log(result.log_path) if result.log_path else {}

    return {
        "api_key_present": HAS_KEY,
        "cmd": result.cmd,
        "responses": result.responses,
        "stderr": result.stderr,
        "error": result.error,
        "log_path": str(result.log_path) if result.log_path else None,
        "summary": summary,
        "detections": detections,
    }


if __name__ == "__main__":
    data = run()
    print(json.dumps(data, indent=2, default=str))
