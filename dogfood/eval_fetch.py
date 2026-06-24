"""
Dogfood evaluation of mcp-server-fetch behind glassport.

Tests:
- benign: fetch example.com with limited max_length
- adversarial: file:// URL, localhost URL, oversized max_length, invalid scheme
- glassport analysis: summarize + detect on the session log
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dogfood.driver import run_session, summarize_log, detect_log


def run() -> dict:
    calls = [
        # Benign
        {"name": "fetch", "arguments": {"url": "https://example.com", "max_length": 1000}},
        # Adversarial
        {"name": "fetch", "arguments": {"url": "file:///etc/passwd", "max_length": 1000}},
        {"name": "fetch", "arguments": {"url": "http://localhost:22", "max_length": 1000}},
        {"name": "fetch", "arguments": {"url": "https://example.com", "max_length": 999_999_999}},
        {"name": "fetch", "arguments": {"url": "foo://bar", "max_length": 1000}},
        {"name": "fetch", "arguments": {"url": "not-a-url", "max_length": 1000}},
        {"name": "unknown_tool_xyz", "arguments": {"url": "https://example.com"}},
    ]

    result = run_session(
        name="fetch",
        cmd=["uvx", "mcp-server-fetch"],
        calls=calls,
        timeout=60.0,
    )

    summary = summarize_log(result.log_path) if result.log_path else {}
    detections = detect_log(result.log_path) if result.log_path else {}

    return {
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
