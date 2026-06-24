"""
Dogfood evaluation of @modelcontextprotocol/server-filesystem behind glassport.

Tests:
- benign: list_directory, read_file, write_file
- adversarial: path traversal read, traversal write, multi-file traversal,
  oversized content, binary/null content
- glassport analysis: summarize + detect on the session log
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dogfood.driver import run_session, summarize_log, detect_log

ALLOWED = Path(tempfile.mkdtemp(prefix="glassport-dogfood-allowed-"))
OUTSIDE = Path(tempfile.mkdtemp(prefix="glassport-dogfood-outside-"))
SECRET = OUTSIDE / "secret.txt"
SECRET.write_text("outside-secret-12345", encoding="utf-8")

# Place a file inside the allowed dir
(ALLOWED / "inside.txt").write_text("inside-safe-content", encoding="utf-8")


def run() -> dict:
    calls = [
        # Benign
        {"name": "list_directory", "arguments": {"path": str(ALLOWED)}},
        {"name": "read_file", "arguments": {"path": str(ALLOWED / "inside.txt")}},
        {"name": "write_file", "arguments": {"path": str(ALLOWED / "new.txt"), "content": "created by dogfood"}},
        # Adversarial: path traversal
        {"name": "read_file", "arguments": {"path": str(ALLOWED / ".." / ".." / "secret.txt")}},
        {"name": "read_multiple_files", "arguments": {"paths": [str(ALLOWED / "inside.txt"), str(SECRET)]}},
        {"name": "write_file", "arguments": {"path": str(ALLOWED / ".." / ".." / "pwned.txt"), "content": "escaped"}},
        # Edge: null bytes and oversized
        {"name": "read_file", "arguments": {"path": str(ALLOWED / "inside.txt\x00.txt")}},
        {"name": "write_file", "arguments": {"path": str(ALLOWED / "big.txt"), "content": "x" * 100_000}},
    ]

    result = run_session(
        name="filesystem",
        cmd=["npx", "-y", "@modelcontextprotocol/server-filesystem", str(ALLOWED)],
        calls=calls,
        timeout=30.0,
    )

    summary = summarize_log(result.log_path) if result.log_path else {}
    detections = detect_log(result.log_path) if result.log_path else {}

    return {
        "allowed_dir": str(ALLOWED),
        "outside_dir": str(OUTSIDE),
        "secret_file": str(SECRET),
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
