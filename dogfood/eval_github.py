"""
Adversarial dogfood evaluation for @modelcontextprotocol/server-github
running behind the glassport tap.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dogfood.driver import detect_log, run_session, summarize_log


def main() -> None:
    token = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN")
    env = {"GITHUB_PERSONAL_ACCESS_TOKEN": token} if token else None
    token_note = "present" if token else "MISSING"

    calls = [
        # Benign
        {
            "name": "search_repositories",
            "arguments": {"query": "language:python stars:>1000", "perPage": 1},
        },
        # Adversarial / malformed
        {
            "name": "search_repositories",
            "arguments": {"query": 12345},
        },
        # Adversarial / oversized query
        {
            "name": "search_repositories",
            "arguments": {"query": "a" * 5000, "perPage": 1},
        },
        # Adversarial / unknown tool name
        {
            "name": "__does_not_exist__",
            "arguments": {"foo": "bar"},
        },
    ]

    result = run_session(
        name="github",
        cmd=["npx", "-y", "@modelcontextprotocol/server-github"],
        calls=calls,
        env=env,
        timeout=30.0,
    )

    output = {
        "token_status": token_note,
        "cmd": result.cmd,
        "tap_cmd": ["python", "glassport_tap.py", "--log-dir", "dogfood/logs/github", "--"] + result.cmd,
        "log_path": str(result.log_path) if result.log_path else None,
        "returncode": result.returncode,
        "stderr": result.stderr,
        "error": result.error,
        "requests": result.requests,
        "responses": result.responses,
    }

    if result.log_path:
        output["summarize"] = summarize_log(result.log_path)
        output["detect"] = detect_log(result.log_path)

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()
