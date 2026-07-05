"""End-to-end wire-reality test (roadmap H1.08).

Every other test in this suite builds synthetic tap logs line-by-line — good
for unit coverage, but nothing drives glassport against a *real* MCP server.
This one does: it runs `glassport wrap` as a stdio man-in-the-middle in front
of the official `@modelcontextprotocol/server-filesystem` reference server,
feeds a real `initialize` -> `tools/list` -> `tools/call` sequence, and then
asserts the JSONL the tap wrote parses back into a faithful InteractionTrace.

Doctrine guarantee: the whole thing is gated on `skipUnless(which("npx"))`, so
the zero-dependency main CI matrix (no node) and any clone-and-run without npm
skip it cleanly. Only `ci-coverage.yml` (which sets up node) and developers who
have node installed execute it. No new runtime dependency, no `src/` change.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# The assertions parse the tap's own log — this exercises the mcp_session
# adapter and InteractionTrace against bytes a real server actually emitted.
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.interaction_trace import EventKind

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

# The roadmap's named reference server: official, stable, credential-free,
# and confinable to a temp directory we create and clean up.
SERVER_PKG = "@modelcontextprotocol/server-filesystem"

# `list_directory` is a long-stable read-only tool of server-filesystem. If a
# future major renames it, this test fails loudly with the declared surface
# printed — which is the correct signal, not a silent pass.
CALLED_TOOL = "list_directory"

# The reference server uses modern ESM (top-level await), so an npx backed by
# an ancient node crashes at startup rather than serving. The honest
# precondition is therefore "node new enough to run the server," not merely
# "npx on PATH" — otherwise a stale system node turns a skip into a failure.
_MIN_NODE_MAJOR = 18


def _usable_npx() -> bool:
    # POSIX only. On Windows `npx` is `npx.cmd`, a batch file: shutil.which
    # resolves it (PATHEXT), but the tap spawns the child server with a
    # non-shell subprocess (a shell spawn in the tap would be a security
    # regression), and CreateProcess cannot run a .cmd without a shell. So
    # "which finds npx" would be true while the actual spawn fails — the
    # precondition must exclude Windows, like the suite's other POSIX-only
    # tests. The e2e still runs for real on ubuntu in ci-coverage.yml.
    if os.name == "nt":
        return False
    if not shutil.which("npx") or not shutil.which("node"):
        return False
    try:
        out = subprocess.run(
            ["node", "--version"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    m = re.match(r"v(\d+)\.", out)
    return m is not None and int(m.group(1)) >= _MIN_NODE_MAJOR


def _frames(sandbox: str) -> list[dict]:
    return [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "glassport-e2e", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": CALLED_TOOL, "arguments": {"path": sandbox}},
        },
    ]


@unittest.skipUnless(
    _usable_npx(),
    f"POSIX + node>={_MIN_NODE_MAJOR} + npx required; e2e skipped "
    "(Windows spawns npx via a shell the tap deliberately avoids)")
class TestE2EFilesystemServer(unittest.TestCase):
    def test_wrap_captures_real_handshake_and_call(self):
        with tempfile.TemporaryDirectory() as workdir:
            logdir = Path(workdir) / "logs"
            logdir.mkdir()
            sandbox = Path(workdir) / "sandbox"
            sandbox.mkdir()
            (sandbox / "hello.txt").write_text("hi", encoding="utf-8")

            # Run the tap via the module so this works whether or not the
            # console script is installed; PYTHONPATH covers the clone case.
            env = dict(os.environ)
            env["PYTHONPATH"] = os.pathsep.join(
                [str(SRC), env.get("PYTHONPATH", "")]
            ).rstrip(os.pathsep)
            cmd = [
                sys.executable, "-m", "glassport.tap", "wrap",
                "--log-dir", str(logdir), "--",
                "npx", "-y", SERVER_PKG, str(sandbox),
            ]
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
            )
            payload = "".join(json.dumps(f) + "\n" for f in _frames(str(sandbox)))
            try:
                # Closing stdin (communicate) makes the stdio server hit EOF
                # after processing our buffered frames, so it exits and the
                # tap flushes every frame. Timeout is generous: first `npx -y`
                # may download the package.
                err = proc.communicate(payload, timeout=180)[1]
            except subprocess.TimeoutExpired:
                proc.kill()
                err = proc.communicate()[1]
                self.fail(f"glassport wrap did not terminate; stderr:\n{err}")

            logs = list(logdir.glob("*.jsonl"))
            self.assertTrue(logs, f"no session log written; stderr:\n{err}")
            trace = from_mcp_session_file(str(logs[0]))

            # 1. The server declared a real tool surface (handshake + tools/list
            #    captured from real bytes, not a synthetic fixture).
            declared = trace.declared_tools()
            self.assertTrue(
                declared,
                f"declared tool surface empty; the tap saw no tools/list "
                f"result. stderr:\n{err}",
            )
            self.assertIn(
                CALLED_TOOL, declared,
                f"{CALLED_TOOL!r} not in declared surface {sorted(declared)}",
            )

            # 2. Our tools/call was captured.
            called = [name for _, name in trace.called_tools()]
            self.assertIn(CALLED_TOOL, called)

            # 3. A legitimate call against a declared tool is not fabricated.
            self.assertEqual(
                trace.fabricated_tool_calls(), [],
                "a call to a declared tool must not be flagged fabricated",
            )

            # 4. The server's response to the call was captured (round trip).
            results = [e for e in trace.events
                       if e.kind == EventKind.TOOL_RESULT]
            self.assertTrue(
                results, "no TOOL_RESULT event; the call's response was not logged",
            )


if __name__ == "__main__":
    unittest.main()
