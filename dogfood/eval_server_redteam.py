# dogfood/eval_server_redteam.py
"""Serve red-team grill — audit_server path confinement (roadmap P0.1).

Drives the real serve() dispatch over StringIO with hostile `path`
arguments a malicious MCP client could send, and asserts every escape is
rejected (isError, no file content echoed). A benign in-root audit must
still succeed — the confinement must not break the tool.
Exits non-zero on any FAIL. Run: PYTHONPATH=src python dogfood/eval_server_redteam.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from glassport import server as server_mod

FINDINGS = "dogfood/findings/server-redteam.md"


def call_audit(path_arg: str, root: str) -> dict:
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "audit_server",
                      "arguments": {"path": path_arg}}}
    src = io.StringIO(json.dumps(req) + "\n")
    out = io.StringIO()
    server_mod.serve(src, out, log_dir=Path(root),
                     audit_roots=[Path(root)])
    return json.loads(out.getvalue())["result"]


def run() -> int:
    with tempfile.TemporaryDirectory() as root, \
            tempfile.TemporaryDirectory() as outside:
        benign = Path(root) / "srv.py"
        benign.write_text("import os\nos.system('id')\n", encoding="utf-8")
        (Path(outside) / "secret.py").write_text(
            "AWS_KEY = 'AKIAOUTSIDEROOT00000'\n", encoding="utf-8")
        link = Path(root) / "innocent"
        link.symlink_to(outside)

        hostile = [
            ("H1 absolute /etc", "/etc"),
            ("H2 /etc/passwd file", "/etc/passwd"),
            ("H3 dotdot traversal", root + "/../" * 10 + "etc"),
            ("H4 literal tilde", "~/.ssh"),
            ("H5 tilde id_rsa", "~/.ssh/id_rsa"),
            ("H6 symlink escape", str(link)),
            ("H7 empty path", ""),
            ("H8 home absolute", os.path.expanduser("~")),
        ]

        checks = []
        for name, payload in hostile:
            res = call_audit(payload, root)
            text = res["content"][0]["text"]
            ok = (res.get("isError") is True
                  and "AKIAOUTSIDEROOT00000" not in text
                  and "root:" not in text)
            checks.append((name, ok, f"isError={res.get('isError')}"))

        res = call_audit(str(benign), root)
        body = res["content"][0]["text"]
        benign_ok = not res.get("isError") and json.loads(body) is not None
        checks.append(("B1 benign in-root audit still works", benign_ok,
                       f"isError={res.get('isError')}"))

    lines = ["# serve red-team — audit_server path confinement", "",
             "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, ok, detail in checks:
        all_ok &= ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    Path(FINDINGS).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
