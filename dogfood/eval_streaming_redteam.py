# dogfood/eval_streaming_redteam.py
"""Streaming red-team grill — tail_only surfacing (roadmap P0.3).

A log big enough to trip the tail cap silently drops its head; doctrine
says every consumer must surface that. This grill shrinks the cap, feeds
one oversized session through the real CLI paths, and asserts all three
surfaces say PARTIAL: summarize (stderr WARN + JSON completeness field),
report (HTML banner), watch (low-confidence drift notice in fingerprint).
Exits non-zero on any FAIL. Run: PYTHONPATH=src python dogfood/eval_streaming_redteam.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from glassport import report as report_mod
from glassport import tap, watch
from glassport.adapters import mcp_session
from glassport.adapters.mcp_session import from_mcp_session_file

FINDINGS = "dogfood/findings/streaming-redteam.md"
CAP = 2000


def frame(seq, obj):
    return json.dumps({"schema_version": "0.1", "seq": seq, "ts": f"t{seq}",
                       "dir": "c2s", "frame": obj, "raw": None})


def write_big_session(tmp: str) -> Path:
    lines = [frame(1, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-03-26"}})]
    for i in range(80):
        lines.append(frame(2 + i, {
            "jsonrpc": "2.0", "id": 2 + i, "method": "tools/call",
            "params": {"name": "web_search",
                       "arguments": {"q": "padding " * 10}}}))
    p = Path(tmp) / "20260101T000000Z_big_1.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert p.stat().st_size > CAP
    return p


def run() -> int:
    checks = []
    old = mcp_session.TAIL_CAP_BYTES
    mcp_session.TAIL_CAP_BYTES = CAP
    try:
        with tempfile.TemporaryDirectory() as tmp:
            session = write_big_session(tmp)

            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                tap.summarize(session, as_json=True)
            data = json.loads(out.getvalue())
            checks.append(("S1 summarize JSON completeness",
                           data.get("completeness") == "partial_tail_only",
                           f"completeness={data.get('completeness')}"))
            checks.append(("S2 summarize stderr WARN",
                           "WARN" in err.getvalue() and
                           "tail-only" in err.getvalue(),
                           repr(err.getvalue()[:60])))

            trace = from_mcp_session_file(session)
            html = report_mod.render_html(trace, session.name)
            checks.append(("R1 report PARTIAL banner",
                           "PARTIAL" in html and "tail-only" in html,
                           f"len={len(html)}"))

            fp = watch.fingerprint(trace, session.name)
            checks.append(("W1 fingerprint tail_only flag",
                           fp.get("tail_only") is True,
                           f"tail_only={fp.get('tail_only')}"))
            base = watch.merge(watch.new_baseline(), fp)
            kinds = [dr.kind for dr in watch.drift(base, fp)]
            checks.append(("W2 drift low-confidence notice",
                           "tail_only_partial" in kinds,
                           f"kinds={kinds[:4]}"))

            # control: a small complete log must NOT claim partial
            small = Path(tmp) / "20260101T000001Z_small_1.jsonl"
            small.write_text(frame(1, {"jsonrpc": "2.0", "id": 1,
                                       "method": "initialize",
                                       "params": {}}) + "\n",
                             encoding="utf-8")
            out2 = io.StringIO()
            with contextlib.redirect_stdout(out2), \
                    contextlib.redirect_stderr(io.StringIO()):
                tap.summarize(small, as_json=True)
            checks.append(("C1 small log stays complete",
                           json.loads(out2.getvalue())["completeness"]
                           == "complete", ""))
    finally:
        mcp_session.TAIL_CAP_BYTES = old

    lines = ["# streaming red-team — tail_only surfacing", "",
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
