#!/usr/bin/env python3
"""
bench.py — stdlib performance benchmark for the analysis pipeline
(GQM plan 2.1: "the tap is dumb and fast" needs numbers, not vibes).

Builds a synthetic N-frame session (default 10k), then times the three
hot paths a user actually waits on: batch ingest, full detector
annotation, and HTML report render. Prints frames/sec and wall times;
exits non-zero if any stage blows its generous ceiling, so CI catches
order-of-magnitude regressions without flaking on runner jitter.

Zero dependencies — deliberately not pytest-benchmark; a benchmark that
violates the project's own zero-dep constraint would be an ironic
number. Run: PYTHONPATH=src python scripts/bench.py [N_FRAMES]
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, "src")

# generous ceilings (seconds) — regression tripwires, not SLOs.
# measured on a dev laptop: 10k frames ingest ~0.35s, annotate ~0.6s,
# report ~0.5s; ceilings are ~20x headroom for slow CI runners.
CEILINGS = {"ingest": 10.0, "annotate": 15.0, "report": 15.0}


def frame(seq: int, obj: dict) -> str:
    return json.dumps({"schema_version": "0.1", "seq": seq,
                       "ts": f"2026-01-01T00:00:{seq % 60:02d}+00:00",
                       "dir": "c2s" if obj.get("method") else "s2c",
                       "frame": obj, "raw": None})


def build_session(path: Path, n_frames: int) -> None:
    # full clean handshake — a missing notifications/initialized would
    # trip premature_call on every call and bench the annotated path
    lines = [
        frame(1, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-03-26"}}),
        frame(2, {"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2025-03-26", "capabilities": {}}}),
        frame(3, {"jsonrpc": "2.0",
                  "method": "notifications/initialized"}),
        frame(4, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        frame(5, {"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "web_search",
                       "inputSchema": {"type": "object"}}]}}),
    ]
    rid = 3
    while len(lines) < n_frames:
        rid += 1
        lines.append(frame(len(lines) + 1, {
            "jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": "web_search",
                       "arguments": {"q": f"query {rid} padding pad"}}}))
        lines.append(frame(len(lines) + 1, {
            "jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text",
                             "text": f"result {rid} " + "body " * 8}]}}))
    path.write_text("\n".join(lines[:n_frames]) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    n = int(argv[0]) if argv else 10_000
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import annotate
    from glassport.report import render_html

    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp) / "bench.jsonl"
        build_session(session, n)
        size_mb = session.stat().st_size / 1e6

        t0 = time.perf_counter()
        trace = from_mcp_session_file(session)
        t_ingest = time.perf_counter() - t0

        t0 = time.perf_counter()
        anns = annotate(trace)
        t_annotate = time.perf_counter() - t0

        t0 = time.perf_counter()
        html = render_html(trace, "bench.jsonl")
        t_report = time.perf_counter() - t0

    results = {"ingest": t_ingest, "annotate": t_annotate,
               "report": t_report}
    print(f"bench: {n} frames · {size_mb:.1f} MB · "
          f"{len(trace.events)} events · {len(anns)} annotations · "
          f"{len(html)} B html")
    failed = False
    for stage, secs in results.items():
        ceiling = CEILINGS[stage]
        fps = n / secs if secs else float("inf")
        flag = "" if secs <= ceiling else "  <-- REGRESSION (ceiling "
        tail = f"{ceiling}s)" if flag else ""
        print(f"  {stage:9s} {secs * 1000:8.1f} ms   "
              f"{fps:10.0f} frames/s{flag}{tail}")
        failed |= secs > ceiling
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
