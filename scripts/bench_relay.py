#!/usr/bin/env python3
"""Repeatable SessionLog relay-path benchmark; run from a clean checkout.

Each sample gets a fresh interpreter and private temporary file. Modes run
serially so benchmark processes do not compete with each other.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time


LINE = (b'{"jsonrpc":"2.0","id":7,"method":"tools/call",'
        b'"params":{"name":"search","arguments":{"q":"hello"}}}\n')
GATE = {"action": "gate_skipped", "reason": "no_surface_timeout",
        "tool": "search"}


def _worker(case: str, iterations: int) -> float:
    from glassport.tap import SessionLog

    marker = GATE if case == "gate_marker" else None
    with tempfile.TemporaryDirectory() as tmp:
        log = SessionLog(Path(tmp) / "session.jsonl")
        start = time.perf_counter_ns()
        for _ in range(iterations):
            if log.record("c2s", LINE, gate=marker) is None:
                raise RuntimeError("session log append failed")
        log.write_metrics()
        log.close()
        return (time.perf_counter_ns() - start) / iterations


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--worker", choices=("plain", "gate_marker"))
    args = parser.parse_args(argv)
    if args.samples < 1 or args.iterations < 1:
        parser.error("samples and iterations must be positive")
    if args.worker:
        print(_worker(args.worker, args.iterations))
        return 0
    report = {"platform": platform.platform(), "python": platform.python_version(),
              "root": str(args.root.resolve()), "samples": args.samples,
              "iterations_per_sample": args.iterations, "p95_method": "nearest-rank",
              "cases": {}}
    for case in ("plain", "gate_marker"):
        values = []
        for _ in range(args.samples):
            env = dict(os.environ, PYTHONPATH=str(args.root.resolve() / "src"))
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--worker", case,
                 "--iterations", str(args.iterations)], cwd=args.root,
                env=env, text=True, capture_output=True, check=True)
            values.append(float(result.stdout.strip()))
        ordered = sorted(values)
        report["cases"][case] = {
            "ns_per_line": values, "median_ns": statistics.median(values),
            "p95_ns": ordered[math.ceil(0.95 * len(ordered)) - 1],
        }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
