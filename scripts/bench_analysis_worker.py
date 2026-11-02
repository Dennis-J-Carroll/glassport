#!/usr/bin/env python3
"""Informational 1 MB analysis profile; seven fresh interpreters per shape.

Run: PYTHONPATH=src python scripts/bench_analysis_worker.py --root CHECKOUT
No transport, disk writes, or timing gate. Each worker builds its own session.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time


SHAPES = ("ascii-prose", "x", "mixed", "all-cjk", "pii-dense", "adversarial")


def payload(shape: str, size: int = 1_000_000) -> str:
    """Deterministic text shapes; generation is outside every timed stage."""
    if shape == "x":
        return "x" * size
    if shape == "all-cjk":
        return "漢" * size
    if shape == "ascii-prose":
        rng = random.Random(901)
        words = ("".join(chr(97 + rng.randrange(26)) for _ in range(rng.randrange(3, 10)))
                 for _ in range(size // 6 + 1))
        return " ".join(words)[:size].ljust(size, "a")
    if shape == "mixed":
        block = "ordinary ascii words with punctuation, spaces, and numbers 12345 "
        block = (block * 3)[:98] + "é漢"
        return (block * (size // len(block) + 1))[:size]
    if shape == "pii-dense":
        block = ("contact test.person@example.org AKIA" + "A" * 16 +
                 " eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2lnbmF0dXJl ")
        block = block.ljust(200, "q")
        return (block * (size // len(block) + 1))[:size]
    if shape == "adversarial":
        # Fake credential shapes from encoded-canary tests, with all mark classes.
        block = ("sk-\u0430nt-api03-" + "A\u200b\u0301\u0903\u20dd" * 20 +
                 " \u1d00\u200bKIA" + "A\u0332" * 16 + " ordinary ")
        return (block * (size // len(block) + 1))[:size]
    raise ValueError(shape)


def _entry(seq: int, direction: str, frame: dict) -> dict:
    return {"schema_version": "0.1", "seq": seq, "ts": f"t{seq}",
            "dir": direction, "frame": frame, "raw": None}


def _primed_session():
    from glassport.adapters.mcp_session import MCPTraceBuilder
    from glassport.incremental import DetectorEngine, default_detectors

    builder = MCPTraceBuilder(retain_events=False)
    active = default_detectors()
    engine = DetectorEngine(active)
    frames = [
        ("c2s", {"id": 1, "method": "initialize", "params": {"capabilities": {}}}),
        ("s2c", {"id": 1, "result": {"capabilities": {}}}),
        ("c2s", {"method": "notifications/initialized"}),
        ("c2s", {"id": 2, "method": "tools/list"}),
        ("s2c", {"id": 2, "result": {"tools": [{"name": "echo"}]}}),
        ("c2s", {"id": 3, "method": "tools/call",
                  "params": {"name": "echo", "arguments": {"text": "hello"}}}),
    ]
    for seq, (direction, frame) in enumerate(frames, 1):
        event = builder.feed(_entry(seq, direction, frame))
        if event is not None:
            engine.on_event(event, builder.state)
    return builder, engine, active


def sample(shape: str, size: int) -> dict:
    from glassport import detectors

    raw = payload(shape, size)
    frame = _entry(7, "s2c", {"id": 3, "result": {
        "content": [{"type": "text", "text": raw}]}})
    blob = json.dumps([raw], ensure_ascii=False)
    timings = {}

    begin = time.perf_counter_ns()
    normalized = detectors._normalize_for_scan(blob)
    timings["normalize"] = time.perf_counter_ns() - begin

    begin = time.perf_counter_ns()
    detectors._scan_normalized(normalized)
    timings["regex_scan"] = time.perf_counter_ns() - begin

    builder, _, _ = _primed_session()
    begin = time.perf_counter_ns()
    event = builder.feed(frame)
    timings["builder"] = time.perf_counter_ns() - begin
    if event is None:
        raise RuntimeError("result did not produce event")

    for detector in _primed_session()[2]:
        begin = time.perf_counter_ns()
        detector.on_event(event, builder.state)
        timings[detector.name] = time.perf_counter_ns() - begin

    builder, engine, _ = _primed_session()
    begin = time.perf_counter_ns()
    event = builder.feed(frame)
    engine.on_event(event, builder.state)
    timings["end_to_end"] = time.perf_counter_ns() - begin
    return {"shape": shape, "size": size, "ns": timings}


def _summarize(values: list[int]) -> dict[str, float]:
    ordered = sorted(values)
    return {"median_ms": round(statistics.median(values) / 1e6, 3),
            "p95_ms": round(ordered[math.ceil(.95 * len(values)) - 1] / 1e6, 3)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--size", type=int, default=1_000_000)
    parser.add_argument("--worker", choices=SHAPES)
    args = parser.parse_args()
    if args.samples < 1 or args.size < 1:
        parser.error("samples and size must be positive")
    if args.worker:
        print(json.dumps(sample(args.worker, args.size)))
        return
    report = {"root": str(args.root.resolve()), "base_sha": None,
              "python": platform.python_version(), "platform": platform.platform(),
              "uid": os.getuid() if hasattr(os, "getuid") else None,
              "size": args.size, "samples": args.samples, "shapes": {}}
    for shape in SHAPES:
        samples = []
        for _ in range(args.samples):
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--worker", shape,
                 "--size", str(args.size)], cwd=args.root,
                env=dict(os.environ, PYTHONPATH=str(args.root.resolve() / "src")),
                capture_output=True, text=True, check=True, timeout=120)
            samples.append(json.loads(completed.stdout)["ns"])
        report["shapes"][shape] = {stage: _summarize([s[stage] for s in samples])
                                   for stage in samples[0]}
    print(json.dumps(report, indent=2))
    print("shape         normalize  regex  builder  exfil  end-to-end (median ms)", file=sys.stderr)
    for shape, stages in report["shapes"].items():
        print(f"{shape:13} {stages['normalize']['median_ms']:9.3f} "
              f"{stages['regex_scan']['median_ms']:6.3f} "
              f"{stages['builder']['median_ms']:8.3f} "
              f"{stages['data_exfiltration']['median_ms']:6.3f} "
              f"{stages['end_to_end']['median_ms']:10.3f}", file=sys.stderr)


if __name__ == "__main__":
    main()
