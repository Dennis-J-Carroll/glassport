"""Repeated live-ingestion measurements; informational, with structural bounds.

Run: PYTHONPATH=src python scripts/bench_incremental.py
Measures builder + all built-in detectors over normalized tap entries. No file
I/O, renderer, or transport is included. Timing is not a single-run CI gate.
"""
from __future__ import annotations

import argparse
import gc
import json
import platform
import statistics
import time
import tracemalloc

from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.incremental import DetectorEngine


def create_session():
    builder, engine = MCPTraceBuilder(retain_events=False), DetectorEngine()
    frames = [
        ("c2s", {"id": 1, "method": "initialize", "params": {"capabilities": {}}}),
        ("s2c", {"id": 1, "result": {"capabilities": {}}}),
        ("c2s", {"method": "notifications/initialized"}),
        ("c2s", {"id": 2, "method": "tools/list"}),
        ("s2c", {"id": 2, "result": {"tools": [{"name": "echo"}]}}),
    ]
    for seq, (direction, frame) in enumerate(frames):
        event = builder.ingest_frame({"seq": seq, "dir": direction, "frame": frame})
        engine.on_event(event, builder.state)
    return builder, engine


def step(builder, engine, seq):
    event = builder.ingest_frame({"seq": seq, "dir": "c2s", "frame": {
        "id": seq, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hello"}}}})
    engine.on_event(event, builder.state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.events < 1 or args.repeats < 2:
        parser.error("events must be positive and repeats must be at least 2")
    latencies, throughput = [], []
    for _ in range(args.repeats):
        builder, engine = create_session()
        start = time.perf_counter_ns()
        for seq in range(10, args.events + 10):
            tick = time.perf_counter_ns()
            step(builder, engine, seq)
            latencies.append((time.perf_counter_ns() - tick) / 1000)
        elapsed = (time.perf_counter_ns() - start) / 1e9
        throughput.append(args.events / elapsed)
    del builder, engine
    gc.collect()
    tracemalloc.start()
    builder, engine = create_session()
    warm = 2 * builder.state.limits.max_pending
    for seq in range(10, warm + 10):
        step(builder, engine, seq)
    gc.collect()
    before = tracemalloc.get_traced_memory()[0]
    for seq in range(warm + 10, 4 * warm + 10):
        step(builder, engine, seq)
    gc.collect()
    after, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert not builder.events and not builder.snapshot().annotations
    assert len(builder.pending) <= builder.state.limits.max_pending
    print(json.dumps({
        "python": platform.python_version(), "platform": platform.platform(),
        "events_per_sample": args.events, "samples": args.repeats,
        "median_events_per_second": round(statistics.median(throughput)),
        "median_event_us": round(statistics.median(latencies), 2),
        "p95_event_us": round(statistics.quantiles(latencies, n=100)[94], 2),
        "memory_warmup_events": warm, "memory_total_events": 4 * warm,
        "retained_bytes_after_warmup": before, "retained_bytes_final": after,
        "retained_growth_bytes": after - before, "peak_bytes": peak,
        "retained_pending": len(builder.pending), "retained_events": len(builder.events),
    }, indent=2))


if __name__ == "__main__":
    main()
