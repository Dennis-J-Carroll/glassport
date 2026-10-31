#!/usr/bin/env python3
"""Measure the cost of reading server output lines from a real pipe.

bench_stdio_relay.py feeds pump() from an in-memory buffer, so it excludes the
read syscalls on the server's stdout. This driver times pipe write -> complete
line returned, for an unbuffered readline (as run_tap used before line_reader)
and for tap.line_reader, and counts read() calls. No files, no network.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import statistics
import sys
import threading
import time


class CountingPipe(io.RawIOBase):
    def __init__(self, fd):
        self.fd, self.calls = fd, 0

    def readable(self):
        return True

    def readinto(self, buffer):
        self.calls += 1
        data = os.read(self.fd, len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        if not self.closed:
            os.close(self.fd)
        super().close()


def read_once(size, buffered):
    line = b"x" * size + b"\n"
    r, w = os.pipe()
    raw = CountingPipe(r)
    if buffered:
        from glassport import tap
        src = tap.line_reader(raw)
    else:
        src = raw
    writer = threading.Thread(target=lambda: (os.write(w, line), os.close(w)))
    begin = time.perf_counter_ns()
    writer.start()
    got = src.readline()
    elapsed = time.perf_counter_ns() - begin
    writer.join()
    src.close()
    if got != line:
        raise RuntimeError("line corrupted")
    return elapsed / 1e6, raw.calls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--sizes", default="1000,100000,1000000")
    args = parser.parse_args()
    sys.path.insert(0, str(args.root / "src"))
    report = {}
    for size in (int(s) for s in args.sizes.split(",")):
        for mode, buffered in (("unbuffered", False), ("line_reader", True)):
            runs = [read_once(size, buffered) for _ in range(args.samples)]
            report[f"{size}:{mode}"] = {
                "median_ms": round(statistics.median(r[0] for r in runs), 3),
                "read_calls": runs[0][1],
            }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
