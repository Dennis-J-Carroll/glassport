#!/usr/bin/env python3
"""Measure real stdio pump processing, including default analysis/journaling.

Run this same driver with --root pointing at each checkout. Seven fresh
interpreters per case, sequential request/result pairs, private local files,
no fsync or network. Pipe syscalls and process startup are excluded.
"""
from __future__ import annotations

import argparse
import io
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


class Sink(io.BytesIO):
    def close(self):
        pass


def worker(case, iterations):
    from glassport import tap
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        gate = tap.Gate(idempotency_max_repeats=iterations + 1) if case == 'gate' else None
        log = tap.open_session_log(root / 'wire.jsonl', mode='gate' if gate else 'wrap')
        options = {}
        journal = None
        try:
            from glassport.stdio_sessions import StdioObserver
        except ModuleNotFoundError:
            pass  # unchanged main has no stdio observer
        else:
            from glassport.decision_journal import DecisionJournal
            observer = StdioObserver(log)
            journal = DecisionJournal(root / 'decisions', observer, mode='gate' if gate else 'observe')
            options = {'observer': observer, 'journal': journal}
        upstream, downstream = Sink(), Sink()

        def send(direction, frame):
            data = (json.dumps(frame) + '\n').encode()
            tap.pump(io.BytesIO(data), upstream if direction == 'c2s' else downstream,
                     log, direction, gate=gate, client_write=downstream.write, **options)

        send('c2s', {'id': 1, 'method': 'tools/list'})
        send('s2c', {'id': 1, 'result': {'tools': [{'name': 'search'}]}})
        start = time.perf_counter_ns()
        for index in range(iterations):
            send('c2s', {'id': index + 2, 'method': 'tools/call',
                         'params': {'name': 'search', 'arguments': {'q': 'hello'}}})
            send('s2c', {'id': index + 2, 'result': {'content': []}})
        log.write_metrics()
        log.close()
        if journal:
            journal.close()
        if upstream.getvalue().count(b'"tools/call"') != iterations:
            raise RuntimeError('benchmark calls did not reach upstream')
        return (time.perf_counter_ns() - start) / (2 * iterations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--samples', type=int, default=7)
    parser.add_argument('--iterations', type=int, default=500)
    parser.add_argument('--worker', choices=('wrap', 'gate'))
    args = parser.parse_args()
    if args.samples < 1 or not 1 <= args.iterations <= 2000:
        parser.error('positive samples and 1..2000 iterations required (journal record cap)')
    if args.worker:
        print(worker(args.worker, args.iterations))
        return
    report = {'python': platform.python_version(), 'platform': platform.platform(),
              'uid': os.getuid() if hasattr(os, 'getuid') else None,
              'root': str(args.root.resolve()), 'samples': args.samples,
              'pairs_per_sample': args.iterations, 'cases': {}}
    for case in ('wrap', 'gate'):
        values = []
        for _ in range(args.samples):
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), '--worker', case,
                 '--iterations', str(args.iterations)], cwd=args.root,
                env=dict(os.environ, PYTHONPATH=str(args.root.resolve() / 'src')),
                capture_output=True, text=True, check=True, timeout=60)
            values.append(float(result.stdout.strip()))
        report['cases'][case] = {'ns_per_frame': values,
                                'median_ns': statistics.median(values),
                                'p95_ns': sorted(values)[math.ceil(.95 * len(values)) - 1]}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
