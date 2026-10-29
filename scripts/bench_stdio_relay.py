#!/usr/bin/env python3
"""Measure real stdio pump processing, including optional analysis/journaling.

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
    def write(self, data):
        self.received_ns = time.perf_counter_ns()
        return super().write(data)

    def close(self):
        pass


def worker(case, iterations, result_bytes=0):
    from glassport import tap
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        gate = tap.Gate(idempotency_max_repeats=iterations + 1) if case == 'gate' else None
        log = tap.open_session_log(root / 'wire.jsonl', mode='gate' if gate else 'wrap')
        options = {}
        journal = observer = None
        analysis_ns = analysis_bytes = 0
        try:
            from glassport.stdio_sessions import StdioObserver
        except ModuleNotFoundError:
            pass  # unchanged main has no stdio observer
        else:
            from glassport.decision_journal import DecisionJournal
            if case != 'wrap':
                observer = StdioObserver(log)
                journal = DecisionJournal(root / 'decisions', observer, mode='gate' if gate else 'observe')
                if hasattr(observer, 'start'):
                    observer.start(journal)
                    process = observer.worker._process

                    def measured(item):
                        nonlocal analysis_ns, analysis_bytes
                        # Worker-only service time for the large result entries;
                        # excludes queue wait, relay work and shutdown waiting.
                        is_result = (item[0] == 'entry' and item[4] == 's2c'
                                     and 'content' in item[1].get('frame', {}).get('result', {}))
                        begin = time.perf_counter_ns()
                        try:
                            return process(item)
                        finally:
                            if is_result:
                                analysis_ns += time.perf_counter_ns() - begin
                                analysis_bytes += result_bytes
                    observer.worker._process = measured
                options = {'observer': observer, 'journal': journal}
        upstream, downstream = Sink(), Sink()

        def send(direction, frame):
            data = (json.dumps(frame) + '\n').encode()
            begin = time.perf_counter_ns()
            tap.pump(io.BytesIO(data), upstream if direction == 'c2s' else downstream,
                     log, direction, gate=gate, client_write=downstream.write, **options)
            return downstream.received_ns - begin if direction == 's2c' else 0

        send('c2s', {'id': 1, 'method': 'tools/list'})
        send('s2c', {'id': 1, 'result': {'tools': [{'name': 'search'}]}})
        result_elapsed = 0
        start = time.perf_counter_ns()
        for index in range(iterations):
            send('c2s', {'id': index + 2, 'method': 'tools/call',
                         'params': {'name': 'search', 'arguments': {'q': 'hello'}}})
            content = [{'type': 'text', 'text': 'x' * result_bytes}] if result_bytes else []
            result_elapsed += send('s2c', {'id': index + 2, 'result': {'content': content}})
        relay_elapsed = time.perf_counter_ns() - start
        if observer is not None and hasattr(observer, 'finish'):
            if not observer.finish():
                raise RuntimeError('analysis drain failed')
        log.write_metrics()
        log.close()
        if journal:
            journal.close()
        if upstream.getvalue().count(b'"tools/call"') != iterations:
            raise RuntimeError('benchmark calls did not reach upstream')
        return {'relay_ns_per_frame': (result_elapsed / iterations if result_bytes else
                                      relay_elapsed / (2 * iterations)),
                'analysis_mb_s': (analysis_bytes / 1_000_000 / (analysis_ns / 1e9)
                                  if analysis_ns and analysis_bytes else None)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--samples', type=int, default=7)
    parser.add_argument('--iterations', type=int, default=500)
    parser.add_argument('--worker', choices=('wrap', 'wrap-journal', 'gate'))
    parser.add_argument('--result-bytes', type=int, default=0,
                        help='text bytes in each tool result; time s2c pump entry to downstream write when nonzero')
    args = parser.parse_args()
    if args.samples < 1 or not 1 <= args.iterations <= 2000:
        parser.error('positive samples and 1..2000 iterations required (journal record cap)')
    if not 0 <= args.result_bytes <= 1_000_000:
        parser.error('result bytes must be 0..1000000')
    if args.worker:
        print(json.dumps(worker(args.worker, args.iterations, args.result_bytes)))
        return
    report = {'python': platform.python_version(), 'platform': platform.platform(),
              'uid': os.getuid() if hasattr(os, 'getuid') else None,
              'root': str(args.root.resolve()), 'samples': args.samples,
              'pairs_per_sample': args.iterations, 'result_bytes': args.result_bytes,
              'timed': 's2c pump entry to downstream write' if args.result_bytes else 'request/result pair', 'cases': {}}
    for case in ('wrap', 'wrap-journal', 'gate'):
        values = []
        throughput = []
        for _ in range(args.samples):
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), '--worker', case,
                 '--iterations', str(args.iterations), '--result-bytes', str(args.result_bytes)], cwd=args.root,
                env=dict(os.environ, PYTHONPATH=str(args.root.resolve() / 'src')),
                capture_output=True, text=True, check=True, timeout=60)
            sample = json.loads(result.stdout)
            values.append(sample['relay_ns_per_frame'])
            if sample['analysis_mb_s'] is not None:
                throughput.append(sample['analysis_mb_s'])
        report['cases'][case] = {'ns_per_frame': values,
                                'median_ns': statistics.median(values),
                                'p95_ns': sorted(values)[math.ceil(.95 * len(values)) - 1]}
        if throughput:
            report['cases'][case]['analysis_mb_s'] = {
                'samples': throughput, 'median': statistics.median(throughput)}
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
