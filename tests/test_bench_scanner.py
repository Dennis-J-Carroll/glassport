"""Focused checks for the informational scanner benchmark driver."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bench_scanner.py"


def load_benchmark():
    spec = importlib.util.spec_from_file_location("bench_scanner", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load scanner benchmark")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestScannerBenchmark(unittest.TestCase):
    def test_nearest_rank_p95(self):
        benchmark = load_benchmark()
        self.assertEqual(benchmark._p95([1.0, 3.0, 2.0]), 3.0)

    def test_small_normal_run_reports_both_real_entry_points(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--samples", "2", "--modes", "normal",
             "--begin-markers", "4", "--argument-bytes", "128"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(report["modes"]["normal"]["actual_core"], "none")
        self.assertEqual(report["modes"]["normal"]["sample_count"], 2)
        self.assertEqual(report["cases"]["begin_marker_flood"]["entry_point"],
                         "detectors._scan_pii")
        self.assertEqual(report["cases"]["long_argument_exfiltration"]["entry_point"],
                         "detectors.data_exfiltration")


if __name__ == "__main__":
    unittest.main()
