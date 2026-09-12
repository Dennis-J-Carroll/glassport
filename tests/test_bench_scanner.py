"""Focused checks for the informational scanner benchmark driver."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def _args(self, benchmark):
        return benchmark._parse_args(["--samples", "2", "--modes", "ctrace",
                                      "--timeout", "1"])

    def test_worker_failure_is_error(self):
        benchmark = load_benchmark()
        result = mock.Mock(returncode=1, stderr="AssertionError: scanner failed",
                           stdout="")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                benchmark.subprocess, "run", return_value=result):
            report = benchmark._run_mode("ctrace", self._args(benchmark),
                                         Path(directory))
        self.assertEqual(report["status"], "error")
        self.assertIn("AssertionError", report["reason"])

    def test_timeout_is_error(self):
        benchmark = load_benchmark()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                benchmark.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["coverage"], 1)):
            report = benchmark._run_mode("ctrace", self._args(benchmark),
                                         Path(directory))
        self.assertEqual(report["status"], "error")
        self.assertIn("timed out", report["reason"])

    def test_missing_coverage_is_unsupported(self):
        benchmark = load_benchmark()
        result = mock.Mock(returncode=1,
                           stderr="/usr/bin/python: No module named coverage",
                           stdout="")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                benchmark.subprocess, "run", return_value=result):
            report = benchmark._run_mode("ctrace", self._args(benchmark),
                                         Path(directory))
        self.assertEqual(report["status"], "unsupported")

    def test_actual_core_mismatch_is_unsupported(self):
        benchmark = load_benchmark()
        result = mock.Mock(returncode=0, stderr="", stdout=json.dumps({
            "actual_core": "pytrace", "coverage_version": "7.13.0",
        }))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                benchmark.subprocess, "run", return_value=result):
            report = benchmark._run_mode("ctrace", self._args(benchmark),
                                         Path(directory))
        self.assertEqual(report["status"], "unsupported")
        self.assertEqual(report["actual_core"], "pytrace")

    def test_duplicate_modes_are_deduplicated_preserving_order(self):
        # A repeated --modes entry must be run (and recorded) exactly once,
        # not once per occurrence: two _run_mode calls for the same mode
        # would let the second silently clobber the first's recorded
        # result (including an earlier failure) in report["modes"].
        benchmark = load_benchmark()
        calls: list[str] = []

        def fake_run_mode(mode, args, temp_dir):
            calls.append(mode)
            return {"status": "supported", "requested_core": mode,
                    "actual_core": mode, "coverage_version": None,
                    "sample_count": args.samples, "timings_ms": {}}

        with mock.patch.object(benchmark, "_run_mode", side_effect=fake_run_mode), \
                mock.patch.object(benchmark, "_parse_args", return_value=mock.Mock(
                    worker=False, modes=["normal", "normal", "ctrace"], samples=2,
                    begin_markers=1, argument_bytes=1, timeout=1)):
            exit_code = benchmark.main([])
        self.assertEqual(exit_code, 0)
        # First-occurrence order preserved; "normal" run only once despite
        # appearing twice in the requested modes.
        self.assertEqual(calls, ["normal", "ctrace"])

    def test_cli_duplicate_modes_produces_single_clean_result(self):
        # End-to-end smoke check that the real CLI accepts a duplicate mode
        # without raising and produces one clean report entry for it. This
        # does not by itself prove dedup happened (report["modes"] is a dict
        # keyed by mode name, so it would show one entry either way) — that
        # is what test_duplicate_modes_are_deduplicated_preserving_order
        # (above) locks via call count.
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--samples", "2", "--modes", "normal",
             "normal", "--begin-markers", "4", "--argument-bytes", "128"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(list(report["modes"].keys()), ["normal"])
        self.assertEqual(report["modes"]["normal"]["status"], "supported")
        self.assertEqual(report["modes"]["normal"]["sample_count"], 2)

    def test_main_returns_nonzero_for_error_and_zero_for_unsupported(self):
        benchmark = load_benchmark()
        error = {"status": "error", "reason": "boom"}
        unsupported = {"status": "unsupported", "reason": "no core"}
        with mock.patch.object(benchmark, "_run_mode", return_value=error), \
                mock.patch.object(benchmark, "_parse_args", return_value=mock.Mock(
                    worker=False, modes=["normal"], samples=2,
                    begin_markers=1, argument_bytes=1, timeout=1)):
            self.assertEqual(benchmark.main([]), 1)
        with mock.patch.object(benchmark, "_run_mode", return_value=unsupported), \
                mock.patch.object(benchmark, "_parse_args", return_value=mock.Mock(
                    worker=False, modes=["normal"], samples=2,
                    begin_markers=1, argument_bytes=1, timeout=1)):
            self.assertEqual(benchmark.main([]), 0)


if __name__ == "__main__":
    unittest.main()
