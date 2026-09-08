#!/usr/bin/env python3
"""Compare scanner timing with normal, C-trace, and sys.monitoring execution.

The parent process starts one fresh child per sample.  Each child measures the
first and second invocation of the two adversarial paths used by the test
suite.  Coverage data is written below a temporary directory and discarded.

Run from the repository root:

    PYTHONPATH=src python scripts/bench_scanner.py --samples 7

This is an informational measurement driver.  It has no timing gate.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
DEFAULT_BEGIN_MARKERS = 200_000
DEFAULT_ARGUMENT_BYTES = 2 * 1024 * 1024
MODES = ("normal", "ctrace", "sysmon")
EXPECTED_CORES = {"normal": "none", "ctrace": "ctrace", "sysmon": "sysmon"}


def _coverage_identity() -> tuple[str | None, str]:
    """Return the installed coverage version and the active tracing core."""
    try:
        import coverage
    except ImportError:
        return None, "none"

    current = coverage.Coverage.current()
    if current is None:
        return coverage.__version__, "none"
    core = getattr(current, "_core", None)
    tracer_class = getattr(core, "tracer_class", None)
    tracer_name = getattr(tracer_class, "__name__", "unknown")
    return coverage.__version__, {
        "CTracer": "ctrace",
        "SysMonitor": "sysmon",
        "PyTracer": "pytrace",
    }.get(tracer_name, tracer_name)


def _frame(seq: int, direction: str, frame: dict[str, Any]) -> str:
    return json.dumps({
        "schema_version": "0.1",
        "seq": seq,
        "ts": "2026-01-01T00:00:00+00:00",
        "dir": direction,
        "frame": frame,
        "raw": None,
    })


def _adversarial_inputs(begin_markers: int, argument_bytes: int) -> tuple[str, Any]:
    sys.path.insert(0, str(SRC))
    from glassport.adapters.mcp_session import from_mcp_session

    flood = "-----BEGIN PRIVATE KEY-----\n" * begin_markers
    lines = [
        _frame(1, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-03-26"}}),
        _frame(2, "s2c", {"jsonrpc": "2.0", "id": 1, "result": {
            "protocolVersion": "2025-03-26", "capabilities": {}}}),
        _frame(3, "c2s", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
        _frame(4, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        _frame(5, "s2c", {"jsonrpc": "2.0", "id": 2, "result": {
            "tools": [{"name": "web_search", "inputSchema": {"type": "object"}}]}}),
        _frame(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "web_search",
                                      "arguments": {"query": "x" * argument_bytes}}}),
    ]
    return flood, from_mcp_session(lines)


def _time_call(function: Any, argument: Any) -> tuple[float, Any]:
    started = time.perf_counter_ns()
    result = function(argument)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return elapsed_ms, result


def _worker(begin_markers: int, argument_bytes: int) -> dict[str, Any]:
    # User-supplied custom patterns change scanner work and make comparisons
    # incomparable, so the benchmark always measures the built-in baseline.
    os.environ.pop("GLASSPORT_PII_PATTERNS", None)
    flood, trace = _adversarial_inputs(begin_markers, argument_bytes)
    from glassport import detectors

    measurements: dict[str, dict[str, float]] = {}
    cold, cold_result = _time_call(detectors._scan_pii, flood)
    warm, warm_result = _time_call(detectors._scan_pii, flood)
    if cold_result or warm_result:
        raise AssertionError("unterminated BEGIN-marker flood produced a PII hit")
    measurements["begin_marker_flood"] = {"cold_ms": cold, "warm_ms": warm}

    cold, cold_result = _time_call(detectors.data_exfiltration, trace)
    warm, warm_result = _time_call(detectors.data_exfiltration, trace)
    if cold_result or warm_result:
        raise AssertionError("long benign tool argument produced an annotation")
    measurements["long_argument_exfiltration"] = {"cold_ms": cold, "warm_ms": warm}

    coverage_version, actual_core = _coverage_identity()
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "coverage_version": coverage_version,
        "actual_core": actual_core,
        "measurements": measurements,
    }


def _p95(values: list[float]) -> float:
    """Nearest-rank p95, defined for every positive sample count."""
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def _summary(samples: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for case in ("begin_marker_flood", "long_argument_exfiltration"):
        out[case] = {}
        for temperature in ("cold_ms", "warm_ms"):
            values = [sample["measurements"][case][temperature] for sample in samples]
            out[case][temperature] = {
                "median": round(statistics.median(values), 3),
                "p95": round(_p95(values), 3),
                "samples": [round(value, 3) for value in values],
            }
    return out


def _sample_command(mode: str, data_file: Path, args: argparse.Namespace) -> tuple[list[str], dict[str, str]]:
    worker_args = [
        str(Path(__file__).resolve()),
        "--worker",
        "--begin-markers", str(args.begin_markers),
        "--argument-bytes", str(args.argument_bytes),
    ]
    env = os.environ.copy()
    env.pop("COVERAGE_PROCESS_START", None)
    env.pop("COVERAGE_CORE", None)
    env.pop("GLASSPORT_PII_PATTERNS", None)
    env["PYTHONPATH"] = str(SRC)
    if mode == "normal":
        return [sys.executable, *worker_args], env
    env["COVERAGE_CORE"] = mode
    return [
        sys.executable, "-m", "coverage", "run",
        f"--data-file={data_file}", "--source=src/glassport", *worker_args,
    ], env


def _run_mode(mode: str, args: argparse.Namespace, temp_dir: Path) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for sample_number in range(args.samples):
        command, env = _sample_command(
            mode, temp_dir / f"{mode}-{sample_number}.coverage", args,
        )
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=args.timeout,
            check=False,
        )
        if completed.returncode:
            reason = completed.stderr.strip() or completed.stdout.strip()
            return {
                "status": "unsupported",
                "reason": reason[-1000:] or f"worker exited {completed.returncode}",
                "requested_core": mode,
                "samples_completed": len(samples),
            }
        try:
            sample = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            return {
                "status": "unsupported",
                "reason": f"worker did not emit JSON: {exc}: {completed.stdout[-500:]}",
                "requested_core": mode,
                "samples_completed": len(samples),
            }
        expected = EXPECTED_CORES[mode]
        if sample["actual_core"] != expected:
            return {
                "status": "unsupported",
                "reason": f"requested {expected}, coverage selected {sample['actual_core']}",
                "requested_core": mode,
                "actual_core": sample["actual_core"],
                "coverage_version": sample["coverage_version"],
                "samples_completed": len(samples),
            }
        samples.append(sample)

    identity = samples[0]
    return {
        "status": "supported",
        "requested_core": mode,
        "actual_core": identity["actual_core"],
        "coverage_version": identity["coverage_version"],
        "sample_count": len(samples),
        "timings_ms": _summary(samples),
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=7,
                        help="fresh processes per mode (default: 7)")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    parser.add_argument("--begin-markers", type=int, default=DEFAULT_BEGIN_MARKERS,
                        help=argparse.SUPPRESS)
    parser.add_argument("--argument-bytes", type=int, default=DEFAULT_ARGUMENT_BYTES,
                        help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="per-sample subprocess timeout in seconds")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.samples < 2:
        parser.error("samples must be at least 2")
    if args.begin_markers < 1 or args.argument_bytes < 1 or args.timeout <= 0:
        parser.error("input sizes and timeout must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.worker:
        print(json.dumps(_worker(args.begin_markers, args.argument_bytes)))
        return 0

    report: dict[str, Any] = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "sample_count_per_mode": args.samples,
        "cases": {
            "begin_marker_flood": {"entry_point": "detectors._scan_pii",
                                   "begin_markers": args.begin_markers},
            "long_argument_exfiltration": {
                "entry_point": "detectors.data_exfiltration",
                "argument_bytes": args.argument_bytes,
            },
        },
        "p95_method": "nearest-rank",
        "modes": {},
    }
    with tempfile.TemporaryDirectory(prefix="glassport-scanner-bench-") as temp:
        for mode in args.modes:
            report["modes"][mode] = _run_mode(mode, args, Path(temp))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
