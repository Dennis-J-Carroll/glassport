# Scanner timing and coverage instrumentation

The security timing tests retain their existing inputs and deadlines. The
opt-in coverage job uses CPython 3.13 and coverage.py 7.13.0 with
`COVERAGE_CORE=sysmon`. The ordinary stdlib test matrix still covers Python
3.10–3.13. Runtime dependencies and scanner code are unchanged.

Coverage is instrumentation, so its overhead is part of a test's measured
elapsed time. Earlier full-suite runs under the C tracer crossed the existing
2-second long-argument and 3-second BEGIN-flood deadlines. That does not prove
scanner regression, nor does a fast isolated run prove a loaded host cannot
cross a deadline. We compare repeated measurements before changing the
instrumentation; no timing threshold is raised and no scanner coverage is
excluded.

## Reproduce the measurements

From the repository root, with coverage.py 7.13.0 installed:

```bash
PYTHONPATH=src python scripts/bench_scanner.py --samples 7 > /tmp/scanner-benchmark.json
```

The stdlib driver runs modes serially. Each sample starts a fresh interpreter
and times the first and second invocation of each entry point. “Cold” here
means its first invocation in that process, after imports and input assembly;
it does not include interpreter startup or guarantee cold CPU/filesystem caches.
The second entry point runs after the first scanner case, so shared scanner
initialization may already be warm. Run without concurrent test or benchmark
processes. The report includes all samples, median, nearest-rank p95, platform,
Python version, coverage version and the observed tracing core. With seven
samples p95 is the maximum, not a precise estimate of a population tail.

Inputs match the adversarial test paths: 200,000 unterminated BEGIN markers
through `detectors._scan_pii`, and a 2 MiB benign tool argument through the full
`detectors.data_exfiltration` entry point. Scan normalization and the existing
input cap remain active. Custom PII configuration is cleared in child processes
to measure the built-in baseline. Coverage artifacts live in a temporary
directory and are removed after each benchmark invocation. Missing coverage or
an unsupported requested core is reported explicitly; fallback measurements are
never labeled as the requested core.

## Measured result, 2026-09-08

CPython 3.13.5, coverage.py 7.13.0, Linux 7.1.1 x86_64/glibc 2.35.
Seven fresh processes per mode; milliseconds, median / p95:

| Entry point | Mode | First invocation | Second invocation |
|---|---|---:|---:|
| BEGIN flood | Normal | 666.811 / 680.175 | 671.611 / 714.973 |
| BEGIN flood | C tracer | 962.802 / 1382.953 | 987.945 / 1142.563 |
| BEGIN flood | Sys.monitoring | 708.637 / 746.410 | 743.271 / 772.197 |
| Long argument | Normal | 838.310 / 999.001 | 835.258 / 861.313 |
| Long argument | C tracer | 1140.435 / 1316.846 | 1178.972 / 1437.065 |
| Long argument | Sys.monitoring | 913.040 / 953.927 | 912.693 / 930.830 |

Both instrumented modes passed these isolated measurements. Sys.monitoring
showed lower overhead in both cases, which supports choosing it for the
coverage job; this is host-specific evidence, not a universal speed guarantee.
The raw local report is `/tmp/glassport-scanner-benchmark.json` and is not a
tracked build artifact.

Separate runs of the same benchmark worker under the C and sys.monitoring
cores produced identical per-file executed/missing/excluded line evidence
(626 covered statements across the measured package source). This comparison
checks these two paths, not universal equivalence between coverage engines.
The coverage job still runs the complete suite and retains its 85% core gate.

## CI core verification

The workflow pins the measured coverage version and runs a traced unittest
with `coverage run --debug=sys`. It requires the debug identity
`core: SysMonitor` before running the suite. A future runtime incompatibility
or tracer fallback therefore fails visibly instead of silently changing the
timing methodology. This job collects line coverage; branch-coverage support
is not part of this change.

For local verification using an already-cached MCP filesystem server:

```bash
COVERAGE_CORE=sysmon npm_config_offline=true python -m coverage run \
  --source=src/glassport -m unittest discover -s tests -t .
```

The integration tests require localhost sockets. `npm_config_offline=true`
prevents the existing npx fixture from downloading packages; the cache must
already contain its dependency. CI retains its existing installation path.

Verified local full run: **784 tests passed in 38.731 seconds**, **93% core
line coverage**; the unchanged 85% gate passed. The traced CI probe reported
`SysMonitor`. Existing HTTP socket ResourceWarnings remained visible.
