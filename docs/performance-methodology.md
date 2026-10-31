# Performance methodology

## Session relay append timing (Phase 3a)

From repository root, run `python3 scripts/bench_relay.py --root .` on both
checkouts without concurrent tests or benchmarks. The driver starts seven
fresh CPython interpreters per case and records 10,000 calls to
`SessionLog.record` per interpreter against a private temporary file.
`plain` logs a small `tools/call` frame; `gate_marker` adds a fixed gate
marker. Timing includes the per-line JSONL append and digest update, then
one trailer write and close; it excludes interpreter startup, network I/O,
HTTP policy evaluation, and fsync. Reported median is across seven per-line
sample means; p95 uses nearest rank, so seven-sample p95 is the maximum.

Measured on the same local host, non-root, CPython 3.13; nanoseconds per line:

| Case | Phase 2 base median / p95 | Phase 3a median / p95 | Median change |
|---|---:|---:|---:|
| Plain | 8400.4 / 8938.8 | 8443.1 / 9051.3 | +0.51% |
| Gate marker | 9538.6 / 9959.8 | 9613.9 / 9876.4 | +0.79% |

The measured medians stay within the Phase 3a 2% budget for this synthetic
append path. P95 varies across the seven process samples and is reported for
visibility, not treated as a population tail estimate. Raw reports live under
`/tmp/glassport-phase3a-paired-{base,new}.json` on the measurement host.

## Scanner timing and coverage instrumentation

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
never labeled as the requested core. Worker assertion/import/runtime failures
and sample timeouts are reported as errors, and the command exits nonzero for
those errors so a broken measurement cannot look like an unavailable instrument.

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

## Stdio observer and journal (Handoff 07)

Run `python3 scripts/bench_stdio_relay.py --root CHECKOUT` against baseline and
candidate, without concurrent tests/benchmarks. Each case uses seven fresh
interpreters and 500 sequential request/result pairs through the real `pump`,
private SessionLog, and optional observer/journal (`wrap-journal` or `gate`).
Plain `wrap` now measures the restored passive path. The historical table below
compares the original passive baseline with the pre-review journal-enabled PR. Mode `gate`
also runs the unchanged stdio Gate. Serialization, analysis, logging, and close
are timed; startup, network, real pipe syscalls, and fsync are excluded. The
sink count asserts that all benchmark calls reached upstream. The 2,000-pair
maximum keeps journal recording below its 4,096-record cap.

Measured non-root (UID 1000), CPython 3.13.5, Linux x86_64, baseline `0047731`:

| Path | Baseline median / p95 µs per frame | With journal median / p95 | Median change |
| --- | ---: | ---: | ---: |
| Wrap pump | 13.45 / 14.26 | 144.25 / 252.98 | +972.7% (+130.80 µs) |
| Gate pump | 114.15 / 151.75 | 227.66 / 236.41 | +99.4% (+113.51 µs) |

These measurements expose substantial relative processing overhead, especially
on the previously passive path. They do not establish unchanged latency or
real-pipe throughput. Seven-sample p95 is the maximum; wrap samples show host
variance. Failure isolation and unchanged transport bytes do not mean analysis
is free. Session/detector and journal limits remain active.

The existing append-only benchmark measured plain `10.23 → 10.01 µs` and
marker `15.88 → 11.48 µs` medians. That benchmark excludes the new observer and
journal, so it cannot substantiate the cost of default stdio captures. The 2%
figure above belonged to the earlier Phase 3a append-only change, not this new
analysis path.


## Large stdio results (owner review)

This historical measurement describes #126 before background analysis.
Plain wrap and internal probe performed no live detector analysis;
`wrap --journal` and gate scanned synchronously under the observer lock.
Current behavior and measurements follow below.

Reproduce against `0047731` and the revised checkout using the revised driver:

```bash
python3 scripts/bench_stdio_relay.py --root CHECKOUT \
  --result-bytes 1000000 --iterations 5 --samples 7
```

Each fresh interpreter sends five valid `tools/call` requests and correlated
results containing 1,000,000 ASCII `x` text bytes (plus JSON framing). Measure
from entry to the s2c pump until its first downstream `write`, excluding JSON
input construction, startup, gate c2s checks, teardown, network and real pipe
syscalls. Baseline uses v0.9.0 with no observer; the baseline `wrap-journal`
label is only a passive comparison because that checkout lacks the feature.
Samples are per-process means; median/p95 below summarize seven processes
(p95 is their maximum). UID 1000, CPython 3.13.5, Linux x86_64; runs sequential,
without concurrent tests. Payload and host scheduling affect these values.

| Mode | v0.9.0 median / p95 ms | Revised median / p95 ms | Added median latency |
| --- | ---: | ---: | ---: |
| Plain wrap | 0.049 / 0.093 | 0.048 / 0.068 | approximately unchanged |
| Wrap --journal | 0.049 / 0.093 (passive wrap) | 832.376 / 980.249 | +832.327 ms |
| Gate | 2.146 / 2.263 | 1119.598 / 1481.125 | +1117.452 ms |

These are relay-start latencies, not end-to-end execution times. Passive wrap
logs after the downstream write, as v0.9.0 did; journal-enabled captures record
and analyze before it. The large-frame cost is why journal analysis is opt-in
for wrap. Small-frame averages above must not be extrapolated to large results.


## Background stdio analysis (Handoff 08)

One ordered worker per analyzed stdio session now owns folding, detectors and
normal journal writes. The relay persists its wire receipt and enqueues work;
it never waits for detector completion or queue capacity. The existing Gate
still performs its own synchronous checks. CPU scheduling, file writes and
pipe backpressure remain costs; this is not a universal latency ceiling.

The default queue bound is **64 MiB of queued input-line bytes**, excluding
one item already being analyzed and Python object overhead. Overflow replaces
the payload with a compact ordered marker and poisons subsequent analysis.
Client sequence/digest/gate facts and deliveries remain linked; verification
returns `2`. Control records have an additional bound of twice the journal's
record cap, preventing small overflow markers from growing without limit.
Exceeding that cap abandons analysis and writes a truncation marker.
Shutdown waits at most **10 seconds** for drain; unfinished work is explicitly
truncated, never silently certified over a prefix. These are module constants,
not CLI flags. Normal drains preserve exit-`0` bundles.

Same host, UID 1000, CPython 3.13.5, Linux x86_64. Seven fresh processes per
case, five 1,000,000-byte ASCII results per process, using the command above.
No concurrent benchmark or test load. Both tables report per-process means,
then median / nearest-rank p95 across processes; with seven samples p95 is
only their maximum. Receive-to-write timing remains entry to the real s2c
`pump` through its first downstream sink write, excluding input serialization,
startup, real pipe syscalls, network and shutdown drain.

| Mode | Main `12cfd03` median / p95 ms | Background worker median / p95 ms |
| --- | ---: | ---: |
| Passive wrap | 0.042 / 0.068 | 0.054 / 0.098 |
| Wrap --journal | 811.178 / 1113.054 | 8.094 / 20.567 |
| Gate | 950.314 / 1365.227 | 10.803 / 32.021 |

Both **median** targets pass: gate 10.803 ms is below the pre-#126 gate
baseline plus 25 ms (2.146 + 25 = 27.146 ms; also below 27.1 ms using the
handoff's rounded baseline). Journal wrap 8.094 ms is below passive wrap plus
25 ms (25.054 ms). Gate p95 is higher than that median budget and is reported
without claiming a tail guarantee. An earlier branch run measured gate
10.707 / 19.046 ms and journal wrap 9.253 / 14.089 ms.

Small-frame medians, 500 request/result pairs per process: passive wrap
19.216 → 16.447 µs/frame; journal wrap 148.908 → 32.494 µs/frame; gate
429.433 → 157.394 µs/frame. The old driver included final close in these means;
the updated driver stops relay timing before draining and closing. It must not
charge asynchronous shutdown work as relay latency.

Worker service throughput is reported separately by the updated driver:
**1.241 MB/s** in journal wrap and **1.044 MB/s** in gate, median across seven
processes. MB means 1,000,000 payload bytes. Timing wraps worker processing of
the five large result entries (fold and detector pass); queue wait and drain
waiting are excluded. The worker still analyzes every result in this scenario;
no overflow or truncation occurred. Moving work off the relay does not make
analysis faster, and sustained input faster than service can exhaust the bound.

Raw before/after reports on the measurement host:
`/tmp/h08-{large,small}-baseline.json` and
`/tmp/h08-{large,small}-final.json`. Benchmark results are host/payload specific.

## Server output reads (stdio s2c)

`bench_stdio_relay.py` feeds `pump()` from an in-memory buffer, so it never
measured reading the server's stdout. `run_tap` starts the server with
`bufsize=0`, and `readline()` on that raw pipe made one `read()` syscall per
byte. The s2c pump now reads through `tap.line_reader`, a 64 KiB
`io.BufferedReader` that returns each line as soon as its newline arrives;
writes to the server stay unbuffered.

```
python3 scripts/bench_stdio_pipe_read.py --samples 5
```

Pipe write to complete line returned, median of five, CPython 3.13, Linux:

| Line size | Unbuffered (before) | `line_reader` (after) | read() calls before → after |
| ---: | ---: | ---: | ---: |
| 1 KB | 1.206 ms | 0.237 ms | 1,001 → 1 |
| 100 KB | 80.346 ms | 0.468 ms | 100,001 → 2 |
| 1 MB | 789.658 ms | 1.567 ms | 1,000,001 → 16 |

End to end, `strace -f -c -e trace=read` on `glassport wrap` around a server
that writes one 1 MB line counted 939,915 `read()` calls before and 314 after.
This cost applied to every stdio mode, passive wrap included.
