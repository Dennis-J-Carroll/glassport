# Task 1 diagnostic fix report

## Scope

Updated `scripts/bench_scanner.py` so unavailable coverage instrumentation and
observed-core mismatches remain `unsupported`, while worker assertion/import/
runtime failures, malformed worker output, and sample timeouts are `error`.
The top-level command returns exit code 1 when any selected mode is `error`,
and returns 0 for supported or unsupported modes. No timing threshold was
added. Added mocked focused coverage for each status and exit-code behavior.

## Validation

Exact command:

```text
python -m unittest tests.test_bench_scanner
```

Result: `Ran 7 tests in 0.309s` / `OK`.

The controller separately ran the full e111202 suite before this change:
`804 passing, 40.603s`. Real benchmarks and the full suite were not rerun by
this task.

## Revision

- Base: `e11120256770ae3aed152554a1299bb288f83af0`
- Head: `015b119` (`015b119` / `fix: distinguish scanner benchmark failures`)

Owned files committed:

- `scripts/bench_scanner.py`
- `tests/test_bench_scanner.py`
- `docs/performance-methodology.md`
