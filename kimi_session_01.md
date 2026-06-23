# Glassport Security Test Session — Kimi Session 01

## 1. Methodology

The goal was to thoroughly test the glassport MCP security proxy and identify what is needed to make it production-legitimate. The approach combined:

1. **Baseline establishment** — ran the full existing pytest suite and measured coverage.
2. **Code review** — read every source module (`tap.py`, `detectors.py`, `audit.py`, `server.py`, `report.py`, `watch.py`, `tui.py`, `sarif.py`, `interaction_trace.py`, `adapters/mcp_session.py`).
3. **Gap-driven adversarial testing** — wrote new tests targeting:
   - Adversarial wire inputs (malformed JSONL, invalid UTF-8, oversized payloads, deep nesting)
   - Gate enforcement edge cases (concurrency, empty tool lists, non-string tool names, rapid surface changes)
   - Static audit containment (symlink traversal, permission-denied files)
   - MCP server tool security (path traversal via `serve` tools)
   - Tap fault isolation (unwritable log dirs, broken pipes, logging failures)
   - Report/HTML safety (SVG payloads, `javascript:` URLs, large annotation counts)
   - Detector robustness (non-object schemas, notification vs request semantics)
   - ReDoS resistance of PII regexes
4. **Fix-on-fail** — every failing security test was treated as a finding and fixed in the source.
5. **Regression verification** — existing test suites were re-run after source changes.

## 2. Baseline

- **Existing tests:** 224 passed.
- **Coverage:** 81% overall (`pytest --cov=src/glassport`).
- **Lowest-coverage modules:**
  - `tui.py` — 50% (curses rendering layer is hard to unit-test)
  - `tap.py` — 82% (exception paths, signal forwarding, stderr pump)
  - `server.py` — 78% (CLI entry, exception handlers)
  - `watch.py` — 78% (text-printing CLI)
  - `report.py` — 81% (CLI entry)

## 3. Source Changes Made

### 3.1 Fixed ReDoS vulnerability in PII email regex (`src/glassport/detectors.py`)

**Finding:** The email pattern
```python
r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
```
catastrophically backtracked on long inputs without an `@` sign. A 100 KB string of `x` characters took ~3 seconds; at the 1 MB `MAX_SCAN_BYTES` cap it would hang for minutes. This is a denial-of-service vector because wire payloads are attacker-controlled.

**Fix:** Bounded the quantifiers to realistic email lengths:
```python
r"([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,})"
```

**Verification:** 100 KB now scans in ~0.02 s; existing PII tests still pass.

### 3.2 Fixed audit symlink traversal (`src/glassport/audit.py`)

**Finding:** `_iter_source_files()` yielded symlinked files and then read them via `read_text()`. An attacker who can place a symlink inside an audited tree could make glassport read arbitrary files outside the tree.

**Fix:** Added explicit symlink skipping and made `os.walk` not follow directory symlinks:
```python
for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
    ...
    for name in sorted(filenames):
        p = base / name
        if p.is_symlink():
            continue
        ...
```

### 3.3 Fixed path traversal in `glassport serve` tools (`src/glassport/server.py`)

**Finding:** `analyze_session` and `get_gate_status` opened `args["session_path"]` directly. An MCP client could pass `/etc/passwd` or `../../../.env` and read arbitrary files.

**Fix:** Added `_resolve_session_path(raw, log_dir)` helper that resolves the path and verifies it is inside `log_dir` via `Path.is_relative_to()`. Both tools now reject escaped paths and return an MCP `isError` result.

### 3.4 Fixed tap crash on unwritable log directory (`src/glassport/tap.py`)

**Finding:** `SessionLog.__init__()` calls `path.parent.mkdir()` and `open()` without exception handling. If `log_dir` could not be created (e.g., a file with the same name exists, or permissions are wrong), `run_tap()` crashed before starting the child, violating the documented "logging failure can never alter, delay, or kill a live session" contract.

**Fix:** Wrapped `SessionLog` construction in `try/except OSError`. On failure, logging is disabled, the child still spawns, and the final summary notes that no log was written.

## 4. New Tests Added

File: `tests/test_comprehensive_security.py` (28 tests, all passing after fixes).

Categories:

- **TestAdversarialWireInputs** — missing seq, null frame/raw, invalid UTF-8, oversized arguments, deep nesting.
- **TestDetectorReDoS** — verifies the email scanner is linear-time on hostile input and still catches valid addresses.
- **TestGateEdgeCases** — non-string tool names, empty declared surface, multiple concurrent held calls, latest declaration wins after hold.
- **TestAuditContainment** — file and directory symlinks outside root are skipped; permission-denied files don't crash audit.
- **TestServeToolSecurity** — path traversal rejected for `analyze_session` and `get_gate_status`; valid log-relative paths accepted.
- **TestTapFaultIsolation** — unwritable log dir does not kill the tap; `SessionLog.record` never raises; `pump` survives `BrokenPipeError`.
- **TestReportHtmlSafety** — SVG payloads and `javascript:` values are escaped; large annotation counts render.
- **TestDetectorRobustness** — non-object schemas, secrets in keys, server notifications not treated as capability violations.

## 5. Findings and Suggestions

### 5.1 What is already solid

- **Test discipline:** 224 existing tests with strong adversarial coverage (ReDoS on PEM patterns, zero-width unicode normalization, detector fault isolation).
- **Gate design:** holds pipelined calls, fails open visibly, separates blocked/injected frames in the log.
- **Report safety:** all wire content is HTML-escaped before rendering.
- **Audit philosophy:** capability notes are weight-zero; dangerous variants carry the score.
- **SARIF pipeline:** both static audit and runtime session findings export to SARIF 2.1.0.

### 5.2 What still needs attention to be "legit"

1. **Install / path hygiene for tests**  
   The local source is in `src/`, but `glassport` is also installed in site-packages. Subprocess-based tests must set `PYTHONPATH=src` or they exercise the installed package instead of the working-tree code. Consider adding a `conftest.py` that ensures `src` is first on `sys.path`, or switch to an editable install in CI.

2. **TUI and CLI coverage**  
   `tui.py` is 50% covered and `tap.py`/`server.py`/`watch.py` have untested CLI/signal paths. These are lower-risk but should be backfilled for a production claim.

3. **Audit `audit_server` path traversal is intentional but unbounded**  
   The `audit_server` tool is meant to audit arbitrary server source paths, so path traversal there is a feature, not a bug. Document this clearly in the tool description and consider requiring an explicit allow-list or confirmation if glassport `serve` is exposed to untrusted clients.

4. **GitLab / pre-commit distribution**  
   For the next step (GitLab CI + pre-commit), recommend **Option A**: gate + SARIF artifact only. Rationale:
   - `glassport audit` already exits 1 on critical/high findings.
   - SARIF is already a supported output.
   - GitLab can ingest SARIF as a SAST artifact in some tiers.
   - No new package code, matching the roadmap's "distribution-only" scope.
   - Native `gl-sast-report.json` (Option B) should wait until a user explicitly needs the MR security widget.

5. **Signal-handler isolation in tests**  
   `run_tap` installs `signal.signal` handlers, which interferes with pytest when called in-process. Keep subprocess-based tests for any `run_tap` invocation.

6. **ReDoS audit of remaining patterns**  
   The email regex was the only catastrophic one found, but a periodic fuzz/benchmark of all PII patterns against 1 MB of adversarial text should be part of CI.

7. **Schema for session log**  
   Consider adding a lightweight JSON schema or at least property-based tests for the tap log format. The adapter is permissive, which is good for robustness, but a schema would catch accidental format drift.

## 6. Commands Used

```bash
# baseline
python -m pytest
python -m pytest --cov=src/glassport --cov-report=term-missing

# new security tests
python -m pytest tests/test_comprehensive_security.py -v

# targeted regression after changes
python -m pytest tests/test_detectors.py tests/test_hardening.py
python -m pytest tests/test_audit.py tests/test_server.py tests/test_gate.py
```

## 7. Summary

Glassport is already a well-architected, well-tested security tool. The four fixes above remove real, exploitable weaknesses (DoS, directory traversal, path traversal, availability failure). With the new test file, the project now has explicit adversarial coverage for the most likely attack surfaces. The next legitimate step is distribution artifacts (pre-commit + GitLab CI) using the existing SARIF/exit-code gate, not new renderer code.
