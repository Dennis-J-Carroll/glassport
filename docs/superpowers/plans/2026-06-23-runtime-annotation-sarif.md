# Runtime-annotation SARIF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export detector `Annotation`s over a session trace to SARIF 2.1.0, located into the session `.jsonl` log, via `glassport summarize <session> --sarif`.

**Architecture:** Add a second SARIF renderer (`render_session_sarif`) beside the existing static-audit `render_sarif`, both sharing a factored-out document envelope (`_sarif_document`) and the existing `_sarif_level` severity vocabulary. Runtime results get a physical location by mapping each annotation's event `seq` to its line number in the `.jsonl` (read from disk in the renderer — no adapter change).

**Tech Stack:** Python 3.10+ stdlib only (`json`, `pathlib`, `unittest`). Zero runtime dependencies.

## Global Constraints

- **Zero runtime dependencies** — stdlib only.
- **Python 3.10+** — `from __future__ import annotations` at top of every module.
- **Test doctrine:** drive the REAL adapter (`from_mcp_session` / `from_mcp_session_file`) — never hand-build `InteractionTrace`/`Annotation` objects.
- **SARIF envelope values (verbatim):** `$schema = "https://json.schemastore.org/sarif-2.1.0.json"`, `version = "2.1.0"`, driver `name = "glassport"`, `DRIVER_VERSION = "0.2.0"` (already in `sarif.py`).
- **Severity mapping is fixed** — reuse `_sarif_level` (int `3/2/1` → `error/warning/note`; gate INFO is severity `1` → `note`). Do not add a new severity scale.
- **Run the suite** from `glassport/`: `PYTHONPATH=src python3 -m pytest tests/ -q` (or `python3 -m unittest discover -s tests -t .`).

---

## File Structure

- **Modify** `src/glassport/sarif.py` — extract `_sarif_document`; refactor `render_sarif` to call it; add `_RUNTIME_RULE_TEXT`, `_runtime_rule_object`, `_seq_to_line`, `render_session_sarif`.
- **Modify** `src/glassport/tap.py` — `summarize()` gains `as_sarif` param; `summarize` CLI dispatch parses `--sarif`.
- **Create** `tests/test_session_sarif.py` — runtime SARIF tests via the real adapter.

---

### Task 1: Extract shared SARIF envelope

Refactor only — `render_sarif`'s output must not change. Pull the document shell into `_sarif_document(rules, results, props)` so the runtime renderer can reuse it.

**Files:**
- Modify: `src/glassport/sarif.py` (the `render_sarif` body, ~lines 104-120)
- Test: `tests/test_session_sarif.py` (new)

**Interfaces:**
- Produces: `_sarif_document(rules: list[dict], results: list[dict], props: dict | None = None) -> str` — returns SARIF 2.1.0 JSON (indent=2, ensure_ascii=False).

- [ ] **Step 1: Write the failing test**

Create `tests/test_session_sarif.py`:

```python
"""
Tests for sarif.render_session_sarif() — SARIF 2.1.0 export of runtime
detector annotations, located into the session .jsonl log. Pure stdlib.

Per project doctrine these drive the REAL adapter: a tap log is written
to a temp file, lifted through from_mcp_session_file(), annotated, and
rendered — never a hand-built trace.
"""
import json
import os
import tempfile
import unittest

from glassport import sarif


class TestSharedEnvelope(unittest.TestCase):
    def test_sarif_document_minimal_envelope(self):
        out = json.loads(sarif._sarif_document([], [], {"k": "v"}))
        self.assertEqual(out["version"], "2.1.0")
        self.assertIn("$schema", out)
        self.assertEqual(len(out["runs"]), 1)
        self.assertEqual(out["runs"][0]["tool"]["driver"]["name"], "glassport")
        self.assertEqual(out["runs"][0]["results"], [])
        self.assertEqual(out["runs"][0]["properties"], {"k": "v"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_session_sarif.py::TestSharedEnvelope -q`
Expected: FAIL — `AttributeError: module 'glassport.sarif' has no attribute '_sarif_document'`

- [ ] **Step 3: Add `_sarif_document` and refactor `render_sarif`**

In `src/glassport/sarif.py`, add this helper above `render_sarif`:

```python
def _sarif_document(rules: list, results: list, props: dict | None = None) -> str:
    """Wrap rules + results in the SARIF 2.1.0 run envelope. Shared by the
    static-audit and runtime-annotation renderers."""
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "glassport",
                "version": DRIVER_VERSION,
                "semanticVersion": DRIVER_VERSION,
                "informationUri": _INFO_URI,
                "rules": rules,
            }},
            "results": results,
            "columnKind": "utf16CodeUnits",
            "properties": props or {},
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)
```

Then replace the `doc = {...}` / `return json.dumps(...)` tail of `render_sarif` (currently ~lines 104-120) with:

```python
    return _sarif_document(list(rules.values()), results,
                           {"score": report.score, "grade": report.grade})
```

- [ ] **Step 4: Run tests to verify pass (new + existing unchanged)**

Run: `PYTHONPATH=src python3 -m pytest tests/test_session_sarif.py tests/test_sarif.py -q`
Expected: PASS — the new envelope test passes AND all existing `test_sarif.py` tests still pass (proves the refactor changed nothing observable).

- [ ] **Step 5: Commit**

```bash
git add src/glassport/sarif.py tests/test_session_sarif.py
git commit -m "refactor: extract shared _sarif_document envelope in sarif.py"
```

---

### Task 2: `render_session_sarif` — annotations → located SARIF results

Build the runtime renderer: one rule per distinct `subcategory`, one result per annotation, severity via `_sarif_level`, physical location into the `.jsonl` via a `seq → line` map, `seq` in `partialFingerprints`. Gate INFO records included as `note`.

**Files:**
- Modify: `src/glassport/sarif.py`
- Test: `tests/test_session_sarif.py`

**Interfaces:**
- Consumes: `_sarif_document` (Task 1), `_sarif_level` (existing).
- Produces:
  - `_seq_to_line(session_path: str) -> dict` — maps each log entry's `seq` to its 1-based line number; `{}` when path is empty/unreadable.
  - `_runtime_rule_object(annotation) -> dict` — a SARIF reportingDescriptor for one annotation's subcategory.
  - `render_session_sarif(trace, session_path: str = "") -> str` — SARIF JSON over `trace.annotations`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_session_sarif.py`:

```python
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.detectors import annotate


def L(seq, direction, frame, gate=None):
    rec = {"schema_version": "0.1", "seq": seq, "ts": f"t{seq}",
           "dir": direction, "frame": frame, "raw": None}
    if gate is not None:
        rec["gate"] = gate
    return json.dumps(rec)


def handshake(tools):
    """initialize -> result -> initialized -> tools/list -> result."""
    return [
        L(1, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26",
                                "capabilities": {},
                                "clientInfo": {"name": "c"}}}),
        L(2, "s2c", {"jsonrpc": "2.0", "id": 1,
                     "result": {"protocolVersion": "2025-03-26",
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "s"}}}),
        L(3, "c2s", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
        L(4, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        L(5, "s2c", {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}),
    ]


def render_lines(lines):
    """Write lines to a temp .jsonl, lift via the real adapter, annotate,
    and render. Returns (parsed_sarif_dict, session_path)."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    trace = from_mcp_session_file(path)
    trace.annotations.extend(annotate(trace))
    doc = json.loads(sarif.render_session_sarif(trace, path))
    return doc, path


class TestRenderSessionSarif(unittest.TestCase):
    def _fabricated(self):
        # web_search declared; calling shadow_tool is a fabricated call (sev 3)
        lines = handshake([{"name": "web_search"}]) + [
            L(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "shadow_tool", "arguments": {}}}),
        ]
        return render_lines(lines)

    def test_valid_envelope(self):
        doc, _ = self._fabricated()
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "glassport")

    def test_fabricated_call_is_error_level(self):
        doc, _ = self._fabricated()
        res = [r for r in doc["runs"][0]["results"]
               if r["ruleId"] == "glassport/fabricated_tool_call"]
        self.assertTrue(res)
        self.assertEqual(res[0]["level"], "error")          # sev 3 -> error

    def test_result_locates_at_real_jsonl_line(self):
        doc, path = self._fabricated()
        res = [r for r in doc["runs"][0]["results"]
               if r["ruleId"] == "glassport/fabricated_tool_call"][0]
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], path)
        # the shadow_tool call is the 6th line written
        self.assertEqual(loc["region"]["startLine"], 6)

    def test_seq_in_partial_fingerprints(self):
        doc, _ = self._fabricated()
        res = [r for r in doc["runs"][0]["results"]
               if r["ruleId"] == "glassport/fabricated_tool_call"][0]
        self.assertIn("glassportSeq", res["partialFingerprints"])
        self.assertTrue(res["partialFingerprints"]["glassportSeq"]
                        .endswith(":6"))

    def test_distinct_subcategory_yields_one_rule(self):
        doc, _ = self._fabricated()
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertIn("glassport/fabricated_tool_call", rule_ids)

    def test_gate_info_included_as_note(self):
        # a blocked tools/call carries a gate marker; gate_actions emits a
        # gate_blocked INFO annotation (severity 1 -> note), not dropped
        lines = handshake([{"name": "web_search"}]) + [
            L(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "shadow_tool", "arguments": {}}},
              gate={"action": "blocked", "tool": "shadow_tool"}),
        ]
        doc, _ = render_lines(lines)
        gate = [r for r in doc["runs"][0]["results"]
                if r["ruleId"] == "glassport/gate_blocked"]
        self.assertTrue(gate, "gate_blocked INFO record must be emitted")
        self.assertEqual(gate[0]["level"], "note")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/test_session_sarif.py::TestRenderSessionSarif -q`
Expected: FAIL — `AttributeError: module 'glassport.sarif' has no attribute 'render_session_sarif'`

- [ ] **Step 3: Implement the runtime renderer**

Add to `src/glassport/sarif.py`. At the top, ensure `from pathlib import Path` is imported (add if missing). Then:

```python
# subcategory -> human short description; fallback humanizes the slug
_RUNTIME_RULE_TEXT = {
    "fabricated_tool_call": "Tool call outside the declared surface",
    "capability_violation": "Server used a capability the client never granted",
    "schema_violation": "Call arguments violate the declared inputSchema",
    "unexpected_egress_host": "Tool call reached an undeclared host",
    "gate_blocked": "Gate blocked a call outside the declared surface",
    "gate_injected_response": "Gate synthesized the error reply",
    "gate_skipped": "Gate forwarded a call (no surface declared yet)",
    "detector_error": "A detector raised during analysis",
}


def _seq_to_line(session_path: str) -> dict:
    """Map each log entry's `seq` to its 1-based line number in the file.
    Empty/unreadable path -> {}. Lines without a seq are skipped."""
    out: dict = {}
    if not session_path:
        return out
    try:
        with open(session_path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    seq = json.loads(raw).get("seq")
                except json.JSONDecodeError:
                    continue
                if seq is not None:
                    out[seq] = lineno
    except OSError:
        pass
    return out


def _runtime_rule_object(ann) -> dict:
    """SARIF reportingDescriptor for one annotation's subcategory."""
    sub = ann.subcategory or "annotation"
    short = _RUNTIME_RULE_TEXT.get(sub, sub.replace("_", " ").capitalize())
    return {
        "id": f"glassport/{sub}",
        "name": sub,
        "shortDescription": {"text": short},
        "defaultConfiguration": {"level": _sarif_level(ann.severity)},
        "properties": {"tags": ["glassport", "runtime", ann.kind.value]},
    }


def render_session_sarif(trace, session_path: str = "") -> str:
    """Render a session trace's detector annotations as SARIF 2.1.0 (JSON str).

    Results are located into the session `.jsonl` itself: artifactLocation.uri
    is `session_path`, region.startLine is the annotation's event's line in
    that log. `seq` rides in partialFingerprints for stable identity."""
    seq_line = _seq_to_line(session_path)
    event_by_id = {e.id: e for e in trace.events}
    rules: dict = {}
    results: list = []

    for a in trace.annotations:
        rule_id = f"glassport/{a.subcategory or 'annotation'}"
        if rule_id not in rules:
            rules[rule_id] = _runtime_rule_object(a)
        ev = event_by_id.get(a.event_id)
        seq = ev.metadata.get("seq") if ev else None
        line = seq_line.get(seq, 1)
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(a.severity),
            "message": {"text": a.explanation or a.subcategory or rule_id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": session_path},
                    "region": {"startLine": max(1, int(line))},
                },
            }],
            "partialFingerprints": {
                "glassportSeq": f"{a.subcategory}:{seq}"},
            "properties": {"severity": a.severity, "kind": a.kind.value,
                           "subcategory": a.subcategory},
        })

    props = {"session": Path(session_path).name if session_path else "",
             "annotation_count": len(trace.annotations)}
    return _sarif_document(list(rules.values()), results, props)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest tests/test_session_sarif.py -q`
Expected: PASS — all `TestRenderSessionSarif` tests green.

- [ ] **Step 5: Commit**

```bash
git add src/glassport/sarif.py tests/test_session_sarif.py
git commit -m "feat: render_session_sarif — runtime annotations to located SARIF"
```

---

### Task 3: CLI — `glassport summarize <session> --sarif`

Wire the renderer to the CLI. `summarize`'s `--sarif` path runs the full `annotate()` (the human path only runs `context_violations`), populates `trace.annotations`, and prints the SARIF.

**Files:**
- Modify: `src/glassport/tap.py` — `summarize()` signature/early-return and the `summarize` dispatch in `main()`.
- Test: `tests/test_session_sarif.py`

**Interfaces:**
- Consumes: `render_session_sarif` (Task 2), `annotate` (existing), `from_mcp_session_file` (existing).
- Produces: `summarize(log_path, as_json=False, as_sarif=False) -> int`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_session_sarif.py`:

```python
import io
import contextlib

from glassport import tap


class TestSummarizeSarifCLI(unittest.TestCase):
    def test_summarize_sarif_prints_parseable_sarif(self):
        lines = handshake([{"name": "web_search"}]) + [
            L(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "shadow_tool", "arguments": {}}}),
        ]
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = tap.main(["summarize", "--sarif", path])
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(any(r["ruleId"] == "glassport/fabricated_tool_call"
                            for r in doc["runs"][0]["results"]))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_session_sarif.py::TestSummarizeSarifCLI -q`
Expected: FAIL — `--sarif` is treated as the path / `summarize()` rejects the flag (non-zero rc or JSONDecodeError).

- [ ] **Step 3: Add the `as_sarif` path to `summarize()`**

In `src/glassport/tap.py`, change the `summarize` signature and add an early SARIF branch immediately after the trace is built. Current signature:

```python
def summarize(log_path: Path, as_json: bool = False) -> int:
```

becomes:

```python
def summarize(log_path: Path, as_json: bool = False, as_sarif: bool = False) -> int:
```

Then, right after `trace = from_mcp_session_file(log_path)` near the top of the body, insert:

```python
    if as_sarif:
        from glassport.detectors import annotate
        from glassport.sarif import render_session_sarif
        trace.annotations.extend(annotate(trace))
        print(render_session_sarif(trace, str(log_path)))
        return 0
```

- [ ] **Step 4: Parse `--sarif` in the dispatch**

In `main()`, find the `summarize` dispatch block (begins `if argv[0] == "summarize":`). Replace it with:

```python
    if argv[0] == "summarize":
        args = argv[1:]
        as_json = "--json" in args
        as_sarif = "--sarif" in args
        args = [a for a in args if not a.startswith("--")]
        if len(args) != 1:
            print("usage: glassport summarize [--json|--sarif] <session.jsonl>",
                  file=sys.stderr)
            return 2
        return summarize(Path(args[0]), as_json=as_json, as_sarif=as_sarif)
```

- [ ] **Step 5: Update the usage banner**

In `main()`'s help text, change the summarize line to:

```
  summarize:       glassport summarize [--json|--sarif] <session.jsonl>
```

- [ ] **Step 6: Run tests to verify pass**

Run: `PYTHONPATH=src python3 -m pytest tests/test_session_sarif.py -q`
Expected: PASS — including `TestSummarizeSarifCLI`.

- [ ] **Step 7: Full suite + smoke test**

Run: `PYTHONPATH=src python3 -m pytest tests/ -q`
Expected: PASS — all tests (the existing 215 + the new ones).

Smoke (uses a real session log if one exists):
Run: `PYTHONPATH=src python3 -m glassport.tap summarize --sarif "$(ls ~/.glassport/sessions/*.jsonl | head -1)" | python3 -c "import sys,json; print('ok', json.load(sys.stdin)['version'])"`
Expected: `ok 2.1.0`

- [ ] **Step 8: Commit**

```bash
git add src/glassport/tap.py tests/test_session_sarif.py
git commit -m "feat: glassport summarize --sarif emits runtime-annotation SARIF"
```

---

## Documentation follow-up (after the three tasks)

- [ ] Update `README.md` Static-audit/SARIF area: note `summarize --sarif` emits runtime-annotation SARIF located into the session log. Re-run the anchor/link check before any release.
- [ ] Move roadmap item #1 in `STATUS.md` from Tier 3 to Tier 1, and strike it from the README Roadmap.
- [ ] These are doc-only; bundle into the feature PR.

---

## Self-Review

**Spec coverage:**
- Generic-SARIF consumer → no Security-tab coupling: ✅ (renderer emits a plain SARIF doc; CLI prints it).
- Physical location into `.jsonl` (uri=path, startLine=event line, seq fingerprint): ✅ Task 2 (`_seq_to_line`, location block, `glassportSeq`).
- Two renderers, shared core: ✅ Task 1 (`_sarif_document`) + Task 2.
- Rule synthesis per subcategory with fallback: ✅ Task 2 (`_RUNTIME_RULE_TEXT`, `_runtime_rule_object`).
- Severity via existing `_sarif_level`: ✅ (reused, no new scale).
- Gate INFO included as note: ✅ Task 2 `test_gate_info_included_as_note`.
- CLI `summarize --sarif`: ✅ Task 3.
- Testing via real adapter: ✅ all tests write a temp `.jsonl` and lift through `from_mcp_session_file`.

**Refinement flagged (vs. spec):** the spec proposed stamping `event.metadata["line"]` in the adapter. This plan instead maps `seq → line` in the renderer (`_seq_to_line`), reading the log the renderer already has the path to. Same observable output (`region.startLine` = the real `.jsonl` line), zero edits to the multi-branch adapter, lower risk. Surface to the user if adapter-side stamping is preferred.

**Placeholder scan:** none — every code step shows complete code.

**Type consistency:** `_sarif_document(rules, results, props)`, `render_session_sarif(trace, session_path)`, `summarize(log_path, as_json, as_sarif)`, `_seq_to_line`, `_runtime_rule_object` — names match across all tasks and the tests that call them.
