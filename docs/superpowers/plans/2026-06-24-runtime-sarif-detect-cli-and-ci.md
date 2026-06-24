# Runtime-Annotation SARIF — `detect --sarif` + CI Upload + Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the runtime behavioral detectors (`detect` / `data_exfiltration` et al.) surface in the GitHub Security tab the way the static `audit` already does — by giving `detect` a `--sarif` flag, relativizing runtime SARIF locations, naming the high-value rules, and wiring a CI upload step.

**Architecture:** The runtime SARIF *renderer* already ships — `sarif.render_session_sarif(trace, session_path)` (PR from `2026-06-23-runtime-annotation-sarif.md`), reachable today only via `summarize --sarif`. This plan does **not** re-implement it. It closes the four gaps around it: (1) `detect` — the canonical "run all detectors, exit 1 on findings" gate — has no SARIF output; (2) runtime SARIF location URIs aren't repo-relativized, so the Security tab can't resolve them; (3) the dynamic `pii_*` / `pii_in_result_*` exfil rules and the `premature_call` / `call_before_declaration` context rules have no human rule text (they fall through to a `.capitalize()` slug); (4) CI uploads only `glassport-audit` SARIF, never a runtime category.

**Tech Stack:** Python 3.10+ (`from __future__ import annotations`, match/case), **zero runtime dependencies**, stdlib `unittest`. GitHub Actions + `github/codeql-action/upload-sarif@v3`.

## Global Constraints

- Python **3.10+**; zero runtime dependencies (stdlib only). Verbatim from `CLAUDE.md`.
- Tests drive the **real adapter**: write a tap log to a temp file, lift via `from_mcp_session_file()`, never hand-build a trace. Verbatim project doctrine from `tests/test_session_sarif.py`.
- Run the suite from `glassport/`: `PYTHONPATH=src python -m unittest discover -s tests -t .` (currently **259 passing** — keep it green).
- SARIF must stay **2.1.0** and pass through the shared `sarif._sarif_document(...)` envelope; severity must fold through `sarif._sarif_level(...)` (which already maps the `note` tier).
- Test helpers already exist and MUST be reused: `tests/test_detectors.py::{handshake, call, result, L}`; `tests/test_cli.py::{write_session, run_main}`.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/glassport/tap.py` | CLI dispatch; `summarize`/`_cmd_detect` | Modify: add `--sarif` to `detect`; thread `base` into both SARIF calls |
| `src/glassport/sarif.py` | SARIF rendering | Modify: `render_session_sarif` gains `base`; `_runtime_rule_object` becomes prefix-aware; extend `_RUNTIME_RULE_TEXT` |
| `tests/test_cli.py` | `detect`/`summarize` CLI tests | Modify: add `detect --sarif` cases |
| `tests/test_session_sarif.py` | runtime SARIF unit tests | Modify: base relativization + rule-text cases + CI-fixture smoke test |
| `.github/workflows/ci.yml` | CI jobs | Modify: add runtime-SARIF generate + upload steps |

---

### Task 1: `detect --sarif` flag

Give the runtime gate command a SARIF output mode, mirroring `summarize --sarif`. In SARIF mode it prints the SARIF document and returns **0** (the document *is* the report; gate semantics move to the Security tab), matching `summarize`'s behavior.

**Files:**
- Modify: `src/glassport/tap.py` — `_cmd_detect` (currently ~`475-491`) and the `detect` dispatch branch (currently ~`547-551`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `glassport.adapters.mcp_session.from_mcp_session_file`, `glassport.detectors.annotate`, `glassport.sarif.render_session_sarif(trace, session_path: str) -> str` (existing signature; Task 2 adds an optional `base`).
- Produces: `_cmd_detect(log_path: Path, as_sarif: bool = False) -> int`. CLI: `glassport detect [--sarif] <session.jsonl>`.

- [ ] **Step 1: Write the failing test**

In `tests/test_cli.py`, inside `class TestDetectCommand` (it already imports `handshake, call`):

```python
    def test_sarif_flag_emits_runtime_sarif(self):
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, handshake() +
                              [call(6, 3, "shadow_tool", {})])
            rc, out = run_main(["detect", "--sarif", str(p)])
        self.assertEqual(rc, 0)                      # sarif mode never exit-1
        doc = _json.loads(out)                       # stdout is pure SARIF
        self.assertEqual(doc["version"], "2.1.0")
        rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
        self.assertIn("glassport/fabricated_tool_call", rule_ids)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_cli.TestDetectCommand.test_sarif_flag_emits_runtime_sarif -v`
Expected: FAIL — `detect` treats `--sarif` as a second positional, hits `len(argv) != 2`, prints USAGE, returns 2 (so `rc` is 2, not 0; and `out` is the usage banner, not JSON → `json.loads` raises).

- [ ] **Step 3: Write minimal implementation**

In `src/glassport/tap.py`, change the `_cmd_detect` signature and add a SARIF branch:

```python
def _cmd_detect(log_path: Path, as_sarif: bool = False) -> int:
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import annotate

    trace = from_mcp_session_file(log_path)
    annotations = annotate(trace)
    if as_sarif:
        from glassport.sarif import render_session_sarif
        print(render_session_sarif(trace, str(log_path)))
        return 0
    if not annotations:
        print(f"detect: {log_path.name} — no findings")
        return 0
    print(f"detect: {log_path.name} — {len(annotations)} finding(s)\n")
    for a in sorted(annotations,
                    key=lambda x: (-x.severity, x.metadata.get("seq") or 0)):
        sev_label = {1: "INFO", 2: "WARN", 3: "HIGH"}.get(
            a.severity, str(a.severity))
        print(f"  [{sev_label}] seq={a.metadata.get('seq', '?')} "
              f"{a.subcategory}: {a.explanation}")
    return 1
```

Replace the `detect` dispatch branch (mirror `summarize`'s flag parsing):

```python
    if argv[0] == "detect":
        args = argv[1:]
        as_sarif = "--sarif" in args
        args = [a for a in args if not a.startswith("--")]
        if len(args) != 1:
            print(USAGE)
            return 2
        return _cmd_detect(Path(args[0]), as_sarif=as_sarif)
```

Update the USAGE block's `detect:` line:

```python
  detect:          glassport detect [--sarif] <session.jsonl>
                   (run all behavioral detectors; exit 1 if findings,
                    or emit SARIF 2.1.0 with --sarif)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_cli -v`
Expected: PASS (new test + all existing `TestDetectCommand` / `TestSummarize*` tests).

- [ ] **Step 5: Commit**

```bash
git add src/glassport/tap.py tests/test_cli.py
git commit -m "feat(detect): add --sarif flag emitting runtime SARIF 2.1.0"
```

---

### Task 2: Repo-relative location URIs in runtime SARIF

`render_session_sarif` sets `artifactLocation.uri = session_path` verbatim. An absolute path (the common case — sessions live under `~/.glassport/sessions/`) cannot be resolved by the GitHub Security tab, so the finding renders with no code location. Mirror the static-audit path: add an optional `base` threaded through the existing `sarif._repo_uri(path, base)` helper, and have the CLI pass the path as `base` when it is not absolute (exactly as `audit` does).

**Files:**
- Modify: `src/glassport/sarif.py` — `render_session_sarif` (`180-216`)
- Modify: `src/glassport/tap.py` — `summarize` SARIF call (`~402`) and `_cmd_detect` SARIF call (from Task 1)
- Test: `tests/test_session_sarif.py`

**Interfaces:**
- Consumes: `sarif._repo_uri(path: str, base: str) -> str` (existing, `88-95`: relativizes a path under `base`; absolute paths pass through unchanged).
- Produces: `render_session_sarif(trace, session_path: str = "", base: str = "") -> str`. Backward compatible — existing one-/two-arg callers and tests keep working.

- [ ] **Step 1: Write the failing test**

In `tests/test_session_sarif.py`, add to the runtime-render test class (the one that builds a session and calls `render_session_sarif`; reuse its `handshake`/`call` imports — add them to the existing import from `tests.test_detectors` if not present):

```python
    def test_location_uri_is_prefixed_with_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "session.jsonl")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("\n".join(handshake() +
                                   [call(6, 3, "shadow_tool", {})]) + "\n")
            trace = from_mcp_session_file(log)
            annotate(trace)
            # session_path given as a repo-relative name, base = its dir
            doc = json.loads(sarif.render_session_sarif(
                trace, "session.jsonl", base="dogfood/logs/run1"))
        uri = doc["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "dogfood/logs/run1/session.jsonl")

    def test_absolute_session_path_passes_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "session.jsonl")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("\n".join(handshake() +
                                   [call(6, 3, "shadow_tool", {})]) + "\n")
            trace = from_mcp_session_file(log)
            annotate(trace)
            doc = json.loads(sarif.render_session_sarif(trace, log, base="x/y"))
        uri = doc["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, log.replace("\\", "/"))   # absolute: unchanged
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_session_sarif -v`
Expected: FAIL — `render_session_sarif()` has no `base` parameter → `TypeError: unexpected keyword argument 'base'`.

- [ ] **Step 3: Write minimal implementation**

In `src/glassport/sarif.py`, change the signature and the `artifactLocation.uri`:

```python
def render_session_sarif(trace, session_path: str = "", base: str = "") -> str:
    """Render a session trace's detector annotations as SARIF 2.1.0 (JSON str).

    Results are located into the session `.jsonl` itself: artifactLocation.uri
    is `session_path` (prefixed with `base` so it resolves from the repo root
    in the GitHub Security tab; absolute paths pass through unchanged),
    region.startLine is the annotation's event's line in that log. `seq` rides
    in partialFingerprints for stable identity."""
    seq_line = _seq_to_line(session_path)
    uri = _repo_uri(session_path, base)
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
                    "artifactLocation": {"uri": uri},
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

Note: `_seq_to_line` still reads the **real** `session_path` from disk (the relativized `uri` is for the SARIF location only). Keep them separate.

In `src/glassport/tap.py`, thread `base` from both CLIs. In `summarize` (the `as_sarif` branch):

```python
    if as_sarif:
        from glassport.detectors import annotate
        from glassport.sarif import render_session_sarif
        annotate(trace)            # mutates trace.annotations in place
        base = "" if os.path.isabs(str(log_path)) else str(log_path.parent)
        print(render_session_sarif(trace, log_path.name, base=base))
        return 0
```

In `_cmd_detect`'s SARIF branch:

```python
    if as_sarif:
        from glassport.sarif import render_session_sarif
        base = "" if os.path.isabs(str(log_path)) else str(log_path.parent)
        print(render_session_sarif(trace, log_path.name, base=base))
        return 0
```

Ensure `import os` is present at the top of `tap.py` (it already is — used by the tap proxy).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_session_sarif tests.test_cli -v`
Expected: PASS (new base tests + all existing runtime-SARIF and CLI tests, including `test_summarize_sarif_prints_parseable_sarif`).

- [ ] **Step 5: Commit**

```bash
git add src/glassport/sarif.py src/glassport/tap.py tests/test_session_sarif.py
git commit -m "feat(sarif): repo-relative location URIs for runtime SARIF (Security tab resolvability)"
```

---

### Task 3: Rule text for the exfil + context-violation findings

`_RUNTIME_RULE_TEXT` names only 8 subcategories. The highest-value runtime findings — the `data_exfiltration` family (`pii_<category>`, `pii_in_result_<category>`, built dynamically via f-strings) and the context rules `premature_call` / `call_before_declaration` — fall through to `sub.replace("_", " ").capitalize()` (e.g. `"Pii anthropic key"`). Add the two static keys and make `_runtime_rule_object` prefix-aware so every `pii_*` rule gets a real description without enumerating each PII category.

**Files:**
- Modify: `src/glassport/sarif.py` — `_RUNTIME_RULE_TEXT` (`132-141`) and `_runtime_rule_object` (`167-177`)
- Test: `tests/test_session_sarif.py`

**Interfaces:**
- Consumes: `ann.subcategory: str`, `ann.severity: int`, `ann.kind.value: str`.
- Produces: `_runtime_rule_object(ann) -> dict` (unchanged signature; richer `shortDescription.text`).

- [ ] **Step 1: Write the failing test**

In `tests/test_session_sarif.py`:

```python
    def test_pii_rule_has_descriptive_text(self):
        # an anthropic key in tool-call args -> pii_anthropic_key
        key = "sk-ant-api03-" + "A" * 80
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "s.jsonl")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("\n".join(handshake() +
                                   [call(6, 3, "web_search",
                                         {"query": key})]) + "\n")
            trace = from_mcp_session_file(log)
            annotate(trace)
            doc = json.loads(sarif.render_session_sarif(trace, "s.jsonl"))
        rules = {r["id"]: r["shortDescription"]["text"]
                 for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("glassport/pii_anthropic_key", rules)
        self.assertEqual(rules["glassport/pii_anthropic_key"],
                         "Secret or PII in tool-call arguments")

    def test_premature_call_rule_text(self):
        self.assertEqual(
            sarif._RUNTIME_RULE_TEXT["premature_call"],
            "tools/call issued before notifications/initialized")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_session_sarif.TestRuntimeRules -v` (or the class you added the tests to)
Expected: FAIL — `test_pii_rule_has_descriptive_text` gets `"Pii anthropic key"` (the `.capitalize()` fallback), not the descriptive text; `test_premature_call_rule_text` gets `KeyError`.

- [ ] **Step 3: Write minimal implementation**

In `src/glassport/sarif.py`, extend the dict:

```python
# subcategory -> human short description; fallback humanizes the slug
_RUNTIME_RULE_TEXT = {
    "fabricated_tool_call": "Tool call outside the declared surface",
    "capability_violation": "Server used a capability the client never granted",
    "schema_violation": "Call arguments violate the declared inputSchema",
    "unexpected_egress_host": "Tool call reached an undeclared host",
    "premature_call": "tools/call issued before notifications/initialized",
    "call_before_declaration": "tools/call before any tools/list was seen",
    "gate_blocked": "Gate blocked a call outside the declared surface",
    "gate_injected_response": "Gate synthesized the error reply",
    "gate_skipped": "Gate forwarded a call (no surface declared yet)",
    "detector_error": "A detector raised during analysis",
}
```

Make `_runtime_rule_object` prefix-aware (longest prefix first):

```python
def _runtime_rule_object(ann) -> dict:
    """SARIF reportingDescriptor for one annotation's subcategory.

    The data_exfiltration detector mints subcategories dynamically
    (pii_<category>, pii_in_result_<category>), so match those by prefix
    rather than enumerating every PII category."""
    sub = ann.subcategory or "annotation"
    if sub in _RUNTIME_RULE_TEXT:
        short = _RUNTIME_RULE_TEXT[sub]
    elif sub.startswith("pii_in_result_"):
        short = "Secret or PII leaked back in a tool result"
    elif sub.startswith("pii_"):
        short = "Secret or PII in tool-call arguments"
    else:
        short = sub.replace("_", " ").capitalize()
    return {
        "id": f"glassport/{sub}",
        "name": sub,
        "shortDescription": {"text": short},
        "defaultConfiguration": {"level": _sarif_level(ann.severity)},
        "properties": {"tags": ["glassport", "runtime", ann.kind.value]},
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_session_sarif -v`
Expected: PASS (new rule-text tests + all existing).

- [ ] **Step 5: Commit**

```bash
git add src/glassport/sarif.py tests/test_session_sarif.py
git commit -m "feat(sarif): descriptive rule text for pii_* and context-violation findings"
```

---

### Task 4: CI — generate + upload runtime SARIF to the Security tab

Add CI steps that run `detect --sarif` over a committed session fixture and upload the result under a distinct category, so runtime findings appear in the Security tab alongside the static audit. Use `examples/20260609T183929Z_python3_538.jsonl` — it is committed, always present, and is a deliberately-misbehaving "shady-server" session (produces runtime findings). A `category` distinct from `glassport-audit` keeps the two scales from colliding (per the SARIF doctrine in `CLAUDE.md`).

**Files:**
- Modify: `.github/workflows/ci.yml` — `security-scan` job (after the existing audit→SARIF upload, `~59-69`)
- Test: `tests/test_session_sarif.py` (a smoke test that the fixture renders valid SARIF, so CI can't silently upload garbage)

**Interfaces:**
- Consumes: the installed `glassport` console script; `examples/20260609T183929Z_python3_538.jsonl`.
- Produces: `glassport-runtime.sarif.json` artifact uploaded with `category: glassport-runtime`.

- [ ] **Step 1: Write the failing test**

In `tests/test_session_sarif.py`:

```python
    def test_examples_fixture_renders_valid_runtime_sarif(self):
        # the same fixture CI uploads; guards against a broken upload
        fixture = os.path.join(
            os.path.dirname(__file__), os.pardir,
            "examples", "20260609T183929Z_python3_538.jsonl")
        self.assertTrue(os.path.exists(fixture), "CI SARIF fixture missing")
        trace = from_mcp_session_file(fixture)
        annotate(trace)
        doc = json.loads(sarif.render_session_sarif(
            trace, "examples/20260609T183929Z_python3_538.jsonl"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "glassport")
        # the shady-server fixture must produce at least one runtime finding
        self.assertGreater(len(doc["runs"][0]["results"]), 0)
```

- [ ] **Step 2: Run test to verify it fails (or confirm the premise)**

Run: `cd glassport && PYTHONPATH=src python -m unittest tests.test_session_sarif.TestRuntimeRules.test_examples_fixture_renders_valid_runtime_sarif -v`
Expected: PASS is acceptable here **only if** the fixture already yields findings; if it FAILS on `assertGreater` the fixture is wrong — switch the fixture path to a session known to misbehave (confirm with `PYTHONPATH=src python -m glassport.tap detect examples/20260609T183929Z_python3_538.jsonl` and read its finding count before locking the test). Do not proceed to Step 3 until this test passes against a real committed fixture.

- [ ] **Step 3: Add the CI steps**

In `.github/workflows/ci.yml`, inside the `security-scan` job, **after** the existing `Upload SARIF to GitHub Security` step, add:

```yaml
      - name: Runtime detectors -> SARIF (session fixture)
        # mirror the audit path: never let a non-zero detect exit skip the
        # upload — the Security tab is where runtime findings belong
        run: |
          glassport detect --sarif \
            examples/20260609T183929Z_python3_538.jsonl \
            > glassport-runtime.sarif.json || true
      - name: Upload runtime SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: glassport-runtime.sarif.json
          category: glassport-runtime
```

- [ ] **Step 4: Verify locally (CI cannot be run here)**

Run:
```bash
cd glassport && PYTHONPATH=src python -m glassport.tap detect --sarif \
  examples/20260609T183929Z_python3_538.jsonl | python -m json.tool > /dev/null \
  && echo "valid SARIF"
```
Expected: prints `valid SARIF` (document parses). Then run the full suite:
```bash
cd glassport && PYTHONPATH=src python -m unittest discover -s tests -t .
```
Expected: OK, **≥ 259 + new tests** passing.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml tests/test_session_sarif.py
git commit -m "ci: upload runtime-detector SARIF to the Security tab (glassport-runtime)"
```

---

## Documentation update (fold into Task 4's commit or a final commit)

- [ ] Update the workspace `CLAUDE.md`:
  - In the `## SARIF Export` section, note that runtime SARIF now reaches the Security tab via `detect --sarif` + the `glassport-runtime` CI category, with repo-relative locations.
  - In `## Roadmap`, move **"Runtime-annotation SARIF"** from "not yet shipped" to a "Shipped since" block (the renderer shipped earlier; CLI/CI/coverage shipped here).
- [ ] Update the `detect:` and `summarize:` lines and any SARIF mention in `README.md` if they enumerate CLI flags.

---

## Self-Review

**1. Spec coverage:**
- `detect --sarif` → Task 1. ✓
- Security-tab-resolvable locations → Task 2. ✓
- Rule text for `pii_*` / `premature_call` / `call_before_declaration` → Task 3. ✓
- CI runtime SARIF upload → Task 4. ✓
- Docs (CLAUDE.md roadmap correction, README flags) → Documentation step. ✓
- Renderer itself (`render_session_sarif`, `_seq_to_line`, envelope, `note` tier) → **already shipped**, intentionally untouched. ✓

**2. Placeholder scan:** No TBD / "handle edge cases" / "similar to Task N". Every code step shows full code. The one conditional is Task 4 Step 2 (verify the fixture actually yields findings before locking the assertion) — that is a real verification gate, not a placeholder, and it names the exact command to resolve it.

**3. Type consistency:**
- `render_session_sarif(trace, session_path="", base="")` — defined in Task 2, called with `base=` from `summarize` and `_cmd_detect` in the same task. ✓
- `_cmd_detect(log_path, as_sarif=False)` — defined and called (dispatch branch) in Task 1; its SARIF branch is amended in Task 2 consistently. ✓
- `_runtime_rule_object(ann)` — signature unchanged across Task 3. ✓
- `_repo_uri(path, base)` — consumed in Task 2 exactly as defined at `sarif.py:88`. ✓

**Ordering note:** Task 1 calls `render_session_sarif(trace, str(log_path))` (2-arg, current signature); Task 2 adds the optional `base` (backward compatible) and rewrites both CLI call sites to pass `base` and `log_path.name`. No task references a name a later task renames.

---

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks.
2. **Inline Execution** — execute here with checkpoints.
