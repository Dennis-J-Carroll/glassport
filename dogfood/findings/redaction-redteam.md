# Redaction Red-Team Grill Findings

Branch: `fix/sarif-provenance-redaction` (PR #63)  
Grill: `PYTHONPATH=src python dogfood/eval_redaction_redteam.py`  
Run date: 2026-07-12

## Executive summary

The SARIF provenance redaction fix is **solid against the requested attack surface**: 28 fix-specific grill rows pass (plain-secret absent from `message.text`, `properties.package`, and the normalized whole SARIF artifact). No obfuscation, boundary-split, validation-bypass, scan-failure, or structural-consistency escape was found in `sarif.render_sarif`.

Two **adjacent** leaks were found outside SARIF: the `--json` and text audit renderers still emit provenance findings verbatim and must be hardened in a follow-up PR.

## Results table

| ID | Hypothesis | Verdict | Notes |
|---|---|---|---|
| P-lead | Unredacted hostile `pf.package` in SARIF | **FIXED — green lock** | strict-redact → neutralize → clamp on `package`/`detail` |
| P-lead sweep | `pf.ecosystem` reaches SARIF unscrubbed | **FIXED — green lock** | validated `∈ {npm, pypi}` → `unknown` sentinel |
| P-lead sweep | `pf.detail` reaches SARIF unscrubbed | **FIXED — green lock** | `_sanitize_display` |
| P-lead sweep | `pf.rule` reaches SARIF rules table / ruleId | **FIXED — green lock** | validated against fixed catalog → `prov-unknown` |
| FIX-1a | ZWJ-obfuscated secret in `pf.package` | green lock | redaction normalizes before scanning |
| FIX-1b | Fullwidth-obfuscated secret in `pf.package` | green lock | NFKC folded, redacted |
| FIX-1c | Cyrillic-homoglyph secret in `pf.package` | green lock | confusable map folded, redacted |
| FIX-1d | Bidi-override-wrapped secret in `pf.package` | green lock | invisibles stripped, redacted |
| FIX-1e | Combining-mark secret in `pf.package` | green lock | NFKC decomposes, redacted |
| FIX-1f | Latin small-capital-A obfuscated secret | green lock (plain absent) | **obfuscated glyph survives** — see observation below |
| FIX-2 | Obfuscated secret in `pf.manifest` URI | green lock | URI redaction is obfuscation-proof |
| FIX-3 | Secret split across `package`/`detail` boundary | green lock | hardcoded separators break pattern contiguity; composed-msg backstop clean |
| FIX-4a | Secret-shaped unknown `pf.rule` | green lock | collapses to `provenance/prov-unknown`; rules table entry exists |
| FIX-4b | Secret-shaped unknown `pf.ecosystem` | green lock | collapses to `unknown` |
| FIX-5 | `redact_secrets_strict` raises during render | green lock | fail-closed `_WITHHELD`; `render_sarif` does not crash |
| FIX-6 | SARIF structural consistency with mixed/unknown provenance | green lock | valid 2.1.0, no duplicate rules, every `ruleId` resolves |
| ADJ-1 | `--json` audit output provenance leak | **CONFIRMED** | `render_json` emits `vars(pf)` verbatim |
| ADJ-2 | Text audit output provenance leak | **CONFIRMED** | `render_text` prints `pf.package`/`detail` verbatim |

## Fix-specific attacks (all green)

### Repro harness

All FIX rows use the real shipped functions:

```python
from glassport.audit import Report
from glassport.provenance import ProvenanceFinding
from glassport import sarif, detectors

def _prov_doc(package="safe-pkg", detail="detail", manifest="package.json",
              rule="prov-not-in-registry", ecosystem="npm"):
    pf = ProvenanceFinding(rule=rule, severity="high", ecosystem=ecosystem,
                           package=package, manifest=manifest, detail=detail)
    return sarif.render_sarif(
        Report(profile={"name": "demo"}, findings=[], deductions=[],
               score=50, grade="F", provenance=[pf]))

secret = "sk-ant-api03-" + "A" * 40 + "1234567890"
```

### 1. Obfuscation

| Variant | Input package | Plain secret in normalized SARIF? |
|---|---|---|
| ZWJ | `"sk-ant-api03-\u200d" + "A"*40 + "1234567890"` | No |
| Fullwidth | `secret.translate({ord(c): ord(c)+0xFEE0 ...})` | No |
| Cyrillic | `secret.replace("a", "а").replace("A", "А")` | No |
| Bidi override | `"\u202e" + secret + "\u202c"` | No |
| Combining marks | underline each char | No |
| Latin small-capital A | `secret.replace("A", "\u1D00")` | **No** (plain absent) |

### 2. Manifest URI

```python
doc = _prov_doc(manifest=f"src/{secret.replace('a', 'а')}/package.json")
assert secret not in detectors._normalize_for_scan(doc)
```

### 3. Composed-message boundary split

```python
pkg = secret[:23]     # "sk-ant-api03-" + 10 A's — too short to match alone
detail = secret[23:]  # remaining A's + digits
msg = json.loads(_prov_doc(package=pkg, detail=detail))["runs"][0]["results"][0]["message"]["text"]
assert secret not in msg
assert secret not in detectors._normalize_for_scan(_prov_doc(package=pkg, detail=detail))
```

### 4. Unknown rule / ecosystem

```python
d = json.loads(_prov_doc(rule=secret, ecosystem=secret))
res = d["runs"][0]["results"][0]
rules = {r["id"]: r for r in d["runs"][0]["tool"]["driver"]["rules"]}
assert res["ruleId"] == "provenance/prov-unknown"
assert res["ruleId"] in rules
assert res["properties"]["ecosystem"] == "unknown"
assert secret not in json.dumps(d)
```

### 5. Scan failure / totality

```python
from unittest import mock
pf = ProvenanceFinding("prov-not-in-registry", "high", "npm", secret,
                       "package.json", "detail")
report = Report(profile={"name": "demo"}, findings=[], deductions=[],
                score=50, grade="F", provenance=[pf])
with mock.patch.object(detectors, "_scan_pii", side_effect=RuntimeError("boom")):
    doc = sarif.render_sarif(report)   # does not raise
assert secret not in doc
assert detectors._WITHHELD in doc
```

### 6. Structural consistency

Mixed provenance findings (known, duplicate known, unknown rule, unknown ecosystem) produce a valid SARIF 2.1.0 document, no duplicate rule ids, and every `result.ruleId` resolves to a `driver.rules` entry.

## Observation: Latin small-capital-A obfuscation

`secret.replace("A", "\u1D00")` is **not** detected by the scanner (NFKC does not fold U+1D00 to A; it is not in the confusables table). The SARIF fix therefore cannot remove it, so the obfuscated credential shape survives in `message.text` and `properties.package`. The **plain** secret is absent from the normalized artifact, so by the project's oracle this is not a confirmed leak. It is, however, a readable deception glyph that a human or downstream model could interpret as the real credential. Closing it requires expanding the detector's confusable/NFKC coverage, which is a detector-layer change, not a SARIF fix issue.

## Adjacent findings (outside SARIF / PR #63)

### ADJ-1: `--json` audit output leaks provenance secrets

`src/glassport/audit.py:614` does:

```python
obj["provenance"] = [vars(pf) for pf in report.provenance]
```

This emits every `ProvenanceFinding` field verbatim, including attacker-controlled `package` and `detail`.

```python
from glassport.audit import render_json
secret = "sk-ant-api03-" + "A" * 40 + "1234567890"
pf = ProvenanceFinding("prov-not-in-registry", "high", "npm", secret,
                       "package.json", "detail")
report = Report(profile={"name": "demo"}, findings=[], deductions=[],
                score=50, grade="F", provenance=[pf])
assert secret in detectors._normalize_for_scan(render_json(report))  # RED
```

### ADJ-2: Text audit output leaks provenance secrets

`src/glassport/audit.py:593-595` prints `pf.package` and `pf.detail` without redaction.

```python
from glassport.audit import render_text
# ... same pf ...
assert secret in detectors._normalize_for_scan(render_text(report))  # RED
```

### Recommended follow-up

Apply the same `_sanitize_display` / closed-set validation treatment to `render_json` and `render_text` provenance output, or route them through the same sanitization layer used for SARIF. Add regression locks in `tests/test_audit.py` mirroring the SARIF provenance redaction tests.

## Green locks (surface hit, no plain-secret escape found)

- P1/P2/P4/P5/P6/P7 remain green locks from the original grill.
- All SARIF fix-specific obfuscation, boundary, validation, fail-closed, and structural rows are green locks.

These are tested-surface statements, not proofs of universal safety.
