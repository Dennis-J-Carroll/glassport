# Redaction Red-Team Grill Findings

Branch: `fix/sarif-provenance-redaction` (PR #63), commit `ff7d818`  
Grill: `PYTHONPATH=src python dogfood/eval_redaction_redteam.py`  
Run date: 2026-07-12

## Executive summary

PR #63's centralized `detectors.redact_display` is **correctly wired** across all three renderers and holds against plain-secret leaks, scan-failure totality, boundary sizes, malformed string rule/ecosystem values, and structural integrity. The SARIF fix from earlier passes remains solid.

Pass 3 found **eight RED cases** using an independent reconstruction oracle:

1. `pf.severity` is emitted **raw** in text and JSON outputs (defensive-coverage gap; not attacker-reachable in current `evaluate()` code).
2. **Combining-mark obfuscation** (`s̲k̲-̲a̲n̲t̲...`) in `package`/`detail` survives in all rendered artifacts; independent oracle reconstructs the credential.
3. **Latin small-capital-A obfuscation** (`ᴀ`) in `package`/`detail` survives in all rendered artifacts; independent oracle reconstructs.
4. A credential **split across `package` + `detail`** reconstructs in text and SARIF when separators are collapsed.
5. A credential **split across `ecosystem` + `package`** reconstructs in text output.
6. **Non-string `pf.rule`** (e.g., a list) crashes all three renderers — totality violation.
7. **Non-string `pf.ecosystem`** (e.g., a list) crashes all three renderers — totality violation.

Findings 2–5 are **detector-layer normalization gaps** (issue #64 family) or theoretical split-field reconstruction that requires controlling fields currently fixed by `evaluate()`. They are reported with repros so the maintainer can decide scope.

## Results table

| ID | Hypothesis | Verdict | Notes |
|---|---|---|---|
| P-lead | Unredacted hostile `pf.package` in SARIF | **FIXED — green lock** | strict-redact → neutralize → clamp on `package`/`detail` |
| P-lead sweep | `pf.ecosystem` reaches SARIF unscrubbed | **FIXED — green lock** | validated `∈ {npm, pypi}` → `unknown` sentinel |
| P-lead sweep | `pf.detail` reaches SARIF unscrubbed | **FIXED — green lock** | `_sanitize_display` |
| P-lead sweep | `pf.rule` reaches SARIF rules table / ruleId | **FIXED — green lock** | validated against fixed catalog → `prov-unknown` |
| ADJ-1 | `--json` audit output provenance leak | **FIXED — green lock** | `render_json` now uses `redact_display` |
| ADJ-2 | Text audit output provenance leak | **FIXED — green lock** | `render_text` now uses `redact_display` |
| **PASS3-1** | `pf.severity` raw in text/JSON | **RED** | emitted verbatim; defensive gap |
| **PASS3-2a** | Combining-mark obfuscation in `package`/`detail` | **RED** | detector normalization gap; issue #64 family |
| **PASS3-2b** | Small-capital-A obfuscation in `package`/`detail` | **RED** | issue #64 evidence |
| PASS3-2c | ZWJ/fullwidth/Cyrillic/bidi obfuscation | green lock | production oracle catches |
| **PASS3-3a** | Split secret `package` + `detail` | **RED** | reconstructs in text/SARIF (theoretical) |
| **PASS3-3b** | Split secret `ecosystem` + `package` | **RED** | reconstructs in text (theoretical) |
| PASS3-3c | Split secret `rule` + `detail` | green lock | output format inserts `[npm:safe]` between them |
| PASS3-3d | Split secret across JSON punctuation | green lock | punctuation breaks alphanumeric core |
| PASS3-4 | Scan-failure totality per renderer | green lock | `_WITHHELD`, no crash |
| PASS3-5 | Boundary sizes (scan/clamp caps) | green lock | no >cap secret survives |
| **PASS3-6a** | Non-string `pf.rule` | **RED** | crashes all renderers |
| **PASS3-6b** | Non-string `pf.ecosystem` | **RED** | crashes all renderers |
| PASS3-6c | `None`/empty/secret-shaped string rule/ecosystem | green lock | collapse to safe sentinels |
| PASS3-7 | Structural integrity + benign invariance | green lock | valid SARIF, JSON schema unchanged, ordinary npm output preserved |
| PASS3-8 | Benign npm/PyPI output byte-identical | green lock | `left-pad` passes through unchanged |
| PASS3-9 | Bypass hunt for `pf.*` rendering | green lock | only known-safe accesses in `sarif.py` / `audit.py` |

## Independent reconstruction oracle

Implemented in `dogfood/eval_redaction_redteam.py` for Pass 3. It deliberately does **not** call glassport's `_normalize_for_scan`:

```python
def _independent_reconstruct(text: str, secret: str) -> bool:
    # 1. strip Cf/Cc/Mn/Me (format, control, combining marks)
    cleaned = "".join(ch for ch in text
                      if unicodedata.category(ch) not in _INDEP_INVISIBLE_CATS)
    # 2. NFKD then NFKC
    norm = unicodedata.normalize("NFKC", unicodedata.normalize("NFKD", cleaned))
    # 3. fold Cyrillic/Greek/small-capital look-alikes
    folded = norm.translate(_INDEP_TABLE)
    # 4a. exact search
    if secret in folded:
        return True
    # 4b. loose alphanumeric-core search (catches separator-collapsed splits)
    loose_text = re.sub(r"[^A-Za-z0-9]", "", folded)
    loose_secret = re.sub(r"[^A-Za-z0-9]", "", secret)
    return loose_secret in loose_text
```

## Pass 3 RED findings

### PASS3-1: `pf.severity` emitted raw in text and JSON

**Source:** `src/glassport/audit.py:605` and `:630`

```python
out.append(f"  [{pf.severity}] {rule}{where}")          # text
"severity": pf.severity,                                # json
```

`severity` is the only provenance field that bypasses `redact_display` in text/JSON. SARIF is safe because `_sarif_level(pf.severity)` maps to `error/warning/note` and never emits the raw string.

**Repro:**

```python
from glassport.audit import Report, render_text, render_json
from glassport.provenance import ProvenanceFinding

secret = "sk-ant-api03-" + "A" * 40 + "1234567890"
pf = ProvenanceFinding(rule="prov-not-in-registry", severity=secret,
                       ecosystem="npm", package="safe",
                       manifest="m.json", detail="d")
report = Report(profile={...}, findings=[], deductions=[],
                score=50, grade="F", provenance=[pf])

assert secret in render_text(report)   # RED
assert secret in render_json(report)   # RED
```

**Fix suggestion:** run `pf.severity` through a closed-set validator (the real provenance rules only emit `high|medium|low|note`) or through `redact_display` before emission.

### PASS3-2a: Combining-mark obfuscation survives

A credential with a combining underline on every character (`s̲k̲-̲a̲n̲t̲...`) is **not** detected by glassport's scanner. It survives in all three rendered outputs. The independent oracle strips the combining marks and reconstructs the credential; the production oracle reports clean.

**Repro:**

```python
obf = "".join(c + "\u0332" for c in secret)
pf = ProvenanceFinding(rule="prov-not-in-registry", severity="high",
                       ecosystem="npm", package=obf, manifest="m.json", detail="d")
# render_text / render_json / sarif.render_sarif all contain the obfuscated shape
```

**Verdict:** detector-layer normalization gap (issue #64 family).

### PASS3-2b: Latin small-capital-A (U+1D00) obfuscation survives

U+1D00 is not NFKC-folded and not in the confusables table. It survives in all rendered outputs; the independent oracle reconstructs the credential. This is explicit issue #64 evidence.

**Repro:**

```python
obf = secret.replace("A", "\u1D00")
pf = ProvenanceFinding(..., package=obf, ...)
```

### PASS3-3a: Split secret across `package` + `detail`

```python
pf = ProvenanceFinding(rule="prov-not-in-registry", severity="high", ecosystem="npm",
                       package="sk-ant-api03-",
                       manifest="m.json", detail="A" * 40 + "1234567890")
```

The text output joins them as `[npm:sk-ant-api03- — AAAAA...1234567890]`; the SARIF composed message is `npm:sk-ant-api03- — AAAAA...1234567890`. The production backstop does not fire because the delimiter breaks pattern contiguity. The independent oracle collapses separators and reconstructs the credential.

**Note:** in current code `detail` is glassport-authored, so this is a theoretical reconstruction, not an attacker-exploitable leak today.

### PASS3-3b: Split secret across `ecosystem` + `package` (text only)

```python
pf = ProvenanceFinding(rule="prov-not-in-registry", severity="high",
                       ecosystem="sk-ant-api03-",
                       package="A" * 40 + "1234567890",
                       manifest="m.json", detail="d")
```

Text output: `[sk-ant-api03-:AAAA...1234567890]`. Independent oracle reconstructs. `ecosystem` is fixed to `npm`/`pypi` in real code, so not currently exploitable.

### PASS3-6a/b: Non-string `rule`/`ecosystem` crash every renderer

```python
pf = ProvenanceFinding(rule=["prov-not-in-registry"], severity="high",
                       ecosystem="npm", package="safe", manifest="m.json", detail="d")
```

- `render_text` / `render_json`: `AttributeError: 'list' object has no attribute 'isascii'`
- `sarif.render_sarif`: `TypeError: unhashable type: 'list'`

The same happens with `ecosystem=["npm"]`. This violates the project's totality requirement that `redact_secrets*` (and by extension the renderers) must never raise on hostile input.

**Fix suggestion:** coerce provenance fields to `str` before scrubbing/validation, or validate type at construction time.

## Pass 3 GREEN locks

- **Obfuscation:** ZWJ, ZWSP, fullwidth, Cyrillic homoglyphs, bidi override are caught by the production oracle and redacted in all renderers.
- **Manifest URI:** obfuscated secrets in `pf.manifest` are caught by `redact_secrets_strict` in JSON and SARIF.
- **Scan-failure totality:** forcing `_scan_pii` to raise produces `_WITHHELD` and no crash in text, JSON, or SARIF.
- **Boundary sizes:** secrets at/beyond 50k clamp cap and 1MB scan cap do not leak.
- **String rule/ecosystem validation:** `None`, empty string, and secret-shaped string values collapse safely to `prov-unknown` / `unknown`.
- **Structural integrity:** SARIF 2.1.0 valid, every `ruleId` resolves to a `driver.rules` entry, JSON provenance keys/types unchanged.
- **Benign invariance:** ordinary `npm:left-pad` provenance output is unchanged.
- **Bypass hunt:** no unexpected `vars(pf)`, `pf.*` f-string interpolation, or serialization paths outside `sarif.py` / `audit.py`.

## Historical notes

- Pass 1 confirmed the P0 SARIF provenance leak.
- Pass 2 confirmed adjacent JSON/text audit leaks and verified the SARIF fix.
- Pass 3 confirmed the centralized helper is correctly wired, found the `severity` bypass, non-string totality crashes, and additional detector-normalization evidence for issue #64.
