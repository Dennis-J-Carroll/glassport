# Redaction Red-Team Grill Findings

Branch: `fix/sarif-provenance-redaction` (PR #63)  
Grill: `PYTHONPATH=src python dogfood/eval_redaction_redteam.py` (34 cases)  
Kimi's pass-3 evidence (47 cases, 8 intentionally RED at the time) preserved
unmodified on `redteam/pass3-evidence` (commit `128a64d`) for the #64 track.  
Run date: 2026-07-12

## Executive summary

Three Kimi red-team passes against the provenance→artifact path, in sequence:

1. **Pass 1** confirmed the P0: `pf.package` reached SARIF unredacted.
2. **Pass 2** confirmed the same leak class in the `--json`/text audit renderers (ADJ-1/ADJ-2).
3. **Pass 3** validated the centralized fix (`detectors.redact_display`, used by
   all three renderers) and found two further gaps at the renderer boundary:
   `severity` emitted raw in text/JSON, and non-string `rule`/`ecosystem`
   crashing all three renderers. Both are **fixed** in this PR. Pass 3 also
   surfaced Unicode-normalization gaps (combining marks, Latin small-capital-A)
   and theoretical split-field compositions — **not fixed here**, classified
   below and tracked separately (issue #64).

**Reachability, established empirically** (`tests/test_provenance.py::
TestProvenanceFieldReachability`, driving a real `package.json` through
`discover_deps()` → `evaluate()` — the actual shipped pipeline, not a
hand-constructed `ProvenanceFinding`): of the six `ProvenanceFinding` fields,
**only `package` is manifest-derived**. `rule`, `severity`, `ecosystem`,
`manifest`, and `detail` are all fixed, glassport-authored literals chosen by
glassport's own code (which file it parsed, which check fired), never read
from manifest content. This means every renderer-boundary finding below that
requires attacker control of `severity`/`rule`/`ecosystem`/`detail` — alone or
in combination with `package` — is **not currently exploitable through the
real pipeline**. They are fixed anyway, as defense-in-depth against a future or
buggy provenance source (a new ecosystem adapter, a refactor of `evaluate()`),
and reported as such — not as live 0-days.

## Glassport's redaction guarantee (stated explicitly, per this round)

Glassport's shareable-artifact redaction guarantees: **no credential appears
intact, or in a known-obfuscated form (zero-width, homoglyph, fullwidth,
bidi-override), as a contiguous, directly-usable string within a single
rendered field or reasonable composed message.** It does **not** guarantee
against a reconstruction oracle that strips *all* structural punctuation,
whitespace, and field delimiters before searching — that transformation
disregards separators a real reader or tool would see and rely on, and chasing
it risks broad, unjustified over-redaction of ordinary structured output
(false withholding of benign findings). Where this round narrows or does not
extend the guarantee (Unicode confusable coverage; a hypothetical
multi-field-split), it says so explicitly rather than silently.

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
| ADJ-1 | `--json` audit output provenance leak | **CONFIRMED → FIXED** | `render_json` was `vars(pf)`; now per-field `redact_display` |
| ADJ-2 | Text audit output provenance leak | **CONFIRMED → FIXED** | `render_text` scrubs `package`/`ecosystem`/`rule`/`detail` |
| PASS3-1 | `pf.severity` raw in text/JSON | **CONFIRMED → FIXED** | `provenance.safe_severity`, closed set `{high,medium,low,note}` → `note` sentinel; not attacker-reachable today |
| PASS3-6a | Non-string `pf.rule` crashes all 3 renderers | **CONFIRMED → FIXED** | `provenance.safe_rule` — isinstance-first, no `str()`/`in frozenset` on a hostile value |
| PASS3-6b | Non-string `pf.ecosystem` crashes all 3 renderers | **CONFIRMED → FIXED** | `provenance.safe_ecosystem`, same pattern |
| PASS3-hostile | Hostile `__str__`/`__bool__`/`__eq__` on any field | **FIXED** | `redact_secrets_strict`/`redact_display` isinstance-first; SARIF manifest check isinstance-gated before truthiness |
| PASS3-2a | Combining-mark obfuscation in `package` | **not fixed — tracked** | detector-normalization gap; issue #64 |
| PASS3-2b | Latin small-capital-A (U+1D00) obfuscation in `package` | **not fixed — tracked** | issue #64; 0.6.9 gated on its explicit disposition |
| PASS3-3a | Split secret across `package`+`detail` | **classified, not currently reachable** | `detail` is always glassport-authored; no contiguous credential in production oracle — see guarantee statement above |
| PASS3-3b | Split secret across `ecosystem`+`package` | **classified, not currently reachable + structurally protected** | `ecosystem` is glassport-chosen (never manifest content); closed-set validation discards non-enum content wholesale |
| PASS3-3c/3d | Split across `rule`+`detail` / JSON punctuation | green lock | delimiter/key-name insertion breaks contiguity in the production scanner |
| PASS3-5 | Boundary sizes (scan/clamp caps) | green lock | no >cap secret survives |
| PASS3-7/8/9 | Structural integrity, benign invariance, bypass hunt | green lock | valid SARIF, JSON schema unchanged, only known-safe `pf.*` accesses found |

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

## Deferred to issue #64: Unicode-normalization gaps (NOT in this PR)

Combining-mark obfuscation (`s\u0332k\u0332-\u0332a\u0332n\u0332t\u0332...`) and Latin small-capital-A (U+1D00) both
survive in `package` across all three renderers \u2014 the production oracle
(`detectors._normalize_for_scan`) reports clean because glassport's own
normalizer doesn't fold these forms either, so its "clean" verdict cannot be
trusted for these specific glyphs. Per explicit instruction, this is **not**
dismissed on that basis: [issue #64](https://github.com/Dennis-J-Carroll/glassport/issues/64)
requires an *independent* reconstruction oracle (not sharing glassport's
normalizer) to determine actual recoverability, and reachability via `package`
is now real (see `TestProvenanceFieldReachability`) \u2014 0.6.9 does not ship until
#64's disposition (fixed, or the supported-obfuscation claim explicitly
narrowed) is explicit. `secret.replace("A", "\u1D00")` and the combining-mark
repro are preserved unmodified in Kimi's pass-3 evidence
(`redteam/pass3-evidence`, commit `128a64d`) for that work.

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

### Resolution (ADJ-1 / ADJ-2 — FIXED in this PR)

Both audit renderers now scrub provenance fields with the **shared**
`detectors.redact_display` (strict-redact → neutralize → clamp), the single
definition SARIF also uses — so no renderer can drift into the
neutralize-without-redact bug independently:

- `render_json` builds a per-field sanitized dict instead of `vars(pf)` (same
  keys, so the JSON shape is unchanged): `package`/`detail`/`ecosystem`/`rule`
  → `redact_display`, `manifest` → `redact_secrets_strict`.
- `render_text` scrubs `package`/`ecosystem`/`rule`/`detail` before formatting.

Benign npm/PyPI output is byte-unchanged. Locked by
`tests/test_audit.py::TestProvenanceRedactionInRenderers` (plain + zero-width /
fullwidth / Cyrillic obfuscation, JSON schema keys unchanged, ordinary output
unchanged). Teeth: reverting the audit fix reds 3/5. Grill now **30/30**.

## Pass-3 renderer-boundary fixes (this PR)

`src/glassport/provenance.py` gains three shared, closed-set validators used
by **all three** renderers (SARIF, JSON, text) — the single point of truth so
no renderer independently re-derives (and can drift on) the valid-value sets:

- `safe_rule(value)` / `safe_ecosystem(value)` / `safe_severity(value)` — each
  checks `isinstance(value, str)` **first**, before any other operation, so a
  non-string or hostile value never has a method invoked on it (`__str__`,
  `__eq__`, `__bool__`, `__hash__` via `in frozenset`). An unrecognized or
  non-string value collapses to a fixed sentinel (`prov-unknown` / `unknown` /
  `note`).
- `detectors.redact_secrets_strict` and `redact_display` are now themselves
  isinstance-first: a non-string input immediately withholds/sentinels rather
  than risking the fallthrough (root cause of the pass-3 crash: an empty-spans
  no-op splice returned the *unredacted, non-string object itself*, which the
  next stage's string-only method then crashed on).
- `render_text` gained a composed-message backstop mirroring SARIF's (re-scrub
  the fully assembled provenance block) — architecturally consistent, a no-op
  on already-clean text, closes the one path (text) that previously had no
  backstop at all.

Locked by `tests/test_sarif.py::TestProvenanceRendererBoundaryDefensiveGaps`
and `tests/test_audit.py::TestProvenanceRendererBoundaryDefensiveGaps` (severity
closed-mapping, non-string totality, hostile-dunder-never-invoked, split
classification) — teeth: reverting all four source files reds 2 failures + 5
errors across the two classes. Reachability locked separately in
`tests/test_provenance.py::TestProvenanceFieldReachability`.

## Green locks (surface hit, no plain-secret escape found)

- P1/P2/P4/P5/P6/P7 remain green locks from the original grill.
- All SARIF fix-specific obfuscation, boundary, validation, fail-closed, and structural rows are green locks.
- All pass-3 renderer-boundary rows above (severity, non-string totality, hostile-dunder, split classification) are green locks in the live 34-case grill.

These are tested-surface statements, not proofs of universal safety.

---

## Update 2026-07-13: issue #64 resolved — combining-mark + small-capital fixed

Per user directive: time-boxed to an independent-oracle reachability
determination across real attacker-controlled paths before deciding fix vs.
narrow. **Disposition: fix.**

**Reachability, established (not merely proof-read from source):** a genuinely
independent reconstruction oracle — a separate implementation from
`detectors._normalize_for_scan`/`_normalize_with_map` (own category-strip, own
NFKD+NFKC, own confusable table) — was driven across two real
attacker-controlled paths:

1. `provenance.package`, via a real `package.json` through
   `discover_deps()` → `evaluate()` (not a hand-built `ProvenanceFinding`).
2. Ordinary MCP tool-call **arguments and results**, through the real adapter
   (`from_mcp_session`) into `report.html` — the normalizer is shared beyond
   provenance, exactly as flagged.

Both combining-mark (a synthetic mark stapled to every character) and
small-capital (U+1D00 block) obfuscation reconstructed in **both** surfaces.
**`report.html` is a default, always-on artifact — not gated behind
`--provenance`** — so this finding is broader than PASS3-2a/2b's original
provenance-only framing.

**Root cause:** confirmed via `unicodedata.decomposition()` — the entire
U+1D00–U+1D2B block has **no decomposition at all** (these are phonetic
IPA-extension letters, not Unicode compatibility variants), so NFKC can never
fold them; a synthetic combining mark similarly has no compatibility mapping.
Only a curated addition, matching the existing confusables-table pattern,
closes this — the same shape as every prior confusables fix in this file.

**Fix (`src/glassport/detectors.py`):**
- `_CONFUSABLES` += 14 small-capital Latin letters that render as a plain
  capital with no extra stroke/rotation (same-glyph curation rule); excludes
  turned/sideways/barred/ligature variants in the block as visually distinct.
- `_normalize_with_map` drops standalone combining marks (category **Mn**
  only — not Mc, which is not the demonstrated attack and is load-bearing for
  legitimate non-Latin orthography), same treatment as invisible chars.
- `_spanned_original_redactions` extends a match's end boundary past a
  **trailing** invisible/combining run — a cosmetic gap the fix's own tests
  surfaced (no secret information either way, but keeps the redaction
  placeholder free of stray obfuscation bytes, matching the bar the project's
  pre-existing zwj test already set).

**Verified:**
- **False positives:** 5 real multilingual benign fixtures (IPA transcription,
  decomposed "résumé"-style diacritics, Cyrillic stress marks, academic
  phonetics) — zero false PII matches, zero unnecessary redactions.
- **Performance:** linear to 2M chars (correctly capped at `MAX_SCAN_BYTES`);
  a match-followed-by-500k-trailing-run pathological case stays under 3s — no
  ReDoS reopened.
- **Origin-map correctness:** dedicated test for combining-mark deletion
  indices; all 14 confusable-table entries verified against the actual
  committed source (not just a local snippet).
- **Grill:** 4 new permanent rows (`ISSUE64:` prefix), using the same
  independent oracle, across both surfaces — 38/38.

**Process note — a mistake worth recording:** the first pass of every new
artifact-boundary test (report/audit/provenance/grill) used
`detectors._normalize_for_scan` as the "did it leak" check. That is the
**production oracle** — the exact function this fix patches — so it was
structurally blind to the gap it was meant to prove closed, and every one of
those tests reported green even with the fix fully reverted. This is the
precise trap the "independent oracle" directive exists to prevent. Caught by
teeth-proofing every single new test (revert the fix → confirm it fails →
restore → confirm it passes) rather than trusting the first green run; all
tests were then rewritten against the independent oracle and re-verified.
11 tests correctly fail with the fix reverted; all pass restored.

**Disposition of every PASS3 Unicode-related row:**

| ID | Prior status | Now |
|---|---|---|
| PASS3-2a (combining-mark in `package`) | not fixed — tracked | **FIXED** |
| PASS3-2b (small-capital in `package`) | not fixed — tracked | **FIXED** |

Issue #64 closed. 0.6.9's gate on its explicit disposition is satisfied.
