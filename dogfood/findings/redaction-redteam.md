# Redaction Red-Team Grill Findings

Grill: `PYTHONPATH=src python dogfood/eval_redaction_redteam.py` (permanent CI gate).
Target: span-aware redaction (`detectors.py`) + the HTML/SARIF artifact boundaries.
Status: **all 16 cases green.** The one confirmed leak (P-lead) is fixed and locked;
P1–P7 are tested regression locks with no escape found (not a proof of universal safety).

## Summary

| ID | Hypothesis | Verdict | Fields / Notes |
|---|---|---|---|
| **P-lead** | Unredacted hostile `pf.package` reaches SARIF | **CONFIRMED → FIXED** | leaked `message.text`, `properties.package`; now strict-redacted |
| P-lead sweep | `pf.ecosystem` reaches SARIF unscrubbed | **FIXED** | now validated against `{npm, pypi}` → `unknown` sentinel |
| P-lead sweep | `pf.detail` reaches SARIF unscrubbed | **FIXED** | now strict-redact → neutralize → clamp |
| P-lead sweep | `pf.rule` reaches SARIF `rules[].name`/`shortDescription`/`ruleId` | **FIXED** | now validated against the fixed provenance catalog → `prov-unknown` |
| P1 | Backstop fragment-miss topologies | green lock | nested/overlapping, adjacent, placeholder-concat — no escape found |
| P2 | Origin-map drift under cross-char NFKC | green lock | homoglyph, fullwidth — no escape found |
| P3 | Scan-cap straddle / clamp ordering | green lock | clamp always after redact — no escape found |
| P4 | Other artifact field bypasses `redact_secrets_strict` | **= P-lead** | static path/detail, runtime message, HTML `_esc` all redacted |
| P5 | Structural suppression swallows real secret | green lock | JWT-wrapped secret redacted whole — no escape found |
| P6 | Custom pattern reduces built-in redaction | green lock | custom spans only expand union coverage — no escape found |
| P7 | False withhold of clean evidence | green lock | benign prose + literal redaction tags pass — no escape found |

## P-lead — confirmed then fixed

**Attacker-controlled source:** `ProvenanceFinding.package`, supplied through a
dependency manifest scanned on the opt-in `--provenance` audit path.

**Leaking sinks (before fix):** `results[].message.text` and
`results[].properties.package`.

**Root cause:** `sarif.py` applied `neutralize_text()` + `clamp_text()` to
`pf.package` but never `redact_secrets_strict()`. Unicode neutralization is not
credential scrubbing, so a plaintext (or obfuscated) credential in a hostile
package name reached the SARIF artifact intact. The code's own comment claimed the
field was "scrubbed exactly like the static-rule path" — it was not.

**Independent confirmation (RED):** the grill drives the real `sarif.render_sarif`
(no monkeypatch) and the normalize-the-artifact oracle
`secret in detectors._normalize_for_scan(doc)` was `True` on the vulnerable source.

## Resolution (landed with this grill)

`src/glassport/sarif.py` now, per field class:

- **Attacker-displayable text (`package`, `detail`):** `_sanitize_display` =
  `redact_secrets_strict` → `neutralize_text` → `clamp_text`, in that order (redact
  first, because `redact_secrets_strict` normalizes internally and so catches
  obfuscated credentials; neutralize is a *reveal* layer, never a substitute for
  redaction). `manifest` stays redacted via its URI.
- **Structural fields (`ecosystem`, `rule`):** validated against a closed set —
  `ecosystem ∈ {npm, pypi}` else `unknown`; `rule ∈` the fixed provenance catalog
  else `prov-unknown`. An unrecognized value collapses to a safe sentinel instead
  of being smuggled into the rules table or the ecosystem label. Every emitted
  `ruleId` still resolves to an entry in the driver rules table.
- **Composed `message.text`:** built only from the sanitized components, then
  strict-scrubbed again as a backstop so a secret cannot be reconstructed across
  the join of two individually-clean fields.
- **Fail-closed preserved:** if the strict scan raises, the field is withheld
  (`_WITHHELD`), never emitted raw.

Regression locks: `tests/test_sarif.py::TestProvenanceRedaction` (plain +
zero-width/fullwidth/Cyrillic/combined obfuscation, absence from the normalized
whole artifact and from both sinks, fail-closed withholding, valid rule ids +
`ruleId`↔rules-table consistency, and ordinary npm/PyPI output unchanged except
sanitization). Teeth: reverting the source fix reds 5 of the 7 locks.

## Green locks (surface hit, no escape found — NOT a universal-safety proof)

- **P1** — nested/overlapping generic+anthropic spans, adjacent duplicate secrets,
  placeholder concatenation: all redacted, backstop clean.
- **P2** — Cyrillic homoglyph and fullwidth obfuscation: origin map resolves back to
  the original range; full original range redacted.
- **P3** — clamp runs after redact in HTML and SARIF message fields; URI/fingerprint
  inputs are bounded file paths.
- **P4** — static `Finding.path`/`detail` and runtime annotation `explanation` are
  redacted; HTML `_esc` runs redact→clamp→neutralize→escape on every field.
- **P5** — a JWT structural container enclosing a real secret is redacted whole.
- **P6** — an overlapping consumer custom pattern expands, never shrinks, coverage.
- **P7** — clean prose and literal redaction-tag strings are not withheld.
