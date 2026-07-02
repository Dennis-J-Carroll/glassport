# report red-team — findings

| row | result | detail |
|---|---|---|
| R1 no-live-markup | PASS | no attacker markup payload survived unescaped |
| R2 no-bidi-control | PASS | no bidi/directional control survived |
| R3 no-invisible-char | PASS | no invisible/zero-width char survived |
| R4 no-armenian-homoglyph | PASS | no Armenian homoglyph present |
| R5 no-modifier-grave | PASS | no modifier grave present |
| R6 markup-name-escaped | PASS | attacker value not present unescaped |
| R7 script-result-escaped | PASS | attacker value not present unescaped |
| R8 no-raw-secret | PASS | no raw secret present |
| R9 dos-output-bounded | PASS | output 256414 bytes (limit 2000000) |
| R10 no-zalgo-run | PASS | longest combining-mark run = 4 (limit 4) |
| R11 no-nfkc-homoglyph | PASS | no fullwidth homoglyph present; no mathematical-alphanumeric homoglyph present |
| R12 no-exotic-whitespace | PASS | no exotic whitespace present |
| R13 no-zalgo-interleave | PASS | 20 combining marks survived (limit 25) |
| R14 no-novel-secret | PASS | no raw secret present |

## Threat & method

The renderer draws attacker-controlled tool names, arguments and result text into an HTML page a human opens in a browser. `html.escape` neutralizes markup (`< > & " '`) but is blind to Unicode deception — bidi overrides, zero-width joiners and cross-script homoglyphs render as inert-but-misleading text. R2–R5 lock that gap; R1/R6/R7 regression-lock the markup escaping that already held. R9 bounds output against a multi-megabyte field (a resource/DoS shape — the renderer amplified a 5 MB name 4× before the per-field clamp); R10 collapses Zalgo combining-mark runs that an escape-only renderer let overflow the row.

R11 extends the homoglyph hunt to NFKC compatibility variants: fullwidth Latin (U+FF00 block) and mathematical alphanumerics (U+1D400–U+1D7FF) fold to ASCII under NFKC but were outside the curated _HOMOGLYPHS set, so a hostile tool name could visually impersonate a declared one. The neutralizer now reveals any character whose NFKC form is ASCII alphanumeric.

R12 closes exotic whitespace: NBSP (U+00A0), ideographic space (U+3000), line separator (U+2028) and paragraph separator (U+2029) are not _SAFE_WS and can misalign rows or hide breaks; they are now revealed as sentinels.

R13 defeats the Zalgo run-counter reset: interleaving each combining mark with a zero-width joiner made the old counter reset to 0 after every mark, so 60 marks survived individually. The neutralizer now collapses combining-mark runs across transparent interleaves, bounding both the longest consecutive run (R10) and the total number of marks that escape collapse.

R14 adds a novel credential shape — Stripe API keys (`sk_live_`, `pk_test_`, etc.) — to the redaction catalog. Before the pattern the key reached session.html verbatim; after, it is replaced with `[stripe_key redacted · N chars]`.

