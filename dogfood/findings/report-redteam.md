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

## Threat & method

The renderer draws attacker-controlled tool names, arguments and result text into an HTML page a human opens in a browser. `html.escape` neutralizes markup (`< > & " '`) but is blind to Unicode deception — bidi overrides, zero-width joiners and cross-script homoglyphs render as inert-but-misleading text. R2–R5 lock that gap; R1/R6/R7 regression-lock the markup escaping that already held. R9 bounds output against a multi-megabyte field (a resource/DoS shape — the renderer amplified a 5 MB name 4× before the per-field clamp); R10 collapses Zalgo combining-mark runs that an escape-only renderer let overflow the row.

