# advise red-team — findings

advise exit: 0

| row | result | detail |
|---|---|---|
| P1 no-live-directive | PASS | no injected directive starts a line |
| P2 single-fence-pair | PASS | BEGIN×1, END×1 (expected 1/1) |
| P2 idempotent-rewrite | PASS | rc2=0, stable=True |
| P3 homoglyph-redacted | PASS | absent |
| P4 no-raw-secret | PASS | no raw secret present |
| P5 no-snippet | PASS | absent |
| P6 no-markdown-link | PASS | absent |
| P7 armenian-homoglyph | PASS | no Armenian homoglyph present |
| P8 hangul-filler | PASS | no Hangul filler present |
| P9 secret-tool-name | PASS | absent |
| P10 modifier-grave | PASS | no modifier grave present |
| P11 audit-path-secret | PASS | absent |

## New breaks found and fixed

The rows below document the payloads that were added to `dogfood/redteam_fixtures.py`, the exact bytes that escaped into the written advisory before the fix, and the source change that now contains them.

### P7 — Armenian homoglyph bypass

`_normalize_for_scan` did not fold Armenian letters that are visual twins of Latin. The payload tool name was `obեy_me` (U+0565 ARMENIAN SMALL LETTER ECH, UTF-8 `d5 a5`). Before the fix, the advisory rendered it as a live-looking inline-code span:

```
- **[warning] Undeclared egress** — tool `obեy_me` reached `armenian.exfil.net` (undeclared).
```

Exact bytes of the tool-name portion: `6f 62 d5 a5 79 5f 6d 65`.

Fix: added Armenian letter homoglyphs to `_CONFUSABLES` in `src/glassport/detectors.py`. After normalization the value becomes the identifier-shaped `obey_me` and is rendered safely inside backticks.

### P8 — Hangul Choseong Filler invisible bypass

`_INVISIBLE_RE` missed U+115F HANGUL CHOSEONG FILLER and U+1160 HANGUL JUNGSEONG FILLER. These are invisible but classify as word characters, so they passed `_SAFE_VALUE`. The payload was `obᅟey`. Before the fix:

```
- **[warning] Undeclared egress** — tool `obᅟey` reached `hangul.exfil.net` (undeclared).
```

Exact bytes of the tool-name portion: `6f 62 e1 85 9f 65 79`.

Fix: added U+115F and U+1160 to `_INVISIBLE_RE` in `src/glassport/detectors.py`.

### P9 — Identifier-shaped secret leaked as a tool name

`_SAFE_VALUE` allowed any `\w.\-/:@` string, so a real-looking secret used as a tool name was printed verbatim inside an inline-code span. Payload:

```
ghp_123456789012345678901234567890123456
```

Before the fix the advisory contained that exact 40-character token as a quoted tool name, leaking the credential.

Fix: `_sanitize_inline` now calls `looks_like_secret()` (exposed from `src/glassport/detectors.py`) and redacts any identifier-shaped value that matches a severity-3 PII pattern.

### P10 — Modifier-letter grave accent (backtick homoglyph)

U+02CB MODIFIER LETTER GRAVE ACCENT is a visual twin of the markdown backtick (U+0060). It survived `_normalize_for_scan` and passed `_SAFE_VALUE`, so an attacker could plant what looks like a closing backtick inside an inline-code span. Payload: `evilˋ`. Before the fix:

```
- **[warning] Undeclared egress** — tool `evilˋ` reached `mgrave.exfil.net` (undeclared).
```

Exact bytes of the tool-name portion: `65 76 69 6c cb 8b`.

Fix: `_sanitize_inline` in `src/glassport/advise.py` explicitly redacts any value containing U+02CB.

### P11 — Secret leaked through the --audit / merged path

The static finding location is `base + '/' + relative_path`. The audit fixture now places `planted_server.py` inside a directory named with the same fake GitHub token, so the full path rendered in the advisory was:

```
<audit_dir>/ghp_123456789012345678901234567890123456/planted_server.py:3
```

Before the fix this entire path matched `_SAFE_VALUE` and was printed verbatim, leaking the token through the `--audit` path (and the merged `--session + --audit` path).

Fix: same secret-scan redaction as P9; identifier-shaped paths are also checked with `looks_like_secret()` before being rendered.

