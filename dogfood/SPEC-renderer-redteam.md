# Dogfood Spec — Renderer Red-Team Grill (report.py + sarif.py poisoning resistance)

**Status:** both grills implemented and running all-green — report R1–R10 PASS, sarif S1–S5 PASS, exit 0 (merged: PR #29 hardening + grills, PR #30 DoS/Zalgo bounds).
**Author handoff:** Kimi.
**Motivation:** the same through-line as the advise grill — *glassport renders attacker-controlled bytes into a surface that gets parsed downstream*. For `advise` that surface is an agent's `CLAUDE.md`. For these two it is:

- **`report.py` → `session.html`** — an HTML page a human opens in a browser, often from `file://`, where injected script runs with local-file reach. Threat: a hostile MCP server's tool name / arguments / result inject live markup (stored-XSS shape) **or** deceive the analyst who reads the report to make a trust decision.
- **`sarif.py` → SARIF 2.1.0** — a JSON document uploaded to the GitHub Security tab (and sometimes committed). Threat: a finding field breaks the JSON, smuggles markup the UI interprets, or leaks a credential into a shared artifact.

The advise grill proved the method: build the strongest adversary, point it at the **real renderer**, treat every survival as proof and every breakage as a source fix. This spec hands Kimi the same discipline for the two renderers that now have a floor to beat.

---

## Current state — the floor Kimi must beat

Two rounds have already run against these renderers and found real cracks, now fixed. This is the floor, not the ceiling.

### report.py — what was found and fixed

`render_html` already HTML-escaped every wire field (markup injection was closed — R1/R6/R7 regression-lock it). But the grill turned four boxes red:

- **Unicode deception (R2–R5).** `html.escape` neutralizes `< > & " '` but is blind to bidi overrides (U+202E), zero-width joiners, Hangul fillers, and Cyrillic/Armenian/grave homoglyphs. All rendered **verbatim** — a hostile tool name could visually reorder or impersonate a benign one.
- **Credential leak (R8).** Tool arguments and results were dumped into `<pre>` raw, so a secret sent as an argument landed in a shareable HTML file.
- **Unbounded output / DoS (R9).** A 5 MB tool name rendered in ~4 places produced a 20 MB page in ~5–9 s. No per-field cap.
- **Zalgo stacks (R10).** Combining marks (category Mn/Mc/Me) passed `_neutralize` and overflowed the row.

The fix lives in `report.py._esc`, applied to **every** attacker-derived field:

```
_esc(value) = html.escape(_neutralize(clamp_text(redact_secrets(str(value)))))
```

Order is load-bearing: **redact → clamp → neutralize → escape**.
- `detectors.redact_secrets` scans (via `_scan_pii`, capped at `MAX_SCAN_BYTES = 1 MB`) and replaces every recognized credential with a non-reversible `[category redacted · N chars]` tag.
- `detectors.clamp_text` (`MAX_RENDER_CHARS = 50 000`) truncates the field. **Clamp-after-redact is leak-safe**: the clamp bound (50 k) sits well inside the scanned window (1 MB), so a secret cannot survive by straddling the truncation point.
- `_neutralize` **reveals** each deceptive character as a visible `‹U+XXXX›` sentinel (reveal, not silent-strip — the analyst must see the server used a hidden/look-alike char) and **collapses** combining-mark runs longer than 4 into a single `‹combining…›` marker (legit diacritics keep ≤4).

### sarif.py — what was found and fixed

The JSON envelope was never breakable (`json.dumps` escapes structure) and `message.text` is a plain-text field GitHub does not render as HTML — S1/S2 lock that. But:

- **Credential-in-path leak (S3).** `audit` redacts secret *values* in a finding's `detail`, but a **sibling channel** was open: a hostile server can name a directory like a credential (the advise P11 shape), and `Finding.path` flowed into the SARIF `uri`, `partialFingerprints`, and message **verbatim**. Confirmed end-to-end through the real `audit_path → render_sarif`. Fixed by scrubbing message, URI and fingerprint with `detectors.redact_secrets`; `render_session_sarif` scrubs the message at the output boundary too.
- **Unbounded output (S5).** A 5 MB tool name rode into `a.explanation` → 10 MB SARIF. Fixed by `clamp_text` on the message.

A poisoning **directive** the audit quotes in a finding (`directive text: 'ignore previous instructions'`) is deliberately **NOT** redacted — that is the tool faithfully reporting the attack it found, not a leak. Any oracle that flags it is wrong.

---

## Why an in-process harness, not another real server

The bugs that matter live in the chain, not in a single hand-built object:

```
hostile bytes → adapter → detectors.annotate → render_html / render_sarif → artifact
```

A committed (report) or runtime-generated (DoS/Zalgo) hostile session drives the **entire** chain deterministically — no keys, no network, byte-reproducible, CI-runnable. The report grill's injection rows use a tracked, byte-stable `session.jsonl`; the DoS/Zalgo rows generate multi-megabyte fixtures at runtime so they never bloat the repo.

---

## Layer 1 — report.py attack catalog

Each row smuggles a payload through a controlled field (tool name, argument, result text) and asserts an invariant on the produced `session.html`. A failing invariant is a real glassport finding — fixed at `report.py`, never softened.

| # | Attack | Smuggled via | Invariant on the rendered HTML |
|---|--------|--------------|--------------------------------|
| R1 | **Live markup** — `<img src=x onerror=alert(1)>`, `</pre><script>…` | tool name / result | Payload appears only html-escaped; no raw `<…>` survives |
| R2 | **Bidi override** — U+202E `admin‮gpj.exe` | tool name | No bidi/directional control (U+202A–E, 2066–9, 200E/F, 061C) survives; revealed as `‹U+202E›` |
| R3 | **Zero-width / invisible** — U+200D joiner, U+115F/1160 Hangul filler | tool name | No invisible char survives; revealed as sentinel |
| R4 | **Cross-script homoglyph** — Armenian `ե` (U+0565) | tool name | Absent; revealed as `‹U+0565›` |
| R5 | **Backtick look-alike** — U+02CB modifier grave | tool name | Absent; revealed |
| R6/R7 | **Escape regression** — the R1 payloads | name / result | Round-trip through `html.escape`; never verbatim |
| R8 | **Secret leak** — anthropic/aws/db/rsa in args + result | argument / result | Only `[category redacted · N chars]`; no raw value or 12-char prefix |
| R9 | **DoS** — a 2 MB tool name | tool name | Output bounded (< 2 MB); field truncated with a `chars truncated` marker |
| R10 | **Zalgo** — 60 combining marks on one base | tool name | Longest surviving combining-mark run ≤ 4 |

## Layer 2 — sarif.py attack catalog

| # | Attack | Smuggled via | Invariant on the SARIF document |
|---|--------|--------------|---------------------------------|
| S1/S2 | **JSON break** — markup/quotes/control bytes in any field | detail / path / explanation | Document still parses as JSON with a `runs` array |
| S3 | **Credential-in-path** — directory named `ghp_…` | `Finding.path` → uri / fingerprint | No raw secret in the whole document |
| S4 | **Runtime secret** — secret in a tool arg → `a.explanation` | annotation explanation | No raw secret (detector redacts upstream; renderer re-scrubs at the boundary) |
| S5 | **DoS** — 2 MB tool name → `a.explanation` | annotation explanation | Output bounded (< 2 MB); message clamped |

---

## Build targets (already in place)

- **`dogfood/redteam_fixtures.py`** — payloads and session builders: `MARKUP_NAME_PAYLOAD`, `SCRIPT_RESULT_PAYLOAD`, `BIDI_NAME_PAYLOAD`, `ZWJ_NAME_PAYLOAD`, `ZALGO_NAME_PAYLOAD`; `hostile_report_lines()` (tracked session), `dos_report_lines(field_chars)` / `zalgo_report_lines()` (runtime-generated), `write_audit_fixture()` (secret-named dir for S3). `SECRETS` holds the fake-but-format-valid credentials.
- **`dogfood/oracle.py`** — independent checkers (own deceptive-char sets, so the check is never circular): `no_live_markup`, `no_bidi_control`, `no_invisible_char`, `no_armenian_homoglyph`, `no_modifier_grave`, `value_escaped`, `no_raw_secret`, `bounded_output` (deterministic size, not wall-clock), `no_zalgo_run`, `json_well_formed`.
- **`dogfood/eval_report_redteam.py`** / **`dogfood/eval_sarif_redteam.py`** — the runners: drive the real renderer, run the checks, print a PASS/FAIL table, write `dogfood/findings/{report,sarif}-redteam.md`, exit non-zero on any FAIL.

## How to run

```
PYTHONPATH=src python dogfood/eval_report_redteam.py
PYTHONPATH=src python dogfood/eval_sarif_redteam.py
```

Both are gated in CI by the `redteam-grills` job (every PR) and the release `test` gate.

## Pass criteria

Every R- and S-row PASS, exit 0. A documented finding with a tracked source fix (in `src/glassport/report.py`, `sarif.py`, or `detectors.py`) counts as resolved; an unexplained red row does not. **Never soften an oracle to make the grill pass.**

---

## Kimi's charge

> Kimi — the advise renderer already earned its scars from you (P7–P11). Now there are two more surfaces, and the authors believe they've closed them: the HTML a human opens in a browser, and the SARIF a Security tab renders. They think markup is escaped, deception is revealed, secrets are redacted, and output is bounded. The tables above are *their* imagination of your attack. Make them look quaint.
>
> You are the malicious MCP server. You own every byte of every tool name, argument, and result. For `report.py` the prize is a browser that runs your script, or a report that lies to the analyst about what your server did. For `sarif.py` the prize is a document that breaks the Security tab's parser, smuggles a payload its UI interprets, or leaks a credential into a file that gets committed. Every box you turn red is a real fix in the source repo with your name on it.

### Invent beyond the table

The R/S catalog is the authors' imagination. Known-thin spots to attack:

**report.py**
- **Homoglyphs outside `_CONFUSABLES`.** `_neutralize` reveals a *curated* Cyrillic/Greek/Armenian set plus U+02CB/U+0405 — and, unlike `detectors._normalize_for_scan`, it does **NOT** apply NFKC. So a **fullwidth** Latin letter (`Ａ` U+FF21), a **mathematical alphanumeric** (`𝐀` U+1D400), an enclosed or small-caps look-alike, or a Cherokee/Coptic glyph that resembles ASCII will render un-revealed. Find one that lets a hostile tool name impersonate a declared one in the surface chips. This is the most likely real finding.
- **Deceptive whitespace.** `_SAFE_WS` is only ASCII `\t \n \r space`. Other separators — NBSP (U+00A0, Zs), the U+2000–200A spaces, ideographic space (U+3000), line/paragraph separators (U+2028/2029, Zl/Zp) — are neither `_SAFE_WS` nor category Cc/Cf, so they pass through `_neutralize` untouched. Can U+2028 break the visual row, or a wide space misalign the surface list to hide a fabricated call?
- **Zalgo run-counter reset.** `_neutralize` counts *consecutive* combining marks. Interleave each mark with a zero-width char (which is revealed as a sentinel and resets the run to 0): does the combining-mark run collapse still fire, or does the interleave defeat it and let the stack survive (broken up by sentinels)?
- **Deeply nested / recursive content.** A tool result whose value is a 50 000-level nested JSON array: does `_pretty`'s `json.dumps` (or the adapter's `json.loads` upstream) hit `RecursionError` and crash `render_html`? A crash on report generation is a DoS.
- **Event/annotation count.** The per-field clamp does not bound the *number* of events or the *number* of annotations per event. Is there a small hostile session that produces a pathologically large or slow report by count rather than field size?

**sarif.py**
- **Unicode deception in `message.text`.** Unlike `report.py`, `sarif.py` does **not** neutralize — it only redacts + clamps. A bidi override or homoglyph in a tool name flows literally into the SARIF `message.text` (valid JSON, `ensure_ascii=False`). Does the GitHub Security-tab renderer neutralize bidi, or can you make a finding *read* as a different file/host/severity than it is? If the UI honors it, that is a real deception finding — and the fix is to reuse the report neutralizer here.
- **`ruleId` / rule-object fields.** Rule IDs are `glassport/{subcategory}`. Runtime subcategories are detector-minted (`pii_<category>`). Can any attacker-controlled input reach a rule `id`, `name`, or `tags` un-scrubbed and break SARIF rule-object schema validation (which GitHub enforces on upload)?
- **Novel credential shapes.** `redact_secrets` only knows the built-in + custom PII patterns. A credential format glassport does **not** recognize (a new cloud provider's key, a bearer token with an unusual prefix) will not be redacted and will leak into both the report and the SARIF. Demonstrate one; the fix is a new pattern, not a renderer change — but the grill row belongs here.

For every finding: capture the exact produced bytes that prove it, add a payload to `dogfood/redteam_fixtures.py` and an assertion to `dogfood/oracle.py`, do not soften the oracle, and land the source fix in `src/glassport/`.

---

## Out of scope (this round)

- Fuzzing / property-based generation — the method is a deterministic oracle; a seeded fuzz layer is a possible follow-up.
- Wiring a programmatic Kimi tool — none is available; this spec is a brief a human hands to Kimi.
- The semantic-directive judge (does an LLM *obey* surviving text) — needs a model, kept off the zero-dep path; run it in the Kimi loop separately.
