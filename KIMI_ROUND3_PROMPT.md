# Kimi — Round 3 testing brief: the PII plugin registry + validator menu

You are dogfooding **glassport 0.5.0** (this worktree is current `main`, all
tests green: `python -m unittest discover -s tests -t .` → 314 OK). You tested
0.4.0 in rounds 1–2 (see `kimi_session_01.md`, `dogfood/findings/*.md`) and
found a real bug — the `summarize` error taxonomy (`tool_errors` vs
`protocol_errors`). **Find the next one.** Confirmation is not the goal; measured
gaps and reproducible bugs are.

## What is new since you last tested (this is the target surface)

A consumer-extensible **PII / secrets detection layer** was added to the
`data_exfiltration` detector (`src/glassport/detectors.py`):

- **A plugin registry** — two ways to add custom PII patterns:
  - in-code: `register_pii_pattern(PIIPattern(...))` (arbitrary callable validator)
  - declarative: `load_pii_patterns_from_json(path)` + the env var
    `GLASSPORT_PII_PATTERNS=<file.json>` (autoloaded on first scan)
- **A precision menu** of named validators a JSON pattern can reference:
  `luhn`, `ssn`, `iban`, `aba`, `base58`, `jwt`, `uuid4`, `entropy` (>3.0),
  `entropy_high` (>4.0), `entropy_auto` (per-charset: hex 3.0 / alnum 3.7 /
  base64 4.5).
- **New default detections:** `iban` (MOD-97), and `jwt_token` is now
  validator-gated (header must decode to JSON — an `eyJ…` lookalike should no
  longer be a false positive).
- **Two opt-in packs:** `examples/pii-financial.json` (ABA routing),
  `examples/pii-crypto.json` (base58 addresses). Off by default on purpose
  (broad regexes); enabled via `GLASSPORT_PII_PATTERNS`.

The design intent and thresholds are documented in
`docs/assignments/named-validators.md` — read it; your job is to verify the
claims it makes, not take them on faith.

## The two claims to attack

This layer makes a **precision vs recall** bargain (see README "Success
Metrics" and the assignment doc):

1. **Recall** — severity-3 credentials (keys, private keys, db-URLs, IBAN)
   must be caught aggressively. A missed secret is the expensive failure.
2. **Precision** — the validators (Luhn, checksums, entropy thresholds) must
   cull the obvious false positives. Real MCP traffic is *full* of the things
   that fool a naive scanner: UUIDs, SHA/MD5 hashes, base64 blobs, request IDs,
   9-digit numbers, `eyJ…` lookalikes.

Your mission: **measure both, adversarially, against real traffic** — not
synthetic unit cases (those already pass).

## Test campaigns (pick the high-leverage ones; use the existing harness)

Your harness already exists: `dogfood/driver.py::run_session` launches a real
MCP server behind the tap and returns the session log; `glassport detect
<log>.jsonl` runs the detectors; `--sarif` emits SARIF.

**A. Precision on real traffic (highest value).**
Run the real servers you used before (`eval_filesystem.py`, `eval_github.py`,
`eval_fetch.py`, `eval_exa.py`) and any others. These payloads are full of
UUIDs, hashes, base64, IDs. **Count the false positives** the new defaults
(`iban`, `jwt_token`) produce. Specifically:
- Does any real UUID / SHA-256 digest / base64 response body get flagged as
  `pii_iban` or anything else? (IBAN's regex is `[A-Z]{2}\d{2}[A-Z0-9]{11,30}`
  — what real tokens collide and does MOD-97 actually cull them?)
- Does any non-JWT `eyJ…` string survive or get correctly culled?
- Report a **measured FP count per server**, with the offending values
  (redacted) and which pattern fired.

**B. Recall with honeytokens (NOT obvious fakes).**
The assignment doc warns of the *fake-credential paradox*: a smart validator
rejects `FAKEAWSSECRETKEY123456`, so testing with obvious fakes produces a
misleading "miss." Instead inject **real-but-harmless** secrets into tool-call
arguments via the driver: a freshly-minted permission-less API key, a
canary/honeytoken, a self-signed throwaway private key, a real test IBAN
(`DE89370400440532013000`), a real-format JWT, a Luhn-valid test card
(`4111111111111111`). Confirm each is detected (and at the right severity).
**Report any miss** — that is a recall hole.

**C. Registry robustness / fail-safe (must not be brittle, must not blind).**
The env-autoload path is supposed to be **fail-safe** — a misconfigured
`GLASSPORT_PII_PATTERNS` file must warn to stderr and keep the built-in scan
running, NEVER raise out of a scan (that would blind exfil detection). Attack it:
- malformed JSON, non-array JSON, missing fields, out-of-range severity,
  unknown validator name, and a **catastrophic-backtracking regex** in a custom
  pattern. Does any of these crash a scan, hang it, or silently disable the
  built-in detectors? (The explicit `load_pii_patterns_from_json()` is supposed
  to raise; the env path is supposed to swallow+warn. Verify the split holds.)
- Confirm the opt-in packs are genuinely **off by default** and on only when
  the env var points at them.

**D. Checksum validator correctness + adversarial near-misses.**
For `iban` / `aba` / `base58` / `jwt` / `uuid4`: feed real valid vectors AND
single-character-corrupted near-misses AND structurally-valid-but-fake values.
Look for: a checksum that accepts a corrupted value (false accept), or rejects
a real one (false reject). For `base58`, try real BTC/Solana addresses and
random base58 strings — does the SHA-256d checksum hold? For `aba`, the Federal
Reserve leading-range guard — find a valid routing number it wrongly rejects.

**E. Evasion + DoS (the scanner's input is hostile by definition).**
- **Obfuscation:** split a secret with zero-width joiners, disguise it in
  fullwidth homoglyphs — does normalization (`_normalize_for_scan`, NFKC) still
  catch it? Find a normalization gap.
- **ReDoS:** benchmark every PII pattern (old and new — `iban`, the base58 pack
  regex) against ~1 MB of adversarial text. Round 1 fixed the email pattern;
  the new patterns have not been fuzzed. Time them.
- **Oversize:** a multi-megabyte tool payload vs `MAX_SCAN_BYTES` — does the cap
  hold without missing a secret in the first 1 MB?

**F. SARIF + redaction integrity.**
Confirm a flagged secret never appears in the annotation or SARIF output (not
even a prefix) — `_redact` must emit only `[category redacted · N chars]`.
Try to make a finding leak its own value.

## Deliverables

- One findings doc per the convention — `dogfood/findings/pii-registry.md` (or
  a `kimi_session_02.md` running log). For each campaign: a **pass/fail oracle
  table**, the **measured numbers** (FP count per server, recall hits/misses,
  ReDoS timings), and a redacted repro for every real defect.
- File real bugs as you did in round 2 — with the wire log that proves them.
- If you find a precision hole (a real-traffic FP) or a recall hole (a missed
  honeytoken), that is the prize. The last round's `tool_errors` bug shipped a
  fix; aim for the same.

## Rules

- **Commit early and often** to `kimi/eval` (uncommitted work is unrecoverable
  here). Write findings as you go and commit them.
- **Stay in this directory** (`glassport-kimi/`). Do not touch `../glassport`.
- **Honeytokens, never obvious fakes** — and **report measured numbers, not
  vibes.** "3 false positives on the github server, values X/Y/Z, all
  `pii_iban`" beats "seems mostly fine."
- Build mode is `pip install -e .` in this worktree, or
  `PYTHONPATH=src python -m unittest discover -s tests -t .`.

Current state: glassport **0.5.0** + the PII registry/menu work on top of it;
worktree at `main` HEAD, 314 tests green.
