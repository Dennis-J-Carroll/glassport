# Assignment: `_NAMED_VALIDATORS` — the precision layer

**File to edit:** `src/glassport/detectors.py` (the `_NAMED_VALIDATORS = { ... }` block, ~line 510)
**Tests to grow:** `tests/test_plugins.py`
**Goal:** decide which validators a declarative JSON pattern can name, and make
each one a sharp false-positive cull.

---

## Where this sits in the system

```
JSON pattern file ──► load_pii_patterns_from_json()
                          │  resolves "validator": "<name>"
                          ▼
                   _NAMED_VALIDATORS[name]  ◄── YOU BUILD THIS
                          │
   _scan_pii():  regex matches ──► validator(value) ? keep : cull
```

Recall lives in the **regex** (it casts a wide net). Precision lives in the
**validator** (it culls the junk the net caught). They are split on purpose so
you tune one without touching the other.

---

## The contract (non-negotiable — this is what makes it plug in)

1. **Type:** `_NAMED_VALIDATORS: dict[str, Callable[[str], bool]]`. Keys are
   the names JSON authors type; values are predicates.
2. **Predicate semantics:** `validator(matched_value) -> bool`.
   `True` = "real, keep the finding"; `False` = "false positive, cull it."
   It receives the *string the regex matched* (the captured group).
3. **It runs in the hot path.** `_scan_pii` calls it as
   `if pat.validator and not pat.validator(value): continue`. So each predicate
   must be:
   - **Total** — never raise (empty string, unicode, 10 KB blob). A raised
     exception crashes `data_exfiltration` → blinds exfil detection. Wrap
     defensively.
   - **Cheap + ReDoS-safe** — no catastrophic-backtracking regex inside. This
     is a security scanner; the input is hostile.
4. **One pinned test:** `test_validator_by_name_culls_false_positive` requires
   a name `"entropy"` that *rejects* `"a"*32` and *accepts* a random 32-char
   string. Keep that name satisfying that test — or evolve the test too, but
   then own that change.

---

## Methodologies to research (pick ≥2, combine if you want)

### M1 — Entropy thresholding (the baseline)
Shannon entropy (bits/char) separates random secrets from natural text.
Research: the entropy distribution of (a) real API keys, (b) English words,
(c) hex digests, (d) base64. Build a small corpus, compute entropy per class,
pick a threshold where classes separate.
*Keywords:* Shannon entropy, truffleHog entropy detection, base64 vs hex
entropy, ROC curve threshold selection.

### M2 — Checksum / format validators (the high-precision class)
Some tokens carry math you can verify — near-zero false positives. You already
have Luhn (`_luhn_check`) + SSA ranges (`_validate_ssn`). Add one or two:
IBAN mod-97-10, ABA routing checksum, base58check (Bitcoin/Solana addresses),
UUIDv4 structural bits, JWT three-segment base64url structure.
*Method:* implement the checksum, test against real + corrupted samples.

### M3 — Charset / structure heuristics
Cheaper than entropy, sometimes sharper. Detect the alphabet (pure hex? pure
base64? mixed?) and length bands. A 32-char pure-hex string is likely a digest;
40-char base64 with `+/=` is likely a key.
*Keywords:* character-class fingerprinting, secret regex + length gating.

### M4 (stretch) — Gibberish / Markov scoring
"Does this look random or like language?" A char-bigram Markov model scores how
word-like a string is — culls `password123`-style false positives that entropy
alone passes. Must stay pure-stdlib (a tiny hardcoded bigram table is fair
game).
*Keywords:* gibberish detection Markov chain, n-gram language model, nostril.

---

## Deliverable

- `_NAMED_VALIDATORS` filled, **one-line comment per name** stating what it
  culls and why that threshold/method.
- New validator helpers (e.g. `_iban_check`) defined **above** the dict
  (import-order discipline — same reason `_luhn_check` sits above
  `PII_PATTERNS`: a name used before it is defined is a `NameError` at import).
- **Your own tests** in `tests/test_plugins.py`: per name, one value it accepts
  + one it culls. That's the proof your threshold actually separates.

## Acceptance criteria

- [ ] `python -m unittest tests.test_plugins` green (incl. the pinned
      `"entropy"` test).
- [ ] Every predicate is total — add a hostile-input test (empty string,
      50 KB string) that asserts it returns a bool, never raises.
- [ ] Full suite green: `python -m unittest discover -s tests -t .`
- [ ] Each name documents its method + threshold rationale.

---

## Advice for a novice

**Process**
- **Watch the test fail first, then make it pass.** Run
  `python -m unittest tests.test_plugins.TestJsonLoader.test_validator_by_name_culls_false_positive -v`
  *before* you write the dict. Red → your code → green. If it was green before
  you wrote anything, the test is testing nothing.
- **One name at a time.** Add `"entropy"`, get it green, commit. Then `"luhn"`.
  Small steps you can undo beat a big change you can't debug.
- **Commit often with plain messages.** `git add -p` lets you stage one hunk at
  a time and re-read what you actually changed.

**Picking thresholds (the actual hard part)**
- **A threshold is a dial between two failures.** Too low = false positives
  (noise, people stop trusting the tool). Too high = false negatives (a real
  key slips by — the expensive miss). Decide *which failure you fear more* for
  each pattern, then set the dial. For credentials, fear the miss.
- **Don't guess the number — measure it.** Open a Python REPL, paste
  `from glassport.detectors import _calculate_entropy`, and run it on 10 real
  examples and 10 fakes. The threshold lives in the gap between the two
  clusters. If there's no gap, entropy is the wrong tool for that pattern —
  reach for a checksum (M2) instead.

**Safety habits that matter here**
- **Make it total before you make it clever.** Wrap the body so it can't raise:
  ```python
  def _entropy_gate(s: str) -> bool:
      try:
          return _calculate_entropy(s) > 3.0
      except Exception:
          return False   # can't validate → cull, never crash the scan
  ```
  In a normal app a crash is a bug; in *this* detector a crash is a blind spot
  an attacker can trigger on purpose. Fail safe, not loud.
- **Reach for `lambda` only for one-liners.** `"luhn": _luhn_check` (already a
  predicate) needs no wrapper. `"entropy": lambda s: _calculate_entropy(s) > 3.0`
  is fine. Anything with a `try/except` deserves a named `def` — easier to test
  and to read.

**When stuck**
- Read the two validators that already exist (`_luhn_check`, `_validate_ssn`,
  ~line 309). They are the worked examples for everything you're about to write.
- If a test is hard to write, the design is usually too complicated — simplify
  the validator, not the test.
- Ask. "Here's my dict and here's the test that won't pass" is a great question.

---

## Research-locked decisions (from the cascaded-model report)

Decided and fixed — implement within these, don't re-litigate:

- **Cascade is Phase B, not now.** Each `PIIPattern` names exactly one
  validator; the regex already does the structural stage. A true M2→M1
  cascade only exists inside a *composite* validator (`"key_like"`), which
  needs the checksum validators to exist first. Not this PR.
- **Menu, not cascade, is the default.** Standalone named validators; the
  policy/JSON author composes by choosing which to name per pattern.
- **OR-keep for Severity-3.** On a credential-class match, a borderline score
  KEEPS the finding. Only cull a clear false positive. (Same posture as the
  egress allowlist: downgrade, never silently suppress.)

### THIS PR's scope (decided): minimal menu

```
"entropy":      _calculate_entropy(s) > 3.0     # natural-language ceiling
"entropy_high": _calculate_entropy(s) > 4.0     # optional; base64-grade
"luhn":         _luhn_check                      # already a str->bool
"ssn":          _validate_ssn                    # already a str->bool
```

Financial checksums were the **Phase-B PR**. ✅ **IBAN (`iban`) and ABA
(`aba`) validators shipped** + a P/R fixture corpus (`tests/test_checksums.py`).
Placement split by false-positive risk:
- **IBAN** is a default `PII_PATTERN` — structured (2 letters + 2 digits +
  MOD-97), barely false-positives, earns the default scan.
- **ABA** is **menu-only + opt-in** (`examples/pii-financial.json`). Its regex
  is a bare `\d{9}`; even with the Federal-Reserve-range + mod-10 guard it
  passes ~3.8% of random 9-digit strings — too broad to spend every user's
  precision budget on. Consumers who handle banking data opt in via
  `GLASSPORT_PII_PATTERNS`. This is the registry's own thesis applied to a
  built-in: broad patterns belong in opt-in packs, not core.

Base58check / UUIDv4 / JWT-structural remain available by the same recipe.

### Per-charset entropy reference — ✅ shipped as `entropy_auto` (M3)

A single global threshold is the report's named "common mistake." `entropy_auto`
detects the alphabet from the value and picks the threshold. **Order is
load-bearing: hex ⊆ alphanumeric**, so check hex first — `abcABC123` is all
hex digits and must take the 3.0 tier, not 3.7. A pure-alnum string is
indistinguishable from padless base64, so only an actual `+/=` promotes a value
to the 4.5 base64 tier.

| Charset | Max bits/char | Practical threshold |
|---|---|---|
| Natural language | ~4.0 (constrained 3.0–3.5) | baseline to beat |
| Hex (16 symbols) | 4.0 | ~3.0 |
| Alphanumeric (36) | 5.17 | ~3.7 |
| Base64 (64) | 6.0 | ~4.5 |

### Canonical M2 algorithms (Phase-B reference, spec not code)

- **IBAN — ISO 13616 MOD-97-10:** strip spaces; move first 4 chars to the end;
  map `A=10 … Z=35`; interpret as a big integer; valid iff `% 97 == 1`.
- **ABA routing (9 digits):**
  `(3·d1+7·d2+1·d3+3·d4+7·d5+1·d6+3·d7+7·d8+1·d9) % 10 == 0`.
- **Base58check / UUIDv4-bits / JWT-three-segment:** report p.5 table.

### Evaluation rules (do this, skip the heavy harness)

- **Fixtures, not a P/R harness** — for 3 validators, good test fixtures are
  the corpus. Build a real honeytoken/anonymized-commit benchmark only in
  Phase B.
- **The fake-credential paradox:** do NOT test with obvious fakes like
  `FAKEAWSSECRETKEY123456` — a good validator rejects them, and you'd misread
  that as broken. Use real-*shaped* harmless values for accept cases.
- **Known-FP cull cases:** a SHA-256 hex digest and a base64 minified-JS blob
  are high-entropy non-secrets — your entropy threshold must NOT over-flag
  them. Add one of each as a cull test.
- **Precision & recall, never accuracy.** Accuracy conflates the two costs;
  for Severity-3, recall wins.

### Plumbing note (out of scope — don't build it)

The report's param-name context-boosting (`db_password` → high confidence)
would require changing `_scan_pii` to pass surrounding context to the
validator. It currently passes the matched **value only**. Per-charset
thresholds need nothing more (charset is in the value). Context-boosting is a
separate future enhancement — keep it out of `_NAMED_VALIDATORS`.
