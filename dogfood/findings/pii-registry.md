# Dogfood findings: PII plugin registry + validator menu (glassport 0.5.0)

**Branch:** `kimi/eval`  
**Harness:** `dogfood/eval_pii_registry.py`  
**Raw output:** `dogfood/logs/pii_registry_eval_out.json`  
**Date:** 2026-06-28  
**Target surface:** `_NAMED_VALIDATORS` menu (`luhn`, `ssn`, `iban`, `aba`, `base58`, `jwt`, `uuid4`, `entropy`, `entropy_high`, `entropy_auto`), the env-autoload registry (`GLASSPORT_PII_PATTERNS`), the opt-in packs `examples/pii-financial.json` / `examples/pii-crypto.json`, and the new default `iban` + validator-gated `jwt_token` detections.

## Executive summary

| Claim | Verdict | Measured result |
|---|---|---|
| Precision on real MCP traffic | **Mostly pass** | 0 `pii_iban` / 0 `pii_jwt_token` false positives on filesystem/fetch/github/exa traffic. **One real precision hole:** a real-format JWT in a server response is flagged as `pii_in_result_aws_secret_key` because its 40-char base64url header segment matches the broad AWS-secret regex + entropy gate. |
| Recall with honeytokens | **Pass** | 8/8 honeytoken categories detected (IBAN, Luhn-valid card, SSN, JWT, AWS access key, OpenAI key, GitHub token, DB URL). |
| Registry fail-safe | **Pass** | Malformed JSON, non-array, missing field, bad severity, bad regex, unknown validator, and ReDoS regex all warn to stderr and keep built-ins live. |
| Checksum correctness | **Pass** | IBAN, ABA, base58, JWT, UUID4 validators are 100% correct on valid/corrupted fixture corpora. |
| Evasion + DoS | **Partial fail** | Zero-width / fullwidth obfuscation is normalized and caught. **Cyrillic homoglyph (`а` U+0430) evades OpenAI-key detection** because NFKC does not map Cyrillic to Latin. No built-in pattern ReDoSes on ~1 MB (≤400 ms). `MAX_SCAN_BYTES` cap holds. |
| SARIF + redaction | **Pass** | No raw secret or 6-char prefix leaked in SARIF or summarize output. |

---

## A. Precision on real MCP traffic

### Method

Ran the existing real-server evals and a dedicated filesystem precision campaign:

```bash
PYTHONPATH=src python dogfood/eval_pii_registry.py
```

The precision campaign creates files full of realistic non-secret tokens and reads them back through `@modelcontextprotocol/server-filesystem`:

* UUIDs (`550e8400-e29b-41d4-a716-446655440000`)
* SHA-256 / MD5 hex digests
* A real-format JWT
* An `eyJ…` JWT lookalike that is **not** a JWT
* 9-digit IDs
* IBAN-lookalikes that fail MOD-97
* Random base64 blobs
* GitHub-style request IDs

### Measured false-positive counts

| Server / campaign | Total PII annotations | `pii_iban` | `pii_jwt_token` | Other default-pattern FP |
|---|---|---|---|---|
| `eval_filesystem.py` (baseline) | 0 | 0 | 0 | 0 |
| `eval_fetch.py` (baseline) | 0 | 0 | 0 | 0 |
| `eval_github.py` (no token) | 0 | 0 | 0 | 0 |
| `eval_exa.py` (no token) | 0 | 0 | 0 | 0 |
| **Precision campaign (real JWT in response)** | **1** | **0** | **0** | **1 `pii_in_result_aws_secret_key`** |

### Defect: JWT flagged as AWS secret access key

**Verdict:** FAIL — precision hole in the existing `aws_secret_key` pattern, exposed by the new JWT-aware layer when real JWTs cross the wire.

**What happens:** the `aws_secret_key` regex is `(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])` with an entropy gate `> 4.0`. A real JWT header segment such as `eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9` is exactly 40 chars, high entropy, and contains only base64url characters that happen to also be in the AWS-secret charset (no `-`/`_` in this header). It therefore passes the AWS-secret gate even though it is a JWT, not an AWS credential.

**Wire-log repro:**

```text
dogfood/logs/pii-precision/20260628T180923Z_npx_1945484.jsonl
```

The file `real_jwt.txt` contained a real-format HS256 JWT. `read_file` returned it as a tool result. Glassport emitted:

```text
[HIGH] seq=12 pii_in_result_aws_secret_key: tool result leaks AWS secret access key (entropy)
```

The same log shows **no** `pii_jwt_token` finding for that result because `jwt_token` is severity 2 and `data_exfiltration` only scans severity-3 patterns in tool results.

**Redacted SARIF excerpt:**

```json
{
  "ruleId": "glassport/pii_in_result_aws_secret_key",
  "message": {
    "text": "tool result leaks AWS secret access key (entropy)"
  },
  "properties": {
    "severity": 3,
    "subcategory": "pii_in_result_aws_secret_key"
  }
}
```

**Root cause:** the AWS-secret regex is charset/length/entropy only; it has no structural guard against JWT header segments. When the new `jwt_token` validator correctly identifies the value as a JWT, the coarser `aws_secret_key` pattern still fires independently.

**Suggested fix:** either (a) suppress `aws_secret_key` when the same span is already matched by `jwt_token`, or (b) require AWS-secret candidates to lack the JWT three-segment structure.

### What was correctly culled

* The `eyJnotavalidjwtsegment.aaaaaaa.bbbbbbb` lookalike produced **no** `pii_jwt_token` finding (validator correctly rejected it).
* UUIDs, SHA-256/MD5 digests, 9-digit IDs, and IBAN-lookalikes produced **no** `pii_iban` findings (MOD-97 correctly rejected them).

---

## B. Recall with honeytokens

### Method

Injected real-shaped, permission-less secrets into filesystem tool calls and file contents:

| Honeytoken | Value shape |
|---|---|
| IBAN | `DE89370400440532013000` (verified MOD-97) |
| Credit card | `4111111111111111` (Luhn-valid Visa test) |
| SSN | `123-45-6789` |
| JWT | Real-format HS256 JWT |
| AWS access key ID | `AKIAIOSFODNN7EXAMPLE` |
| OpenAI key | `sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJ` |
| GitHub token | `ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| Database URL | `postgresql://user:p4ssw0rd@db.example.com:5432/app` |
| RSA PEM | `-----BEGIN RSA PRIVATE KEY-----...` |

### Results

```json
{
  "found_subcategories": [
    "pii_aws_secret_key",
    "pii_credit_card",
    "pii_in_result_aws_access_key",
    "pii_in_result_credit_card",
    "pii_in_result_database_url",
    "pii_in_result_github_token",
    "pii_in_result_iban",
    "pii_in_result_openai_key",
    "pii_in_result_rsa_private_key",
    "pii_in_result_ssn",
    "pii_jwt_token"
  ],
  "missed_categories": [],
  "recall_miss_count": 0
}
```

**Verdict:** PASS — all 8 honeytoken categories were detected. `pii_aws_secret_key` is an additional false-positive side-effect of the JWT, documented in §A.

**Wire-log repro:** `dogfood/logs/pii-recall/20260628T180925Z_npx_1945532.jsonl`

---

## C. Registry fail-safe (`GLASSPORT_PII_PATTERNS`)

### Oracle

| Input | Expected | Measured |
|---|---|---|
| Malformed JSON | warn, built-ins live | ✅ warn, email detected |
| Non-array JSON | warn, built-ins live | ✅ warn, email detected |
| Missing required field | warn, built-ins live | ✅ warn, email detected |
| Severity out of 1..3 | warn, built-ins live | ✅ warn, email detected |
| Bad regex | warn, built-ins live | ✅ warn, email detected |
| Unknown validator | warn, built-ins live | ✅ warn, email detected |
| ReDoS regex `(a+)+$` | warn only on scan (no crash) | ✅ no crash, email detected |
| `examples/pii-financial.json` not set | ABA routing not detected by default | ✅ not detected |
| `examples/pii-financial.json` set | ABA routing detected | ✅ detected |

**Verdict:** PASS — the env-autoload path is fail-safe in all tested failure modes.

**Sample stderr for malformed JSON:**

```text
glassport: ignoring GLASSPORT_PII_PATTERNS (/tmp/.../malformed_json.json):
/tmp/.../malformed_json.json: invalid JSON: Expecting property name enclosed in double quotes: line 1 column 3 (char 2)
```

---

## D. Checksum validators + adversarial near-misses

### Fixture corpus results

| Validator | Valid positives | Corrupted / invalid negatives | False accepts | False rejects |
|---|---|---|---|---|
| `iban` | 2 (`DE89...`, `GB82...`) | 2 (single-digit corruptions) | 0 | 0 |
| `aba` | 2 (`021000021`, `011401533`) | 2 (mod-10 fail, prefix 99) | 0 | 0 |
| `base58` | 1 (testnet address) | 1 (checksum corruption) | 0 | 0 |
| `jwt` | 1 (real JWT) | 1 (`eyJnotreal.invalid.signature`) | 0 | 0 |
| `uuid4` | 1 (`550e8400-e29b-41d4-a716-446655440000`) | 1 (version 5, wrong variant) | 0 | 0 |

**Verdict:** PASS — all checksum/format validators are perfect on this adversarial near-miss corpus. A corrupted IBAN also did **not** fire end-to-end.

---

## E. Evasion + DoS

### Evasion

| Obfuscation | Expected | Measured |
|---|---|---|
| Credit card split with zero-width spaces (`\u200b`) | detected after normalization | ✅ detected |
| Credit card in fullwidth Latin homoglyphs | detected after NFKC | ✅ detected |
| OpenAI key with Cyrillic `а` (U+0430) homoglyph | detected after normalization | ❌ **missed** |

**Verdict:** PARTIAL FAIL — `_normalize_for_scan` handles invisible controls and fullwidth Latin, but NFKC does **not** map Cyrillic homoglyphs to ASCII, so a secret with a Cyrillic `а` slips through.

### Defect: Cyrillic homoglyph evades key detection

**Verdict:** FAIL — normalization gap.

**What happens:** the OpenAI key regex `[A-Za-z0-9]{32,}` only accepts ASCII letters. Replacing the first Latin `a` with a visually identical Cyrillic `а` (U+0430) breaks the match. NFKC leaves U+0430 unchanged, so `_normalize_for_scan` does not help.

**Minimal repro:**

```python
from glassport import detectors
latin_key = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"    # detected
cyr_key = "sk-proj-аbcdefghijklmnopqrstuvwxyzABCDEFGHIJ"     # 'а' is U+0430
print([p.category for p, _ in detectors._scan_pii(latin_key)])  # ['openai_key']
print([p.category for p, _ in detectors._scan_pii(cyr_key)])    # []
```

**Suggested fix:** add a homoglyph-confusables map (at least the high-risk Cyrillic/Greek lookalikes of ASCII letters) before pattern matching, or document that NFKC-only normalization does not cover cross-script homoglyphs.


### ReDoS timing (~1 MB adversarial input per pattern)

| Pattern | Time (ms) | Verdict |
|---|---|---|
| `iban` | 169 | ✅ no catastrophic backtracking |
| `jwt_token` | 173 | ✅ linear |
| `crypto_address` (base58 pack) | 149 | ✅ linear |
| `email_address` | 175 | ✅ linear (regression from round 1 still holds) |
| `credit_card` | 151 | ✅ linear |

**Verdict:** PASS — no pattern ReDoSes on ~1 MB input.

### Oversize cap

| Payload | Secret location | Expected | Measured |
|---|---|---|---|
| 1.1 MB | credit card at byte 0 | detected | ✅ detected |
| 1.1 MB | credit card at end | missed (beyond cap) | ✅ not detected |

**Verdict:** PASS — `MAX_SCAN_BYTES` (1 MB) cap holds. The design intentionally trades off deep-payload recall for scan DoS resistance.

---

## F. SARIF + redaction integrity

### Method

Ran `glassport detect --sarif` and `glassport summarize --json` on a log containing real honeytokens, then searched the JSON-serialized outputs for the raw secrets and for 6-character prefixes.

### Result

```json
{
  "leaks": [],
  "pii_count": 3
}
```

**Verdict:** PASS — no raw secret value and no 6-character prefix leaked in either output. Redaction consistently emitted `[category redacted · N chars]`.

---

## Recommended bugs

### 1. JWT flagged as AWS secret access key

**Repro log:**

```text
dogfood/logs/pii-precision/20260628T180923Z_npx_1945484.jsonl
```

Minimal one-liner proof:

```python
from glassport import detectors
jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiY2FuYXJ5IiwgImlhdCI6IDE3MTAwMDAwMDB9.xVGZOp8m8rN40GwGwU-qIvGjXxJDlQkrOnddiAqaq2Q"
print([p.category for p, _ in detectors._scan_pii(jwt)])
# -> ['aws_secret_key', 'jwt_token']
```

A JWT should not simultaneously be reported as an AWS secret access key.

### 2. Cyrillic homoglyph (`а` U+0430) evades OpenAI-key detection

Minimal one-liner proof:

```python
from glassport import detectors
latin_key = "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
cyr_key = "sk-proj-аbcdefghijklmnopqrstuvwxyzABCDEFGHIJ"  # 'а' is U+0430
print([p.category for p, _ in detectors._scan_pii(latin_key)])  # ['openai_key']
print([p.category for p, _ in detectors._scan_pii(cyr_key)])    # []
```

Cross-script homoglyphs are a known evasion class that NFKC alone does not defeat.
