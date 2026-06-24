# Dogfood Finding — Hostile Mock MCP Server

**Date:** 2026-06-24
**Glassport worktree:** `kimi/eval`
**Server:** `dogfood/mock_hostile_server.py` (deterministic, stdlib-only, network-free)
**Driver:** `dogfood/eval_hostile.py`
**Session log:** `dogfood/logs/hostile/20260624T135643Z__usr_bin_python_580129.jsonl`
**Spec:** `dogfood/SPEC-hostile-mock.md`

## Setup

Launched the hostile mock behind the glassport tap:

```bash
python glassport_tap.py --log-dir dogfood/logs/hostile -- \
  python dogfood/mock_hostile_server.py
```

Driver performed MCP handshake (`initialize` with `clientInfo` → `notifications/initialized` → `tools/list`) then issued the A–K call matrix in one session.

## Tool surface observed

2 tools declared:

- `sync_record` — `description` embeds the declared host `https://api.trusted-vendor.com/v1/records`; `inputSchema` allows free-form args (`additionalProperties: true`).
- `lookup` — `id`-switched lookup; one id leaks sev-3 secrets back in the result, another leaks only a sev-1 email.

## Call matrix vs oracle

| Case | Tool | Payload | Expected | Actual | Verdict |
|------|------|---------|----------|--------|---------|
| A | `sync_record` | Anthropic key to `evil.exfil.net` | `pii_anthropic_key` sev3; `unexpected_egress_host` sev3 | same | ✅ |
| B | `sync_record` | AWS key to `loot.s3.amazonaws.com` | `pii_aws_access_key` sev3; `unexpected_egress_host` sev2 (trusted, downgraded) | same | ✅ |
| C | `sync_record` | `https://cdn.cloudflare.com/lib.js` | none | none | ✅ |
| D | `sync_record` | `https://api.trusted-vendor.com/v1/records` | none | none | ✅ |
| E | `sync_record` | `contact alice@example.com` | `pii_email_address` sev1 | same | ✅ |
| F1 | `sync_record` | Luhn-valid `4111111111111111` | `pii_credit_card` sev3 | same | ✅ |
| F2 | `sync_record` | Luhn-invalid `1234567890123456` | none | none | ✅ |
| G | `sync_record` | Zero-width-split Anthropic key + fullwidth email | `pii_anthropic_key` sev3; `pii_email_address` sev1 | same | ✅ |
| H | (cross-cutting) | — | no raw secret or 4-char prefix in any output | none found | ✅ |
| I | `lookup` | `id=leak-keys` returns RSA key + DB URL | `pii_in_result_rsa_private_key` sev3; `pii_in_result_database_url` sev3 | same | ✅ |
| J | `lookup` | `id=leak-email` returns email only | none (result scan is sev-3 only) | none | ✅ |
| K | `sync_record` | 5,000 unterminated `-----BEGIN RSA PRIVATE KEY-----` markers | scan completes <1 s, no hang | 71 ms, no findings | ✅ |

## glassport observations

**Summarize (`--json`):**

```json
{
  "session": "20260624T135643Z__usr_bin_python_580129.jsonl",
  "frames_parsed": 27,
  "declared_tools": ["lookup", "sync_record"],
  "called_tools": ["sync_record", "sync_record", "sync_record", "sync_record", "sync_record", "sync_record", "sync_record", "sync_record", "lookup", "lookup", "sync_record"],
  "unused_declared": [],
  "fabricated_calls": [],
  "protocol_errors": [],
  "tool_errors": [],
  "context_violations": []
}
```

**Detect:**

```
detect: 20260624T135643Z__usr_bin_python_580129.jsonl — 10 finding(s)

  [HIGH] seq=4 pii_anthropic_key: tools/call 'sync_record' argument contains Anthropic API key: [anthropic_key redacted · 56 chars]
  [HIGH] seq=4 unexpected_egress_host: tools/call 'sync_record' reaches evil.exfil.net (undeclared) CARRYING SENSITIVE DATA
  [HIGH] seq=5 pii_aws_access_key: tools/call 'sync_record' argument contains AWS access key ID: [aws_access_key redacted · 20 chars]
  [HIGH] seq=9 pii_credit_card: tools/call 'sync_record' argument contains credit card number (Luhn): [credit_card redacted · 16 chars]
  [HIGH] seq=11 pii_anthropic_key: tools/call 'sync_record' argument contains Anthropic API key: [anthropic_key redacted · 56 chars]
  [HIGH] seq=25 pii_in_result_rsa_private_key: tool result leaks RSA/EC/SSH private key (PEM block)
  [HIGH] seq=25 pii_in_result_database_url: tool result leaks database URL with credentials
  [WARN] seq=5 unexpected_egress_host: tools/call 'sync_record' reaches loot.s3.amazonaws.com (allowlisted) CARRYING SENSITIVE DATA
  [INFO] seq=8 pii_email_address: tools/call 'sync_record' argument contains email address: [email_address redacted · 17 chars]
  [INFO] seq=11 pii_email_address: tools/call 'sync_record' argument contains email address: [email_address redacted · 17 chars]
```

**Timing:** `detect` completed in **71 ms** on the ReDoS payload (case K), well under the 1 s budget.

## Findings

1. **Oracle pass.** All 11 rows matched the spec’s expected subcategory + severity; all `(none)` rows produced zero findings. No deviations from the oracle were observed.
2. **Allowlist downgrade rule holds.** Case B proves that a trusted cloud host (`s3.amazonaws.com`) carrying a secret is **not suppressed** — it is downgraded to sev2 and still reported.
3. **Obfuscation normalization works.** Case G’s zero-width-split Anthropic key and fullwidth email were both recovered and flagged.
4. **Redaction is non-reversible.** Case H scan found no raw secret or 4-character prefix in `detect` output, `summarize --json`, or the eval JSON artifact.
5. **Result leak-back detection works.** Cases I and J confirm the detector scans tool results at sev-3 only: RSA key + DB URL flagged, email ignored.
6. **ReDoS hardening holds.** Case K’s unterminated BEGIN-marker flood scanned in ~71 ms with no hang.
7. **Summarize taxonomy is clean.** `fabricated_calls`, `protocol_errors`, and `tool_errors` were all empty, confirming the round-2 fix does not regress on a clean session.

## Recommendations

- Integrate `dogfood/eval_hostile.py` into CI as a pass/fail gate; any future deviation from the oracle is a real glassport defect.
- Re-run the hostile mock whenever `src/glassport/detectors.py` changes.
- Consider folding the same oracle into a unit test so the gate runs without spawning a subprocess.
