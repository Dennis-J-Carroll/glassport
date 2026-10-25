# Decision bundles

`glassport bundle` copies captured wire logs and matching decision journals into
one directory. It adds a SARIF finding index and a canonical manifest. The
manifest records facts. `bundle verify` computes verdicts when somebody reads
the bundle; the manifest has no `verified`, `valid`, or `equivalent` field.

```sh
glassport bundle --log-dir /private/wire --journal-dir /private/decisions -o /private/bundle
glassport bundle verify /private/bundle --json

# One or more explicit captures, with optional static audit:
glassport bundle --wire first.jsonl second.jsonl --journal-dir /private/decisions \
  --audit server/src -o /private/bundle
```

The output path may be absent or empty. A nonempty path is refused; evidence
is never overwritten. Journal pairing uses the `epoch` inside the profile
record, then checks that every record belongs to that epoch. Source file names
are not trusted for pairing. `--wire` can be repeated. `--log-dir` collects
`*.jsonl` files in that directory. HTTP writes one wire log and one journal per
session epoch. Stdio writes one wire log and has no journal.

## Manifest schema: `glassport.bundle/1`

`manifest.json` is [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)
bytes, without a trailing newline. Readers preserve unknown fields when
copying or forwarding a manifest. Existing fields retain their meaning;
future schemas change the `schema` value rather than silently redefining one.

| Field | Meaning |
|---|---|
| `schema` | `glassport.bundle/1`. |
| `canonicalization` | `RFC8785`, the bytes signed by `manifest.sig`. |
| `bundler.version` | Glassport version that assembled the bundle. |
| `bundler.created_at` | ISO 8601 UTC assembly timestamp; not capture time. |
| `versions.glassport_version`, `commit`, `schema_version`, `policy_version`, `detector_engine`, `journal_schema` | Capture identities copied from `glassport.header`; `commit` can be null. |
| `evidence.epochs[]` | One object per captured epoch, including `epoch`, `wire`, `journal`, and `replay_argv`. |
| `evidence.epochs[].wire.path`, `sha256` | Bundle-relative path and SHA-256 of the entire copied wire file. |
| `evidence.epochs[].wire.trailer_log_sha256` | Digest claimed by the `glassport.metrics` trailer over all bytes before that trailer; null when absent. Verification recomputes it. |
| `evidence.epochs[].wire.entries`, `seq_range` | Number of wire entries and inclusive first/last sequence; empty range is `[1,0]`. |
| `evidence.epochs[].journal` | Null for stdio; otherwise `path`, whole-file `sha256`, `records`, and `final_record_sha256`. The last two fields expose tail deletion. |
| `evidence.epochs[].replay_argv` | Exact relative `glassport replay-decisions` command; null for stdio. |
| `evidence.audit` | Null unless `--audit` was given; otherwise copied audit JSON path and SHA-256. |
| `evidence.sarif` | Path and whole-file SHA-256 of `index/findings.sarif.json`. |
| `profile.header` | Verbatim first `glassport.header` record, including hashed remote URL path. |
| `profile.journal_profiles` | Epoch-keyed verbatim journal profile records. Includes `authorization.status: not_evaluated`. |
| `analysis.findings` | `stable_id`-keyed findings with epoch, rule ID, severity, evidence level, and wire sequence. Keys match SARIF `partialFingerprints.stable_id`. |
| `delivery[]` | One row per recorded delivery: epoch, intent and delivery ordinals, wire sequence and exact wire-line digest from the intent, outcome, code, evidence level. |
| `limits[]` | Named limitations from `compute_limits`. A signed raw bundle omits `no_signature`. |

`bundle verify OUT [--trusted-key PUB] [--json]` prints **analysis reproduced**
and **delivery evidence present** separately, then integrity, signature status,
and the manifest's limits verbatim. It exits 0 only if every epoch replays
`equivalent`, every intent has one delivery with a matching wire-line digest,
the pre-trailer log digest matches, and every artifact hash and other integrity
check passes. For stdio, replay and delivery are `unsupported`/`incomplete`
because no journal exists; the limitations say so. A trailer missing after a
crash is reported as `trailer_missing`.

Integrity checks also compare journal record count and last-line hash, pair
the epoch inside wire and journal records, compare the manifest's delivery
rows and profile to copied records, and check whole-file hashes. A digest can
expose accidental or unilateral changes to a copied file. Someone able to
rewrite an unsigned bundle can recompute the hashes; use a trusted signature
for resistance to that rewrite.

## Signing and public copy

```sh
glassport bundle --log-dir /private/wire --journal-dir /private/decisions \
  -o /private/bundle --sign /private/ed25519.key --redact
glassport bundle verify /private/bundle --trusted-key /private/ed25519.pub
```

`--sign` accepts an existing Ed25519 private key in raw 32-byte or PEM form;
glassport never creates a key. Signing needs the optional
`glassport[attestation]` extra. If that extra is absent, `--sign` fails
explicitly. `manifest.sig` contains a detached base64 Ed25519 signature over
the exact JCS manifest bytes. `--trusted-key` accepts a raw 32-byte or PEM
public key. Status is `valid (fingerprint …)`, `invalid`,
`present, not verified (cryptography not installed)`,
`present, no trusted key given`, or `absent`. An unverified signature does not
fail an otherwise valid raw-bundle verification.

`--redact` adds `OUT/public/`: redacted wire, journal, audit, SARIF, and a
public manifest. It uses `detectors.redact_secrets_strict` on string values,
replaces epoch-derived file names with ordinal names, and records both public
artifact hashes and raw artifact hashes under `raw_hashes`. The public manifest
adds `raw_tier: withheld` and `public_redaction_not_replay_equivalent` limit.
Redaction changes wire bytes and journal chains, so the **raw tier** is what
replay verifies. Distribute **only `public/`**; keep `OUT/evidence/`,
`OUT/index/`, raw manifest, and any signing key private. Inspect the public
copy before sharing if your traffic has domain-specific secret formats.

> **What a bundle does not prove**
>
> - Capture completeness: glassport sees only traffic routed through it.
> - Original host authenticity: an unsigned digest proves no origin; a
>   signature proves only that the holder of that key signed this bundle.
> - Caller authorization: status is `not_evaluated`.
> - Server-side execution: `forwarded` proves a complete local send, not that
>   an upstream tool executed. `externally_confirmed` is reserved and never
>   emitted.
