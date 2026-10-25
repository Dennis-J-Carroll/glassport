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
| `analysis.findings` | `stable_id`-keyed findings with `source: wire` and a string epoch, or `source: audit` and `epoch: null`; each has rule ID, severity, evidence level, and wire sequence. Keys match SARIF `partialFingerprints.stable_id`. Public findings replace rule IDs with `rule_id_sha256`. |
| `delivery[]` | One row per recorded delivery: epoch, intent and delivery ordinals, wire sequence and exact wire-line digest from the intent, outcome, code, evidence level. |
| `limits[]` | Named limitations from `compute_limits`. A signed raw bundle omits `no_signature`. |

`bundle verify OUT [--trusted-key PUB] [--json]` prints **analysis reproduced**
and **delivery evidence present** separately, then integrity, signature status,
and the manifest's limits verbatim. It exits 0 only if every epoch replays
`equivalent`, every intent has one delivery with a matching wire-line digest,
the pre-trailer log digest matches, and every artifact hash and other integrity
check passes. Exit `0` means all checkable claims hold; exit `1` means a
contradiction (integrity failure, divergent replay, orphaned or duplicate/missing
delivery, or manifest mismatch); exit `2` means no contradiction but an
unprovable claim. Stdio without a journal exits `2` with
`unsupported`/`incomplete`. A trailer missing after a crash is reported as
`trailer_missing`.

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
glassport bundle verify --public /private/bundle/public --trusted-key /private/ed25519.pub
```

`--sign` accepts an existing Ed25519 private key in raw 32-byte or PEM form;
glassport never creates a key. Signing needs the optional
`glassport[attestation]` extra. If that extra is absent, `--sign` fails
explicitly. `manifest.sig` contains a detached base64 Ed25519 signature over
the exact JCS raw manifest bytes. With `--redact`, `--sign` also writes
`public/manifest.sig` over the separate public JCS manifest. `--trusted-key` accepts a raw 32-byte or PEM
public key. Status is `valid (fingerprint …)`, `invalid`,
`present, not verified (cryptography not installed)`,
`present, no trusted key given`, `trusted_key_unreadable`, or `absent`. A present
signature without a usable trusted key exits `2` when other checks hold.

`--redact` adds `OUT/public/`: projected wire and journal records, a reduced
SARIF index, and a public manifest. It removes peer payload fields (`frame`,
`raw`, `sse_meta`, `http_observation`, `wire_b64`), replaces each `wire_b64`
with SHA-256 of its decoded bytes, and removes journal text and custom pattern
lists. Gate markers keep only fixed `action`, `reason`, and `evidence_level`
codes; unknown actions and reasons become `redacted`. A tool name becomes
`tool_sha256` (SHA-256 of its UTF-8 bytes, or null). `also_skipped` remains
only when every entry is a known reason code. Other gate fields are dropped.
The public manifest records `public_gate_tool_hashed`. Audit JSON is withheld.
SARIF messages, source locations, rule text,
and properties are removed; stable IDs remain. The manifest records
`public_raw_bytes_removed`, `public_peer_text_removed`, and, when applicable,
`public_audit_removed`. It records both public artifact hashes and raw artifact
hashes under `raw_hashes`; those raw hashes cannot be checked from public files.
Without signing it keeps `no_signature`. With signing it records
`signed: public_manifest` and omits `no_signature`.

`bundle verify --public OUT/public` checks public file hashes and that public
manifest's signature. It reports analysis `not_applicable_redacted` and delivery
`records_present_digests_withheld`, so a clean public verify exits `2`.
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
