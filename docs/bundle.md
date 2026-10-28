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
session epoch. Stdio writes one wire log per capture, with a random 32-character
lowercase hexadecimal `epoch` in its header and a journal at
`<log_dir>/decisions/<epoch>.jsonl`. With no explicit `--journal-dir`, stdio
journals are discovered beside their wire logs. Multiple stdio captures can
share a bundle. An old stdio log without a header epoch retains the literal
`stdio` identity and, without a journal, verifies exit `2`.

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
| `evidence.epochs[].journal` | Null when unavailable; otherwise `path`, whole-file `sha256`, `records`, and `final_record_sha256`. The last two fields expose tail deletion. |
| `evidence.epochs[].replay_argv` | Exact relative `glassport replay-decisions` command; null without a journal. |
| `evidence.audit` | Null unless `--audit` was given; otherwise copied audit JSON path and SHA-256. |
| `evidence.sarif` | Path and whole-file SHA-256 of `index/findings.sarif.json`. |
| `profile.header` | Verbatim first `glassport.header` record, including hashed remote URL path. |
| `profile.journal_profiles` | Epoch-keyed verbatim journal profile records. Includes `authorization.status: not_evaluated`. |
| `analysis.findings` | `stable_id`-keyed findings with `source: wire` and a string epoch, or `source: audit` and `epoch: null`; each has rule ID, severity, evidence level, and wire sequence. Keys match SARIF `partialFingerprints.stable_id`. Public findings replace rule IDs with `rule_id_sha256`. |
| `delivery[]` | One row per recorded delivery: epoch, intent and delivery ordinals, wire sequence and exact wire-line digest from the intent, outcome, code, evidence level. |
| `limits[]` | Named limitations from `compute_limits`. A signed raw bundle omits `no_signature`. |

Detector engine `glassport.detectors/3` adds in-session tool-definition
mutation, live declaration poisoning, and bounded base64/base64url argument
rescanning. Replay refuses a `/2` journal as `unsupported` with
`profile_mismatch_detector_engine` (bundle verify exit `2`), rather than
claiming different findings are a divergence. Stable finding IDs change with
the engine string. Encoded scanning is analysis-only and finding-only: it
decodes once, with one 64 KiB decoded-byte budget per call frame; an oversized
candidate is skipped while later arguments are still checked. Hex and
percent decoding are out of scope; JSON parsing already resolves `\u` escapes.

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

## Stdio verification scope

For journal-enabled stdio captures, the wire log records what the tap received before relay, so an s2c entry does not prove the client received it; passive wrap retains post-write logging.

A clean stdio `gate` or `wrap --journal` capture can verify exit `0`: detector analysis and policy
candidates reproduce, and every client line has one intent plus one linked
delivery. `Gate.check_c2s` remains the only blocking authority. The journal
receives its actual verdict as `enforce`; it never calls HTTP `evaluate()` or
uses HTTP `strict_reason()` to classify stdio evidence. Plain wrap and internal
probe captures have no journal or live analysis and verify `2`
(`no_journal_for_path`), while retaining their unique header epochs.

Replay re-judges undeclared-tool candidates. A stdio `blocked` delivery with
`reason: gate_blocked` requires `candidate_block: true`, or a wire gate marker
whose `tool` is absent from its `declared` list and whose declared name set
matches a **completed declaration earlier in the same wire log**, folded by
`MCPTraceBuilder`/`SessionState` with the recorded session limits. This accepts
an honest race: the gate used an earlier surface, then a newer listing folded
before the blocked call was recorded. Orphaned replies, incomplete pagination,
future declarations and invented declared sets provide no historical proof.
A marker including its own blocked tool also provides no historical proof.
Without either justification, verification is contradicted, exit `1`, with
`stdio_undeclared_block_unproven`. Journal replay and all digest/linkage checks
still apply; this rule does not excuse a tampered candidate verdict.

Replay does **not** re-judge schema, PII, taint, depth, size, retries,
attestation, batch/admission refusals, strict faults, skipped/disabled checks,
or server-to-client quarantine actions. When present, the limit
`stdio_gate_reasons_not_replayed` lists their sorted distinct fixed reason codes
(and skipped, disabled, or quarantine action codes). An undeclared-tool refusal
alone does not add this limit. A PII block can verify `0` with
`reasons: ["pii_exfiltration"]`: the recorded decision and linkage hold, but
replay did not re-run the gate's PII check. Verification checks this limit against
the wire markers, preventing its silent omission or alteration.

`stdio_written` means bytes written to the server's stdin, with no response
implied. `stdio_write_failed` means delivery is unknown. Stdio intent and
delivery evidence levels come from `evidence.gate_level` on the recorded gate
marker, so an unmarked frame stays `observed`; use its delivery code for the
pipe-write outcome. Neither exit `0` nor a successful pipe write proves remote
execution, authorization, or that every stdio refusal was justified.

Missing intents produce `stdio_intent_missing` and exit `2`. Recorded observer
faults also prevent equivalence. Existing chain, exact-wire-digest, record-count
and final-record checks still reject unilateral tampering and tail deletion.
A deleted final delivery in an unbundled journal is detected through missing
intent/delivery linkage when bundled; the hash chain alone cannot detect an
unanchored final deletion.

The journal schema stays `/3`, policy `/2`, engine `/3`. Stdio profiles explicitly
record `transport: stdio`; missing transport continues to mean HTTP, preserving
existing HTTP `/3` profiles and acceptance fingerprints. Lossless stdio logging
remains out of scope: `stdio_decoded_text_no_raw_bytes` still applies.

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
For HTTP captures, public headers hash the upstream host as `host_sha256`,
retain the existing path digest and fixed scheme, and remove the port. The
manifest records `public_remote_host_hashed`.
These digests are unsalted: they keep peer-chosen or encoded bytes out of
the public tier, but anyone can confirm a guessed tool or host name by
hashing it. A public bundle is not anonymized.
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
