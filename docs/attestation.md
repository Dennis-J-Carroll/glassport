# Optional caller attestation

Glassport's `com.glassport/attestation` field is a vendor extension inside
`params._meta`. It is not a standard MCP authentication mechanism. Enforcement
is off by default and currently configured through the Python `Gate` API.

## Signing format

Build the tool-call `params` object, including the tool `name`, `arguments`, and
`_meta["com.glassport/attestation"]` containing `alg: "ed25519"` and an integer
Unix-seconds `expires_at`. Call `glassport.attestation.signing_payload(params)`
to obtain the bytes to sign, then put the base64-encoded Ed25519 signature in
that attestation object's `sig` field.

The helper removes only `sig`, retains all other parameters and metadata,
sorts JSON object keys, uses compact separators, emits ASCII escapes, rejects
non-finite numbers, and encodes the result as UTF-8. It does not mutate the
input. The Gate uses the same helper. This serialization is specific to this
extension, not a claim of general JSON canonicalization across languages.

## Gate configuration and failure behavior

```python
from glassport.tap import Gate

gate = Gate(enforce_attestation=True, attestation_pubkey_b64=public_key_b64)
```

Enabling enforcement requires strict base64 decoding to a 32-byte Ed25519
public key. Missing or malformed configuration raises `ValueError` before
relay processing. The optional `glassport[attestation]` extra provides actual
signature verification; it is never a required runtime dependency.

Missing, malformed, expired, or invalid attestations are blocked with the
existing JSON-RPC error code `-32000` and `error.data.reason` set to
`attestation_failed`, subject to the existing enforcement override. A call
whose parameters cannot be serialized into the signing payload (for example
`NaN`/`Infinity`, which `json` accepts on input but the payload rejects, or
excessive nesting) is treated as an invalid attestation and blocked the same
way; the caller controls that input, so it must not open a bypass.

When crypto is unavailable, verification is skipped, and the other boundary
checks still run. If forwarded, the frame is logged with `gate_skipped` and
reason `attestation_unavailable`. An unexpected attestation-check exception
forwards the original frame with reason `attestation_check_error`, consistent
with Glassport's fail-open relay contract, after the remaining idempotency,
taint, schema, and PII checks have run; any of those can still block the call.
Neither marker means authenticated.

With the opt-in strict fault policy (`Gate(strict=True)`, CLI
`glassport gate --strict`), both markers become blocks instead: the call is
refused with `-32000` and `error.data.reason` set to `attestation_unavailable`
or `attestation_check_error`. Enforcement also no longer depends on a
declared tool surface: if no `tools/list` arrives within the hold window,
attestation (and the credential and taint checks) still run on the call.
