"""
attestation.py — structural checks for glassport's own _meta identity
extension. See docs/attestation.md for why this is a glassport extension
and not enforcement of a real MCP mechanism.

Detect-only by design: no real client populates this key today, so
enforcing its presence would break every live session. See Task 13 for
the optional, explicitly-opt-in enforcement path.

PLAY-BY-PLAY
------------
Attestation asks a question the MCP spec does not answer: was this
particular request assembled by the party it claims to come from? No
client sends that today, so this file is careful about what it is
allowed to conclude.

The three checks run at three different levels of certainty:

1. `signing_payload()` decides what bytes a signature would cover. The
   canonical form is the security property, not a formatting chore.
2. `check_meta()` inspects shape alone: is the key present, does it
   have the fields, is it expired. It never touches crypto.
3. `verify_signature()` is the only function that can prove anything,
   and it needs the optional `cryptography` extra. Without it the
   answer is None.

That None is a contract, and a strict one. None means "could not
check". False means "checked and it failed". A caller that treats None
as a failure will reject traffic it merely could not inspect, so the
three-valued answer is deliberate rather than sloppy.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not require the extension, does not enforce anything, and does
not ship a crypto implementation. Every function here accepts
attacker-controlled input and none of them raises.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field

ATTESTATION_KEY = "com.glassport/attestation"


def signing_payload(params: dict) -> bytes:
    """Canonical bytes signed by the vendor extension, excluding only sig.

    Copy the containing objects so signing never mutates the caller's frame.
    Keep every other parameter, including the algorithm, expiry, arguments,
    and other metadata, in the signed payload. Use sorted, compact JSON with
    ASCII escapes and reject non-finite numbers. Callers sign these bytes
    before inserting the base64 signature into the attestation object.
    """
    # PLAY: This is the one function here that does raise, because it is
    # also the one that runs before bytes are signed: a payload built
    # from the wrong shape must fail here, not produce a signature over
    # something ambiguous.
    if not isinstance(params, dict):
        raise ValueError("attestation parameters must be an object")
    meta = params.get("_meta")
    if not isinstance(meta, dict) or not isinstance(meta.get(ATTESTATION_KEY), dict):
        raise ValueError("attestation metadata must contain an object")
    # PLAY: Shallow copies at two levels, then rebuild. Signing must not
    # mutate the caller's frame, and popping sig out of the original
    # would do exactly that.
    att = dict(meta[ATTESTATION_KEY])
    att.pop("sig", None)
    unsigned = {**params, "_meta": {**meta, ATTESTATION_KEY: att}}
    # PLAY: Every keyword is load-bearing. sort_keys makes key order
    # canonical; separators remove whitespace; ensure_ascii fixes the
    # escape spelling; allow_nan=False refuses NaN and Infinity, which
    # have no single JSON form and would make the signed bytes differ
    # between implementations while describing the same value.
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def validate_public_key(pubkey_b64: str | None) -> None:
    """Reject unusable enforcement configuration, without requiring crypto."""
    # PLAY: Validation without cryptography: a 32-byte blob in strict
    # base64 is what an Ed25519 public key is, so bad configuration is
    # rejected at startup instead of at the first request. validate=True
    # makes b64decode reject stray characters rather than skipping them.
    if not isinstance(pubkey_b64, str) or not pubkey_b64:
        raise ValueError("attestation enforcement requires a base64 Ed25519 public key")
    try:
        key = base64.b64decode(pubkey_b64, validate=True)
    except ValueError as exc:
        raise ValueError("attestation public key must be valid base64") from exc
    if len(key) != 32:
        raise ValueError("attestation public key must decode to 32 bytes")


@dataclass
class AttestationResult:
    present: bool
    well_formed: bool = False
    expired: bool = False
    problems: list[str] = field(default_factory=list)


def check_meta(meta: dict | None) -> AttestationResult:
    """Structural-only check: presence, shape, expiry. Never verifies a
    signature (no crypto dependency here — see Task 13's optional
    extra). Never raises: _meta is attacker-controlled wire content."""
    if not isinstance(meta, dict) or ATTESTATION_KEY not in meta:
        return AttestationResult(present=False)

    att = meta.get(ATTESTATION_KEY)
    if not isinstance(att, dict):
        return AttestationResult(present=True, well_formed=False,
                                  problems=["attestation value is not an object"])

    # PLAY: Structural facts only, collected rather than raised. All
    # three problems are gathered so an operator sees every field that
    # is wrong in one pass instead of fixing them one restart at a time.
    problems: list[str] = []
    alg = att.get("alg")
    sig = att.get("sig")
    expires_at = att.get("expires_at")

    if alg != "ed25519":
        problems.append(f"unsupported or missing alg: {alg!r}")
    if not isinstance(sig, str) or not sig:
        problems.append("missing or non-string sig")
    if not isinstance(expires_at, int):
        problems.append("missing or non-integer expires_at")

    # PLAY: well_formed is computed before expiry is examined, so the
    # two questions stay separate: a correctly shaped attestation that
    # has run out is well formed AND expired, not malformed.
    well_formed = not problems
    expired = False
    if isinstance(expires_at, int):
        expired = expires_at < int(time.time())
        if expired:
            problems.append(f"attestation expired at {expires_at}")

    return AttestationResult(present=True, well_formed=well_formed,
                              expired=expired, problems=problems)


# PLAY: The optional dependency, imported defensively. Runtime installs
# are zero-dependency by design; the `attestation` extra exists only for
# callers who want verification, and everything above works without it.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey)
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def verify_signature(payload: bytes, sig_b64: str, pubkey_b64: str
                      ) -> bool | None:
    """True/False when the `cryptography` extra is installed and the
    inputs are well-formed; None when the extra is absent — the caller
    must treat None as "could not check," never as "failed check."
    Never raises: both inputs are attacker-controlled wire content."""
    if not HAS_CRYPTO:
        return None
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(pubkey_b64, validate=True))
        pubkey.verify(base64.b64decode(sig_b64, validate=True), payload)
        return True
    # PLAY: The tuple lists InvalidSignature and ValueError for the
    # reader, but Exception is what does the work: every input here came
    # off the wire, and any failure at all means "not verified". A
    # narrower catch would risk raising out of a check that promised
    # never to raise.
    except (InvalidSignature, ValueError, Exception):
        return False
