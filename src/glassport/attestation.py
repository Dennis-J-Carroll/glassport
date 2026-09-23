"""
attestation.py — structural checks for glassport's own _meta identity
extension. See docs/superpowers/plans/2026-09-22-security-hardening-
outline/APPENDIX.md §5 for why this is a glassport extension and not
enforcement of a real MCP mechanism.

Detect-only by design: no real client populates this key today, so
enforcing its presence would break every live session. See Task 13 for
the optional, explicitly-opt-in enforcement path.
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
    if not isinstance(params, dict):
        raise ValueError("attestation parameters must be an object")
    meta = params.get("_meta")
    if not isinstance(meta, dict) or not isinstance(meta.get(ATTESTATION_KEY), dict):
        raise ValueError("attestation metadata must contain an object")
    att = dict(meta[ATTESTATION_KEY])
    att.pop("sig", None)
    unsigned = {**params, "_meta": {**meta, ATTESTATION_KEY: att}}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def validate_public_key(pubkey_b64: str | None) -> None:
    """Reject unusable enforcement configuration, without requiring crypto."""
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

    well_formed = not problems
    expired = False
    if isinstance(expires_at, int):
        expired = expires_at < int(time.time())
        if expired:
            problems.append(f"attestation expired at {expires_at}")

    return AttestationResult(present=True, well_formed=well_formed,
                              expired=expired, problems=problems)


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
    except (InvalidSignature, ValueError, Exception):
        return False
