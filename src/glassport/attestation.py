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

import time
from dataclasses import dataclass, field

ATTESTATION_KEY = "com.glassport/attestation"


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
    import base64
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
            base64.b64decode(pubkey_b64))
        pubkey.verify(base64.b64decode(sig_b64), payload)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
