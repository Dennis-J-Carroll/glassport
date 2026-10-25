"""Closed evidence-level vocabulary for observed analysis and transport facts.

These labels describe what a capture proves. They do not grant authorization or
turn a locally sent request into proof of remote execution.
"""
from __future__ import annotations

OBSERVED = "observed"
ANALYZED = "analyzed"
INTENDED_BLOCK = "intended_block"
BLOCKED_POLICY = "blocked_policy"
BLOCKED_EVIDENCE_GAP = "blocked_evidence_gap"
BLOCKED_ADMISSION = "blocked_admission"
FORWARDED = "forwarded"
EXTERNALLY_CONFIRMED = "externally_confirmed"  # reserved; never emitted here

LEVELS = frozenset({OBSERVED, ANALYZED, INTENDED_BLOCK, BLOCKED_POLICY,
                    BLOCKED_EVIDENCE_GAP, BLOCKED_ADMISSION, FORWARDED,
                    EXTERNALLY_CONFIRMED})

_ADMISSION_REASONS = frozenset({
    "uninspectable_frame", "frame_too_deep", "batch_unsupported",
})
_GAP_REASONS = frozenset({
    "no_surface_timeout", "gate_check_error", "resource_tracking_error",
    "attestation_unavailable", "attestation_check_error",
    "schema_scan_error", "pii_scan_error", "quarantine_scan_error",
    "surface_observe_error",
})


def gate_level(gate: dict) -> str:
    """Classify one tap-owned stdio/HTTP gate marker, never peer frame text."""
    action = gate.get("action")
    reason = gate.get("reason")
    if not isinstance(reason, str):
        reason = None
    if action == "blocked":
        if reason in _ADMISSION_REASONS:
            return BLOCKED_ADMISSION
        if reason in _GAP_REASONS:
            return BLOCKED_EVIDENCE_GAP
        return BLOCKED_POLICY
    if action in ("quarantine_dropped", "quarantine_withheld"):
        return (BLOCKED_EVIDENCE_GAP if reason == "quarantine_scan_error"
                else BLOCKED_ADMISSION if reason in _ADMISSION_REASONS
                else BLOCKED_POLICY)
    if action == "quarantined":
        return BLOCKED_POLICY  # original server frame was not delivered
    if action in ("injected", "quarantine_replacement", "gate_skipped",
                  "gate_disabled", "quarantine_scan_error"):
        return FORWARDED
    return OBSERVED


def intent_level(*, analyzed: bool, candidate_block: bool,
                 enforce: bool, strict_gap: bool) -> str:
    """An intent is recorded before delivery; an enforce verdict is not a block."""
    if enforce:
        return BLOCKED_EVIDENCE_GAP if strict_gap else BLOCKED_POLICY
    if candidate_block:
        return INTENDED_BLOCK
    return ANALYZED if analyzed else OBSERVED


def delivery_level(*, outcome: str, code: str, candidate_action: str,
                   analyzed: bool) -> str:
    """Classify terminal transport fact without inferring remote execution."""
    if outcome == "blocked":
        return (BLOCKED_EVIDENCE_GAP if code == "http_gate_strict_blocked"
                else BLOCKED_POLICY)
    if code in ("framing_rejected", "invalid_mcp_request"):
        return BLOCKED_ADMISSION
    if candidate_action == "block" and outcome == "sent":
        return INTENDED_BLOCK
    if outcome == "sent":
        return FORWARDED
    return ANALYZED if analyzed else OBSERVED


def annotation_level(annotation, event=None) -> str:
    """Runtime finding: analysis only, unless tap-owned gate metadata proves more."""
    subcategory = getattr(annotation, "subcategory", "")
    if not isinstance(subcategory, str):
        return ANALYZED
    if subcategory == "gate_blocked":
        gate = getattr(event, "metadata", {}).get("gate", {}) if event else {}
        return gate_level(gate) if isinstance(gate, dict) else OBSERVED
    if subcategory.startswith("gate_"):
        gate = getattr(event, "metadata", {}).get("gate", {}) if event else {}
        return gate_level(gate) if isinstance(gate, dict) else OBSERVED
    return ANALYZED
