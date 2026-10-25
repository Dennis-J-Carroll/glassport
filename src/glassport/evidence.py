"""Closed evidence-level vocabulary for observed analysis and transport facts.

These labels describe what a capture proves. They do not grant authorization or
turn a locally sent request into proof of remote execution.

PLAY-BY-PLAY
------------
Every claim glassport makes about a frame wears one of these labels. They
form a ladder from "we saw bytes" to "somebody else confirmed the
result", and the set is closed on purpose: no caller invents a level,
and `LEVELS` is the entire vocabulary. A report that says "blocked"
without saying which kind of blocked has not said anything yet.

  observed             bytes were recorded. Nothing was judged.
  analyzed             a detector read them and produced output.
  intended_block       policy wanted to stop it; delivery is unproven.
  blocked_policy       a rule said stop.
  blocked_evidence_gap a required check could not run, so we stopped.
                       A different fact from a rule match, and usually
                       the more interesting one.
  blocked_admission    the frame never reached any check: unparseable,
                       nested too deep, or a batch.
  forwarded            handed to the transport. Still not proof the far
                       side executed anything.
  injected_locally     glassport itself wrote the bytes one peer sees,
                       so that peer's view is our view.
  externally_confirmed reserved. Nothing in this codebase emits it,
                       because nothing here can prove it.

Two reason tables split "we could not check" into its two causes.
`_ADMISSION_REASONS` means the frame never got far enough to be looked
at; `_GAP_REASONS` means a check ran and could not finish. Off by one
word, different fix: the first is a framing problem, the second is a
scanner problem.

Order of use: `gate_level()` when the tap wrote the marker,
`intent_level()` when a decision was recorded before delivery,
`delivery_level()` for the terminal transport fact, and
`annotation_level()` for a runtime finding. Each function has one job
and cross-references none of the others.

WHAT THIS FILE DOES NOT DO
--------------------------
It holds no state, reads nothing, and never upgrades a level on its own.
Every function maps a tap-owned marker to a name. Peer frame text is
never an input anywhere here.
"""
from __future__ import annotations

OBSERVED = "observed"
ANALYZED = "analyzed"
INTENDED_BLOCK = "intended_block"
BLOCKED_POLICY = "blocked_policy"
BLOCKED_EVIDENCE_GAP = "blocked_evidence_gap"
BLOCKED_ADMISSION = "blocked_admission"
FORWARDED = "forwarded"
INJECTED_LOCALLY = "injected_locally"
EXTERNALLY_CONFIRMED = "externally_confirmed"  # reserved; never emitted here

LEVELS = frozenset({OBSERVED, ANALYZED, INTENDED_BLOCK, BLOCKED_POLICY,
                    BLOCKED_EVIDENCE_GAP, BLOCKED_ADMISSION, FORWARDED,
                    INJECTED_LOCALLY,
                    EXTERNALLY_CONFIRMED})

_ADMISSION_REASONS = frozenset({
    "uninspectable_frame", "frame_too_deep", "batch_unsupported",
    "unencodable_reply",
})
_GAP_REASONS = frozenset({
    "no_surface_timeout", "gate_check_error", "resource_tracking_error",
    "attestation_unavailable", "attestation_check_error",
    "schema_scan_error", "pii_scan_error", "quarantine_scan_error",
    "surface_observe_error", "idempotency_check_error", "taint_scan_error",
})


def gate_level(gate: dict) -> str:
    """Classify one tap-owned stdio/HTTP gate marker, never peer frame text."""
    action = gate.get("action")
    reason = gate.get("reason")
    # PLAY: reason is coerced to None unless it is really a string. The
    # marker came from the tap, but the value inside it can still be
    # anything a bug or a crafted frame put there, and a container would
    # make the frozenset membership tests below lie about what happened.
    if not isinstance(reason, str):
        reason = None
    if action == "blocked":
        # PLAY: Read the blocked cases in this order. An admission
        # failure and a check fault both mean "we do not know", and both
        # must outrank the default BLOCKED_POLICY -- otherwise a frame
        # that was never inspected would be reported as though a rule
        # had convicted it.
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
    # PLAY: A replacement the tap synthesized is not the server talking.
    # Labelling it INJECTED_LOCALLY is what stops a reader from quoting
    # that text as evidence of what the server said.
    if action in ("injected", "quarantine_replacement"):
        return INJECTED_LOCALLY
    # PLAY: Fail-open has to be visible. When a check was skipped or the
    # gate was switched off, the frame still reached the far side, and
    # that is exactly what FORWARDED says -- no hint that it was vetted.
    if action in ("gate_skipped", "gate_disabled", "quarantine_scan_error"):
        return FORWARDED
    # PLAY: An unrecognized action earns the weakest label, never a
    # stronger one. New marker types are safe by default because this
    # branch under-claims.
    return OBSERVED


def intent_level(*, analyzed: bool, candidate_block: bool,
                 enforce: bool, strict_gap: bool) -> str:
    """An intent is recorded before delivery; an enforce verdict is not a block."""
    # PLAY: This is the subtle one. `enforce` means the pipeline decided
    # to stop the frame -- not that it managed to. The journal entry is
    # written first, so the level describes a decision at a moment in
    # time. Only delivery_level() gets to say what actually happened.
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
    # PLAY: A frame rejected for being malformed was never "blocked by a
    # rule"; it never became a message. ADMISSION keeps those two apart.
    if code in ("framing_rejected", "invalid_mcp_request"):
        return BLOCKED_ADMISSION
    # PLAY: The interesting combination: something decided to block and
    # the frame went out anyway. INTENDED_BLOCK records the disagreement
    # instead of letting either half overwrite the other.
    if candidate_action == "block" and outcome == "sent":
        return INTENDED_BLOCK
    if outcome == "sent":
        return FORWARDED
    return ANALYZED if analyzed else OBSERVED


def annotation_level(annotation, event=None) -> str:
    """Runtime finding: analysis only, unless tap-owned gate metadata proves more."""
    # PLAY: A detector's output is analysis, so ANALYZED is the default
    # and the only way out of it is the tap's own gate record. That keeps
    # "a detector matched some text" from ever reading as "it was blocked".
    subcategory = getattr(annotation, "subcategory", "")
    if not isinstance(subcategory, str):
        return ANALYZED
    if subcategory == "gate_blocked":
        gate = getattr(event, "metadata", {}).get("gate", {}) if event else {}
        return gate_level(gate) if isinstance(gate, dict) else OBSERVED
    return ANALYZED
