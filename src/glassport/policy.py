"""Pure policy decisions over trusted detector output; no transport operations.

Callers may inspect a decision without enforcing it. Neither the passive tap
nor the existing stdio gate invokes this module. An HTTP enforcer must still
provide session routing, delivery semantics, and persisted decision evidence.

PLAY-BY-PLAY
------------
This is the smallest file in the package and the one that decides whether
traffic lives or dies, so it does nothing else: no transports, no files,
no imports of either. `decide()` maps one event plus its annotations
onto one of three actions, and `Decision` records the reasoning so a
human can argue with it later.

The doctrine shows up as an asymmetry. Observation needs no
justification. Any real finding produces a warning, and a
missing-evidence observation stays visible as a warning instead of being
swallowed. Blocking is opt-in and shaped to one narrow case: a
severity-3 hallucination, subcategory ``fabricated_tool_call``, whose
``no_declaration_seen`` is explicitly False.

That last condition is the whole argument. False means a declaration
existed and the tool was not in it. None means no declaration was ever
observed, which proves nothing about the request, and None must not
block.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not enforce. Nothing here opens a connection, writes a frame, or
ends a session; a caller may read a decision and do nothing with it.
This file only says what it thinks, and says why.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from glassport.interaction_trace import Annotation, AnnotationKind


class Action(str, Enum):
    # PLAY: Str-valued so a decision serializes to plain JSON for the
    # journal without a custom encoder. Three values, no more: a fourth
    # would need a documented meaning for every consumer.
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Decision:
    # PLAY: Frozen so a recorded decision cannot be edited by a caller
    # that disagrees with it. annotation_ids is a tuple for the same
    # reason: no later append can widen what the decision cited.
    action: Action
    event_id: str
    annotation_ids: tuple[str, ...]
    reason: str


def _select_action(findings: tuple[Annotation, ...], block_fabricated: bool) -> Action:
    """Warn for severity 1+ and optionally block observed fabricated calls.

    Findings already belong to the current event and exclude informational
    records. Blocking must require severity 3, hallucination kind, subcategory
    fabricated_tool_call, and metadata no_declaration_seen explicitly False.
    Severity-1 warnings keep missing-evidence observations visible.
    """
    # PLAY: Four conditions, all required, and the last one is the point.
    # `is False` is not `is not True`: None means nobody ever saw a tool
    # declaration, so the wire never proved the call was outside the
    # surface. Absence of evidence cannot reach BLOCK here.
    if block_fabricated and any(
        a.severity == 3 and a.kind == AnnotationKind.HALLUCINATION
        and a.subcategory == "fabricated_tool_call"
        and a.metadata.get("no_declaration_seen") is False
        for a in findings
    ):
        return Action.BLOCK
    # PLAY: Severity-1 findings warn rather than pass silently. "I saw
    # something I could not finish checking" is exactly the observation
    # a reader should not have to go digging for.
    return Action.WARN if findings else Action.ALLOW


def decide(event_id: str, annotations: Iterable[Annotation], *,
           block_fabricated: bool = False) -> Decision:
    """Select an action for one event; observation is the default.

    Only positive-severity, non-INFO findings linked to this event participate.
    Pass engine-produced annotations, never peer-supplied purported findings.
    The optional blocking rule applies only to proved declared-surface
    divergence, not to all severity-3 findings. No traffic is changed here.
    """
    # PLAY: Both arguments are validated because both steer an outcome.
    # `type(x) is not bool` rather than a truthiness test: 1, "yes" and
    # a non-empty list all pass `if flag`, and none of them is a policy
    # decision somebody made on purpose.
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("policy requires a nonempty event id")
    if type(block_fabricated) is not bool:
        raise ValueError("block_fabricated must be a boolean")
    # PLAY: Only this event's findings count, INFO records are bookkeeping
    # and never a reason to act, and severity 0 is likewise not a reason.
    # A decision about one event must not be swayed by a neighbour's.
    findings = tuple(a for a in annotations if a.event_id == event_id
                     and a.kind != AnnotationKind.INFO and a.severity > 0)
    action = _select_action(findings, block_fabricated)
    # PLAY: The vocabulary is fixed per action so downstream code can key
    # on the string, and a reader can tell "nothing found" apart from
    # "something found, nothing blocked".
    reason = {
        Action.ALLOW: "no_actionable_findings",
        Action.WARN: "observed_findings",
        Action.BLOCK: "outside_observed_surface",
    }[action]
    # PLAY: Findings are cited by id, sorted and deduplicated, so the
    # decision is reproducible: the same inputs produce the same tuple in
    # the same order, which is what makes it safe to hash or journal.
    return Decision(action, event_id, tuple(sorted({a.id for a in findings})), reason)
