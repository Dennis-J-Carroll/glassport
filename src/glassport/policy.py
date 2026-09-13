"""Pure policy decisions over trusted detector output; no transport operations.

Callers may inspect a decision without enforcing it. Neither the passive tap
nor the existing stdio gate invokes this module. An HTTP enforcer must still
provide session routing, delivery semantics, and persisted decision evidence.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from glassport.interaction_trace import Annotation, AnnotationKind


class Action(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class Decision:
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
    if block_fabricated and any(
        a.severity == 3 and a.kind == AnnotationKind.HALLUCINATION
        and a.subcategory == "fabricated_tool_call"
        and a.metadata.get("no_declaration_seen") is False
        for a in findings
    ):
        return Action.BLOCK
    return Action.WARN if findings else Action.ALLOW


def decide(event_id: str, annotations: Iterable[Annotation], *,
           block_fabricated: bool = False) -> Decision:
    """Select an action for one event; observation is the default.

    Only positive-severity, non-INFO findings linked to this event participate.
    Pass engine-produced annotations, never peer-supplied purported findings.
    The optional blocking rule applies only to proved declared-surface
    divergence, not to all severity-3 findings. No traffic is changed here.
    """
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("policy requires a nonempty event id")
    if type(block_fabricated) is not bool:
        raise ValueError("block_fabricated must be a boolean")
    findings = tuple(a for a in annotations if a.event_id == event_id
                     and a.kind != AnnotationKind.INFO and a.severity > 0)
    action = _select_action(findings, block_fabricated)
    reason = {
        Action.ALLOW: "no_actionable_findings",
        Action.WARN: "observed_findings",
        Action.BLOCK: "outside_observed_surface",
    }[action]
    return Decision(action, event_id, tuple(sorted({a.id for a in findings})), reason)
