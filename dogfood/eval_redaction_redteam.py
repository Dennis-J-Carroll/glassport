#!/usr/bin/env python3
"""Redaction red-team grill — beat the span-aware redaction floor.

Run from repo root:
    PYTHONPATH=src python dogfood/eval_redaction_redteam.py

Self-exits with nonzero status if any case fails.
"""
from __future__ import annotations

import sys
from typing import Callable

from glassport.audit import Finding, Report
from glassport.provenance import ProvenanceFinding
from glassport import sarif
from glassport import detectors


CASES: list[tuple[str, Callable[[], tuple[bool, str]]]] = []


def _report(findings=None, provenance=None, **kw):
    return Report(
        profile={"name": "demo"},
        findings=findings or [],
        deductions=[],
        score=50,
        grade="F",
        provenance=provenance or [],
        **kw
    )


def _live_secret():
    return "sk-ant-api03-" + "A" * 40 + "1234567890"


def _leaks(artifact: str, secret: str) -> bool:
    return secret in detectors._normalize_for_scan(artifact)


# ═══════════════════════════════════════════════════════════════════════════
# P-lead — suspected unredacted hostile provenance field in SARIF
# ═══════════════════════════════════════════════════════════════════════════
def p_lead():
    """A live-shaped secret in pf.package reaches SARIF message.text and
    properties.package because sarif.py:155 omits redact_secrets_strict."""
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry",
        severity="high",
        ecosystem="npm",
        package=secret,  # attacker-controlled manifest-supplied package name
        manifest="package.json",
        detail="declared dependency not found in the npm registry",
    )
    doc = sarif.render_sarif(_report(provenance=[pf]))
    if _leaks(doc, secret):
        return False, (
            "P-lead CONFIRMED: secret leaks via pf.package; "
            "exact fields: message.text, properties.package"
        )
    return True, "P-lead green: pf.package is redacted in SARIF"


CASES.append(("P-lead: provenance package secret leaks to SARIF", p_lead))


# ═══════════════════════════════════════════════════════════════════════════
# P-lead sweep: adjacent provenance fields bypass redact_secrets_strict
# (defensive gaps — not attacker-reachable in current code, but should be
# hardened by the same fix).
# ═══════════════════════════════════════════════════════════════════════════
def p_lead_ecosystem():
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry",
        severity="high",
        ecosystem=secret,
        package="safe-pkg",
        manifest="package.json",
        detail="declared dependency not found",
    )
    doc = sarif.render_sarif(_report(provenance=[pf]))
    if _leaks(doc, secret):
        return False, "P-lead sweep: pf.ecosystem bypasses redaction (defensive gap)"
    return True, "P-lead ecosystem green"


CASES.append(("P-lead sweep: provenance ecosystem secret leaks", p_lead_ecosystem))


def p_lead_detail():
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry",
        severity="high",
        ecosystem="npm",
        package="safe-pkg",
        manifest="package.json",
        detail=f"detail contains {secret}",
    )
    doc = sarif.render_sarif(_report(provenance=[pf]))
    if _leaks(doc, secret):
        return False, "P-lead sweep: pf.detail bypasses redaction (defensive gap)"
    return True, "P-lead detail green"


CASES.append(("P-lead sweep: provenance detail secret leaks", p_lead_detail))


def p_lead_rule_id():
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule=secret,
        severity="high",
        ecosystem="npm",
        package="safe-pkg",
        manifest="package.json",
        detail="declared dependency not found",
    )
    doc = sarif.render_sarif(_report(provenance=[pf]))
    if _leaks(doc, secret):
        return False, "P-lead sweep: pf.rule leaks to SARIF rule name/shortDescription (defensive gap)"
    return True, "P-lead rule id green"


CASES.append(("P-lead sweep: provenance rule id secret leaks", p_lead_rule_id))


# ═══════════════════════════════════════════════════════════════════════════
# P1 — backstop fragment-miss siblings
# ═══════════════════════════════════════════════════════════════════════════
def p1_nested_overlapping():
    """A generic_api_key value nested inside an anthropic_key span; union-merge
    must redact the whole range and the backstop must not see a survivor."""
    secret = _live_secret()
    text = f'api_key = "{secret}"'
    out = detectors.redact_secrets_strict(text)
    if _leaks(out, secret):
        return False, "P1 CONFIRMED: nested/overlapping span leaves reconstructable secret"
    return True, "P1 nested/overlapping green"


CASES.append(("P1: nested/overlapping span fragment miss", p1_nested_overlapping))


def p1_adjacent_secrets():
    """Two adjacent secrets; union-merge should not drop bytes between them."""
    secret = _live_secret()
    text = f"{secret} {secret}"
    out = detectors.redact_secrets_strict(text)
    if _leaks(out, secret):
        return False, "P1 CONFIRMED: adjacent secrets leave a fragment"
    return True, "P1 adjacent secrets green"


CASES.append(("P1: adjacent secrets fragment miss", p1_adjacent_secrets))


def p1_placeholder_concat():
    """A redaction placeholder concatenated with surviving text must not
    reconstruct a secret pattern."""
    secret = _live_secret()
    # Prefix that, if concatenated with a placeholder, could look like a secret
    text = f"sk-ant-api03-[placeholder]{secret[13:]}"
    out = detectors.redact_secrets_strict(text)
    if _leaks(out, secret):
        return False, "P1 CONFIRMED: placeholder concatenation reconstructs secret"
    return True, "P1 placeholder concatenation green"


CASES.append(("P1: placeholder concatenation reconstructs secret", p1_placeholder_concat))


# ═══════════════════════════════════════════════════════════════════════════
# P2 — origin-map drift under cross-char NFKC
# ═══════════════════════════════════════════════════════════════════════════
def p2_homoglyph_obfuscation():
    """Cyrillic homoglyphs must map back to the original source range and be
    fully redacted."""
    secret = _live_secret()
    obf = secret.replace("a", "а")
    out = detectors.redact_secrets_strict(obf)
    if _leaks(out, secret):
        return False, "P2 CONFIRMED: homoglyph origin-map drift leaks secret"
    return True, "P2 homoglyph origin-map green"


CASES.append(("P2: homoglyph origin-map drift", p2_homoglyph_obfuscation))


def p2_fullwidth_obfuscation():
    secret = _live_secret()
    obf = secret.translate({ord(c): ord(c) + 0xFEE0 for c in secret if "!" <= c <= "~"})
    out = detectors.redact_secrets_strict(obf)
    if _leaks(out, secret):
        return False, "P2 CONFIRMED: fullwidth origin-map drift leaks secret"
    return True, "P2 fullwidth origin-map green"


CASES.append(("P2: fullwidth origin-map drift", p2_fullwidth_obfuscation))


# ═══════════════════════════════════════════════════════════════════════════
# P4 — any OTHER artifact field that bypasses redact_secrets_strict entirely
# ═══════════════════════════════════════════════════════════════════════════
def p4_static_finding_path():
    secret = _live_secret()
    f = Finding("tool-poisoning", "critical",
                f"src/{secret}/planted.py", 3, "directive text found")
    doc = sarif.render_sarif(_report(findings=[f]))
    if _leaks(doc, secret):
        return False, "P4 CONFIRMED: static Finding.path leaks to SARIF"
    return True, "P4 static path green"


CASES.append(("P4: static finding path bypass", p4_static_finding_path))


def p4_static_finding_detail():
    secret = _live_secret()
    f = Finding("tool-poisoning", "critical", "app.py", 1,
                f"directive text: {secret}")
    doc = sarif.render_sarif(_report(findings=[f]))
    if _leaks(doc, secret):
        return False, "P4 CONFIRMED: static Finding.detail leaks to SARIF"
    return True, "P4 static detail green"


CASES.append(("P4: static finding detail bypass", p4_static_finding_detail))


def p4_runtime_message():
    """Runtime session SARIF messages are redacted; build the smallest fake
    annotation and drive render_session_sarif."""
    from glassport.interaction_trace import (
        InteractionTrace, Actor, ActorKind, ProtocolKind,
        Event, EventKind, Part, PartKind,
        Annotation, AnnotationKind,
    )
    secret = _live_secret()
    trace = InteractionTrace(
        id="t1",
        protocol=ProtocolKind.AGENT_TOOL,
        actors=[
            Actor(id="a1", kind=ActorKind.AGENT, name="agent"),
            Actor(id="s1", kind=ActorKind.EXTERNAL, name="server"),
        ],
        events=[Event(
            id="e1", timestamp="2026-07-12T00:00:00Z",
            actor_id="a1",
            kind=EventKind.MESSAGE,
            parts=[Part(kind=PartKind.TEXT, content="hello")],
            metadata={"method": "test", "seq": 1})],
        annotations=[Annotation(
            id="ann1", event_id="e1", kind=AnnotationKind.ANOMALY,
            subcategory="fabricated_tool_call", severity=3,
            explanation=f"tool call {secret}")],
        metadata={},
    )
    doc = sarif.render_session_sarif(trace, session_path="session.jsonl")
    if _leaks(doc, secret):
        return False, "P4 CONFIRMED: runtime annotation explanation leaks to SARIF"
    return True, "P4 runtime message green"


CASES.append(("P4: runtime session SARIF message bypass", p4_runtime_message))


# ═══════════════════════════════════════════════════════════════════════════
# P5 — structural suppression swallowing a real secret
# ═══════════════════════════════════════════════════════════════════════════
def p5_jwt_wraps_secret():
    """A JWT structural container that encloses a real generic secret must be
    redacted as a whole; the inner secret must not leak because suppression
    dropped it from the span set."""
    import base64
    import json

    secret = _live_secret()
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"key": secret}).encode()).rstrip(b"=")
    jwt = f"{header.decode()}.{payload.decode()}.{'s'*15}"
    out = detectors.redact_secrets_strict(jwt)
    if _leaks(out, secret):
        return False, "P5 CONFIRMED: JWT structural suppression leaks inner secret"
    return True, "P5 JWT-wrapped secret green"


CASES.append(("P5: JWT structural suppression leaks inner secret", p5_jwt_wraps_secret))


# ═══════════════════════════════════════════════════════════════════════════
# P6 — custom-pattern registry cannot reduce built-in redaction
# ═══════════════════════════════════════════════════════════════════════════
def p6_custom_pattern_does_not_shrink_builtin():
    """A consumer custom pattern overlapping a built-in secret must not shift
    the union-merge so the built-in span is corrupted."""
    secret = _live_secret()
    # Register an overly broad custom pattern that also covers the secret.
    from glassport.detectors import register_pii_pattern, PIIPattern, clear_custom_pii_patterns
    import re

    register_pii_pattern(PIIPattern(
        "custom_overlap", 2,
        re.compile(r"(sk-ant-api03-[A-Za-z0-9_-]{10,50})"),
        None, "overlapping custom pattern"))
    try:
        out = detectors.redact_secrets_strict(secret)
        if _leaks(out, secret):
            return False, "P6 CONFIRMED: custom pattern reduced built-in redaction"
        return True, "P6 custom pattern overlap green"
    finally:
        clear_custom_pii_patterns()


CASES.append(("P6: custom pattern overlap shrinks built-in redaction", p6_custom_pattern_does_not_shrink_builtin))


# ═══════════════════════════════════════════════════════════════════════════
# P7 — false withhold of clean evidence
# ═══════════════════════════════════════════════════════════════════════════
def p7_benign_text_not_withheld():
    """Clean prose must not trip the fail-closed backstop."""
    text = (
        "This is a benign explanation of a tool-poisoning directive. "
        "It contains no credentials, no API keys, and no tokens."
    )
    out = detectors.redact_secrets_strict(text)
    if out == detectors._WITHHELD:
        return False, "P7 CONFIRMED: benign text was withheld"
    return True, "P7 benign text green"


CASES.append(("P7: benign text falsely withheld", p7_benign_text_not_withheld))


def p7_redaction_tag_not_secret():
    """A literal redaction tag must not be mistaken for a secret and trigger
    the backstop."""
    text = "[anthropic_key redacted · 63 chars]"
    out = detectors.redact_secrets_strict(text)
    if out == detectors._WITHHELD:
        return False, "P7 CONFIRMED: literal redaction tag triggered withhold"
    return True, "P7 literal tag green"


CASES.append(("P7: literal redaction tag triggers withhold", p7_redaction_tag_not_secret))


# ═══════════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════════
def main() -> int:
    fails = []
    for name, fn in CASES:
        ok, detail = fn()
        status = "PASS" if ok else "FAIL"
        print(f"{status}: {name} — {detail}")
        if not ok:
            fails.append(name)
    print(f"\n{len(CASES) - len(fails)}/{len(CASES)} passed")
    if fails:
        print("FAILURES:", ", ".join(fails))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
