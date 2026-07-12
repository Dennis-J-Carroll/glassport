#!/usr/bin/env python3
"""Redaction red-team grill — beat the span-aware redaction floor.

Run from repo root:
    PYTHONPATH=src python dogfood/eval_redaction_redteam.py

Self-exits with nonzero status if any case fails.
"""
from __future__ import annotations

import json
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
# PR #63 fix-specific attacks — try to break the provenance redaction patch
# ═══════════════════════════════════════════════════════════════════════════
def _prov_doc(package="safe-pkg", detail="detail", manifest="package.json",
              rule="prov-not-in-registry", ecosystem="npm"):
    pf = ProvenanceFinding(
        rule=rule, severity="high", ecosystem=ecosystem,
        package=package, manifest=manifest, detail=detail)
    return sarif.render_sarif(_report(provenance=[pf]))


def _fields_leak(doc: str, secret: str) -> dict[str, bool]:
    d = json.loads(doc)
    res = d["runs"][0]["results"][0]
    msg = res["message"]["text"]
    prop_pkg = res["properties"]["package"]
    return {
        "message.text": secret in msg,
        "properties.package": secret in prop_pkg,
        "normalized_artifact": _leaks(doc, secret),
    }


def fix_obf_zwj_package():
    secret = _live_secret()
    obf = "sk-ant-api03-" + "\u200d" + "A" * 40 + "1234567890"
    doc = _prov_doc(package=obf)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"ZWJ obf leaks: {leaks}"
    return True, "ZWJ obfuscation green"


CASES.append(("FIX: ZWJ-obfuscated secret in package", fix_obf_zwj_package))


def fix_obf_fullwidth_package():
    secret = _live_secret()
    obf = secret.translate({ord(c): ord(c) + 0xFEE0 for c in secret if "!" <= c <= "~"})
    doc = _prov_doc(package=obf)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"fullwidth obf leaks: {leaks}"
    return True, "fullwidth obfuscation green"


CASES.append(("FIX: fullwidth-obfuscated secret in package", fix_obf_fullwidth_package))


def fix_obf_cyrillic_package():
    secret = _live_secret()
    obf = secret.replace("a", "а").replace("A", "А")
    doc = _prov_doc(package=obf)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"Cyrillic obf leaks: {leaks}"
    return True, "Cyrillic homoglyph obfuscation green"


CASES.append(("FIX: Cyrillic-homoglyph secret in package", fix_obf_cyrillic_package))


def fix_obf_bidi_package():
    secret = _live_secret()
    obf = "\u202e" + secret + "\u202c"
    doc = _prov_doc(package=obf)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"bidi obf leaks: {leaks}"
    return True, "bidi override obfuscation green"


CASES.append(("FIX: bidi-override-wrapped secret in package", fix_obf_bidi_package))


def fix_obf_combining_package():
    secret = _live_secret()
    obf = "".join(c + "\u0332" for c in secret)  # underline each char
    doc = _prov_doc(package=obf)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"combining-mark obf leaks: {leaks}"
    return True, "combining-mark obfuscation green"


CASES.append(("FIX: combining-mark secret in package", fix_obf_combining_package))


def fix_obf_smallcap_package():
    """Latin small-capital A is not NFKC-folded or confusable-mapped, so the
    obfuscated shape survives even though the plain secret does not."""
    secret = _live_secret()
    obf = secret.replace("A", "\u1D00")
    doc = _prov_doc(package=obf)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"small-cap obf leaks PLAIN secret: {leaks}"
    return True, "small-capital-A obfuscation: plain secret absent (obfuscated shape survives)"


CASES.append(("FIX: small-capital-A obfuscated secret in package", fix_obf_smallcap_package))


def fix_manifest_obfuscated_path():
    secret = _live_secret()
    manifest = f"src/{secret.replace('a', 'а')}/package.json"
    doc = _prov_doc(manifest=manifest)
    if _leaks(doc, secret):
        return False, "obfuscated manifest path leaks plain secret"
    return True, "manifest URI redaction obfuscation-proof green"


CASES.append(("FIX: obfuscated secret in manifest path", fix_manifest_obfuscated_path))


def fix_composed_message_boundary():
    """Split the secret so one half is in package and the other in detail.
    The hardcoded separators ': ' and ' — ' must break pattern contiguity."""
    secret = _live_secret()
    pkg = secret[:23]      # "sk-ant-api03-" + 10 A's  (too short alone)
    detail = secret[23:]   # remaining A's + digits
    doc = _prov_doc(package=pkg, detail=detail)
    leaks = _fields_leak(doc, secret)
    if any(leaks.values()):
        return False, f"split secret reconstructs across join: {leaks}"
    return True, "composed-message boundary green"


CASES.append(("FIX: secret split across package/detail boundary", fix_composed_message_boundary))


def fix_unknown_rule_validation():
    secret = _live_secret()
    doc = _prov_doc(rule=secret)
    d = json.loads(doc)
    res = d["runs"][0]["results"][0]
    rules = {r["id"]: r for r in d["runs"][0]["tool"]["driver"]["rules"]}
    if res["ruleId"] not in rules:
        return False, "dangling ruleId for unknown rule"
    if secret in json.dumps(rules[res["ruleId"]]):
        return False, "secret-shaped rule value reached rules table"
    if secret in res["message"]["text"] or secret in res["properties"].get("package", ""):
        return False, "secret leaked via unknown rule handling"
    return True, "unknown rule collapses to safe sentinel green"


CASES.append(("FIX: secret-shaped unknown rule id", fix_unknown_rule_validation))


def fix_unknown_ecosystem_validation():
    secret = _live_secret()
    doc = _prov_doc(ecosystem=secret)
    d = json.loads(doc)
    res = d["runs"][0]["results"][0]
    if res["properties"]["ecosystem"] != "unknown":
        return False, f"unknown ecosystem not collapsed: {res['properties']['ecosystem']}"
    if secret in res["message"]["text"]:
        return False, "secret-shaped ecosystem leaked to message"
    return True, "unknown ecosystem collapses to 'unknown' green"


CASES.append(("FIX: secret-shaped unknown ecosystem", fix_unknown_ecosystem_validation))


def fix_scan_failure_totality():
    """If the strict scanner raises, the field must be withheld and render_sarif
    must not propagate the exception."""
    from unittest import mock
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package=secret, manifest="package.json", detail="detail")
    report = _report(provenance=[pf])
    with mock.patch.object(detectors, "_scan_pii", side_effect=RuntimeError("boom")):
        try:
            doc = sarif.render_sarif(report)
        except Exception as exc:
            return False, f"render_sarif crashed on scan failure: {exc}"
    if secret in doc:
        return False, "secret emitted raw despite scan failure"
    if detectors._WITHHELD not in doc:
        return False, "scan failure did not produce _WITHHELD placeholder"
    return True, "scan failure fail-closed green"


CASES.append(("FIX: scan failure withholds and does not crash", fix_scan_failure_totality))


def fix_structural_consistency():
    pfs = [
        ProvenanceFinding("prov-not-in-registry", "high", "npm", "pkg1", "m1.json", "d1"),
        ProvenanceFinding("prov-not-in-registry", "high", "pypi", "pkg2", "m2.json", "d2"),
        ProvenanceFinding("prov-deprecated", "medium", "npm", "pkg3", "m3.json", "d3"),
        ProvenanceFinding("this-is-not-a-rule", "low", "not-an-eco", "pkg4", "m4.json", "d4"),
    ]
    doc = sarif.render_sarif(_report(provenance=pfs))
    d = json.loads(doc)
    if d.get("version") != "2.1.0":
        return False, "SARIF version missing"
    if len(d.get("runs", [])) != 1:
        return False, "unexpected run count"
    rules = d["runs"][0]["tool"]["driver"]["rules"]
    results = d["runs"][0]["results"]
    rule_ids = [r["id"] for r in rules]
    result_ids = [r["ruleId"] for r in results]
    if len(rule_ids) != len(set(rule_ids)):
        return False, "duplicate rule ids"
    if not all(rid in rule_ids for rid in result_ids):
        return False, "dangling ruleId(s)"
    if len(rules) > 3:
        return False, "too many rules (unknown values should collapse)"
    return True, "SARIF structural consistency green"


CASES.append(("FIX: SARIF structural consistency under mixed/unknown provenance", fix_structural_consistency))


# ═══════════════════════════════════════════════════════════════════════════
# Adjacent artifact boundaries not covered by the SARIF fix
# ═══════════════════════════════════════════════════════════════════════════
def adjacent_json_audit_leaks_provenance():
    """PR #63 hardens SARIF only. The --json audit renderer still emits
    provenance findings verbatim via vars(pf)."""
    from glassport.audit import render_json
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package=secret, manifest="package.json", detail="detail")
    report = _report(provenance=[pf])
    doc = render_json(report)
    if secret in detectors._normalize_for_scan(doc):
        return False, "CONFIRMED: --json audit output leaks provenance package secret"
    return True, "JSON audit provenance green"


CASES.append(("ADJACENT: --json audit provenance leak", adjacent_json_audit_leaks_provenance))


def adjacent_text_audit_leaks_provenance():
    """PR #63 hardens SARIF only. The text audit renderer also emits provenance
    package / detail verbatim."""
    from glassport.audit import render_text, Report
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package=secret, manifest="package.json", detail=f"detail contains {secret}")
    report = Report(
        profile={
            "name": "demo", "path": "/tmp/demo", "runtime": "python",
            "files_scanned": 1, "depth": {"ast": 1, "pattern": 0},
            "package_name": "", "version": "",
        },
        findings=[], deductions=[], score=50, grade="F", provenance=[pf])
    doc = render_text(report)
    if secret in detectors._normalize_for_scan(doc):
        return False, "CONFIRMED: text audit output leaks provenance package/detail secret"
    return True, "text audit provenance green"


CASES.append(("ADJACENT: text audit provenance leak", adjacent_text_audit_leaks_provenance))


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
