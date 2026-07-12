#!/usr/bin/env python3
"""Redaction red-team grill — beat the span-aware redaction floor.

Run from repo root:
    PYTHONPATH=src python dogfood/eval_redaction_redteam.py

Self-exits with nonzero status if any case fails.
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from typing import Callable

from glassport.audit import Finding, Report, render_text, render_json
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
# Pass 3 — attack the centralized redact_display boundary and every consumer
# ═══════════════════════════════════════════════════════════════════════════

# Independent reconstruction oracle: must NOT use glassport's normalizer.
# Strip Cf/Cc/Mn/Me, apply NFKD+NFKC, fold a curated homoglyph/small-capital
# table, then search exact and alphanumeric-loose.
_INDEP_HOMOGLYPHS: dict[str, str] = {}
for _src, _dst in [
    # Cyrillic look-alikes
    ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"), ("с", "c"), ("у", "y"), ("х", "x"),
    ("і", "i"), ("ј", "j"), ("ѕ", "s"), ("А", "A"), ("В", "B"), ("Е", "E"), ("К", "K"),
    ("М", "M"), ("Н", "H"), ("О", "O"), ("Р", "P"), ("С", "C"), ("Т", "T"), ("У", "Y"),
    ("Х", "X"),
    # Greek look-alikes
    ("Α", "A"), ("Β", "B"), ("Ε", "E"), ("Η", "H"), ("Ι", "I"), ("Κ", "K"), ("Μ", "M"),
    ("Ν", "N"), ("Ο", "O"), ("Ρ", "P"), ("Τ", "T"), ("Υ", "Y"), ("Χ", "X"), ("ο", "o"),
    ("α", "a"),
]:
    _INDEP_HOMOGLYPHS[_src] = _dst
# Latin small-capital letters (U+1D00..U+1D25) — visually capital, not NFKC-folded
_INDEP_SMALLCAP_MAP = {
    0x1D00: "A", 0x1D01: "AE", 0x1D02: "AO", 0x1D03: "AU", 0x1D04: "AV",
    0x1D05: "D", 0x1D06: "E", 0x1D07: "E", 0x1D08: "I", 0x1D09: "I",
    0x1D0A: "J", 0x1D0B: "K", 0x1D0C: "L", 0x1D0D: "M", 0x1D0E: "N",
    0x1D0F: "O", 0x1D10: "O", 0x1D11: "O", 0x1D12: "O", 0x1D13: "OE",
    0x1D14: "OU", 0x1D15: "OU", 0x1D16: "O", 0x1D17: "O", 0x1D18: "P",
    0x1D19: "R", 0x1D1A: "R", 0x1D1B: "T", 0x1D1C: "U", 0x1D1D: "UI",
    0x1D1E: "UU", 0x1D1F: "V", 0x1D20: "V", 0x1D21: "W", 0x1D22: "Z",
    0x1D23: "Z", 0x1D24: "Z", 0x1D25: "E",
}
for _cp, _val in _INDEP_SMALLCAP_MAP.items():
    _INDEP_HOMOGLYPHS[chr(_cp)] = _val
_INDEP_TABLE = str.maketrans(_INDEP_HOMOGLYPHS)
_INDEP_INVISIBLE_CATS = frozenset({"Cf", "Cc", "Mn", "Me"})


def _independent_reconstruct(text: str, secret: str) -> bool:
    cleaned = "".join(
        ch for ch in text
        if unicodedata.category(ch) not in _INDEP_INVISIBLE_CATS
    )
    norm = unicodedata.normalize(
        "NFKC", unicodedata.normalize("NFKD", cleaned))
    folded = norm.translate(_INDEP_TABLE)
    if secret in folded:
        return True
    loose_text = re.sub(r"[^A-Za-z0-9]", "", folded)
    loose_secret = re.sub(r"[^A-Za-z0-9]", "", secret)
    return loose_secret in loose_text


def _audit_profile() -> dict:
    return {
        "name": "demo", "path": "/tmp/demo", "runtime": "python",
        "files_scanned": 1, "depth": {"ast": 1, "pattern": 0},
        "package_name": "", "version": "",
    }


def _text_report(provenance: list) -> Report:
    return Report(
        profile=_audit_profile(), findings=[], deductions=[],
        score=50, grade="F", provenance=provenance)


def _render_all(report: Report) -> dict[str, str]:
    return {
        "text": render_text(report),
        "json": render_json(report),
        "sarif": sarif.render_sarif(report),
    }


def _leak_status(outputs: dict[str, str], secret: str) -> dict[str, dict[str, bool]]:
    return {
        name: {
            "prod": secret in detectors._normalize_for_scan(out),
            "indep": _independent_reconstruct(out, secret),
        }
        for name, out in outputs.items()
    }


def _format_leaks(status: dict[str, dict[str, bool]]) -> str:
    return "; ".join(
        f"{k}({('prod' if v['prod'] else '')}{('|indep' if v['indep'] else '')})"
        for k, v in status.items() if v["prod"] or v["indep"]
    ) or "clean"


def _any_leak(status: dict[str, dict[str, bool]]) -> bool:
    return any(v["prod"] or v["indep"] for v in status.values())


# ── 1. Field coverage ──────────────────────────────────────────────────────
def pass3_field_coverage_severity():
    """severity is the only provenance field that bypasses redact_display in
    text/JSON outputs. In real code evaluate() sets fixed strings, but the
    dataclass does not enforce it, so this is a defensive-coverage gap."""
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity=secret, ecosystem="npm",
        package="safe", manifest="m.json", detail="d")
    outputs = _render_all(_text_report([pf]))
    # SARIF uses severity only via _sarif_level, so it does not leak there.
    leaks = {k: v for k, v in _leak_status(outputs, secret).items()
             if k in ("text", "json")}
    if _any_leak(leaks):
        return False, f"severity emitted raw in text/json: {_format_leaks(leaks)}"
    return True, "severity safely consumed in all renderers"


CASES.append(("PASS3: severity field coverage", pass3_field_coverage_severity))


def pass3_field_coverage_manifest():
    """manifest goes through redact_secrets_strict (not redact_display) in JSON
    and SARIF; it is not rendered in text. Confirm obfuscation still gets caught."""
    secret = _live_secret()
    obf_path = f"src/{secret.replace('a', 'а').replace('A', 'А')}/package.json"
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package="safe", manifest=obf_path, detail="d")
    outputs = _render_all(_text_report([pf]))
    leaks = _leak_status(outputs, secret)
    if _any_leak(leaks):
        return False, f"manifest obfuscation leaks: {_format_leaks(leaks)}"
    return True, "manifest URI redaction obfuscation-proof"


CASES.append(("PASS3: manifest field coverage", pass3_field_coverage_manifest))


# ── 2. Obfuscation variants in every display field ─────────────────────────
def _obf_cases():
    secret = _live_secret()
    return {
        "plain": secret,
        "zwj": "sk-ant-api03-" + "\u200d" + "A" * 40 + "1234567890",
        "zwsp": "sk-ant-api03-" + "\u200b" + "A" * 40 + "1234567890",
        "fullwidth": secret.translate(
            {ord(c): ord(c) + 0xFEE0 for c in secret if "!" <= c <= "~"}),
        "cyrillic": secret.replace("a", "а").replace("A", "А"),
        "bidi": "\u202e" + secret + "\u202c",
        "combining": "".join(c + "\u0332" for c in secret),
        "smallcap": secret.replace("A", chr(0x1D00)),
        "multi": ("sk-ant-api03-" + "\u200d"
                  + ("A" * 10).replace("A", "а")
                  + "\u202e" + "A" * 20 + "\u202c"
                  + "A" * 10 + "1234567890"),
    }


def pass3_obfuscation_package():
    secret = _live_secret()
    findings = []
    for name, obf in _obf_cases().items():
        pf = ProvenanceFinding(
            rule="prov-not-in-registry", severity="high", ecosystem="npm",
            package=obf, manifest="m.json", detail="d")
        status = _leak_status(_render_all(_text_report([pf])), secret)
        if _any_leak(status):
            findings.append(f"{name}({_format_leaks(status)})")
    if findings:
        return False, "package obfuscation leaks: " + ", ".join(findings)
    return True, "package obfuscation green with both oracles"


CASES.append(("PASS3: package obfuscation variants", pass3_obfuscation_package))


def pass3_obfuscation_detail():
    secret = _live_secret()
    findings = []
    for name, obf in _obf_cases().items():
        pf = ProvenanceFinding(
            rule="prov-not-in-registry", severity="high", ecosystem="npm",
            package="safe", manifest="m.json", detail=obf)
        status = _leak_status(_render_all(_text_report([pf])), secret)
        if _any_leak(status):
            findings.append(f"{name}({_format_leaks(status)})")
    if findings:
        return False, "detail obfuscation leaks: " + ", ".join(findings)
    return True, "detail obfuscation green with both oracles"


CASES.append(("PASS3: detail obfuscation variants", pass3_obfuscation_detail))


def pass3_obfuscation_smallcap_evidence_for_issue_64():
    """U+1D00 small-capital-A is not detected by glassport's scanner. The
    obfuscated credential shape survives in all rendered artifacts; the
    independent oracle reconstructs the plain secret. This is evidence for
    issue #64 (detector normalization), not a redaction-fix bug."""
    secret = _live_secret()
    obf = secret.replace("A", chr(0x1D00))
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package=obf, manifest="m.json", detail="d")
    status = _leak_status(_render_all(_text_report([pf])), secret)
    indep_only = {k: {"indep": v["indep"]} for k, v in status.items()
                  if not v["prod"] and v["indep"]}
    if indep_only:
        return False, (
            "Issue #64 evidence: U+1D00 small-capital shape survives; "
            "independent oracle reconstructs: " +
            "; ".join(f"{k}(indep)" for k in indep_only))
    return True, "small-capital obfuscation also caught by production oracle"


CASES.append(("PASS3: U+1D00 small-capital reconstruction (issue #64)",
              pass3_obfuscation_smallcap_evidence_for_issue_64))


# ── 3. Split-secret / boundary composition ─────────────────────────────────
def pass3_split_package_detail():
    """A credential whose halves land in package and detail; the rendered text
    and SARIF join them with fixed delimiters. The independent oracle collapses
    those delimiters and may reconstruct."""
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package="sk-ant-api03-", manifest="m.json",
        detail="A" * 40 + "1234567890")
    status = _leak_status(_render_all(_text_report([pf])), secret)
    if _any_leak(status):
        return False, f"split package/detail reconstructs: {_format_leaks(status)}"
    return True, "package/detail split green"


CASES.append(("PASS3: split secret across package/detail", pass3_split_package_detail))


def pass3_split_ecosystem_package_text():
    """Text renderer joins [ecosystem:package]. Split a credential across the
    two fields and check reconstruction."""
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="sk-ant-api03-",
        package="A" * 40 + "1234567890", manifest="m.json", detail="d")
    status = _leak_status(_render_all(_text_report([pf])), secret)
    if _any_leak(status):
        return False, f"split ecosystem/package reconstructs: {_format_leaks(status)}"
    return True, "ecosystem/package split green"


CASES.append(("PASS3: split secret across ecosystem/package", pass3_split_ecosystem_package_text))


def pass3_split_rule_detail_text():
    """Text renderer puts rule on one line and detail on the next."""
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="sk-ant-api03-", severity="high", ecosystem="npm",
        package="safe", manifest="m.json", detail="A" * 40 + "1234567890")
    status = _leak_status(_render_all(_text_report([pf])), secret)
    if _any_leak(status):
        return False, f"split rule/detail reconstructs: {_format_leaks(status)}"
    return True, "rule/detail split green"


CASES.append(("PASS3: split secret across rule/detail", pass3_split_rule_detail_text))


def pass3_split_json_values():
    """JSON separates provenance values with punctuation. Split a credential
    across package and detail and check whether the JSON string reconstructs."""
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package="sk-ant-api03-", manifest="m.json",
        detail="A" * 40 + "1234567890")
    js = render_json(_text_report([pf]))
    status = _leak_status({"json": js}, secret)
    if _any_leak(status):
        return False, f"split JSON values reconstruct: {_format_leaks(status)}"
    return True, "JSON value split green"


CASES.append(("PASS3: split secret across JSON values", pass3_split_json_values))


# ── 4. Scan-failure / totality per renderer ────────────────────────────────
def pass3_scan_failure_totality():
    from unittest import mock
    secret = _live_secret()
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package=secret, manifest="package.json", detail="detail")
    report = _text_report([pf])
    failures = []
    for name, renderer in [("text", render_text), ("json", render_json),
                           ("sarif", sarif.render_sarif)]:
        with mock.patch.object(detectors, "_scan_pii",
                               side_effect=RuntimeError("boom")):
            try:
                out = renderer(report)
                if secret in out:
                    failures.append(f"{name} leaked raw secret")
                elif detectors._WITHHELD not in out:
                    failures.append(f"{name} did not emit _WITHHELD")
            except Exception as exc:
                failures.append(f"{name} crashed: {exc}")
    if failures:
        return False, "scan-failure totality failure: " + "; ".join(failures)
    return True, "scan-failure totality green for text/json/sarif"


CASES.append(("PASS3: scan-failure totality per renderer", pass3_scan_failure_totality))


# ── 5. Boundary sizes ──────────────────────────────────────────────────────
def pass3_boundary_sizes():
    secret = _live_secret()
    scenarios = [
        ("secret beyond 50k clamp cap", "x" * 49_990 + secret),
        ("secret at 40k within 50k", "x" * 40_000 + secret),
        ("secret straddling 1MB scan cap", "x" * 999_990 + secret),
        ("secret beyond 1MB", "x" * 1_000_100 + secret),
    ]
    failures = []
    for label, pkg in scenarios:
        pf = ProvenanceFinding(
            rule="prov-not-in-registry", severity="high", ecosystem="npm",
            package=pkg, manifest="m.json", detail="d")
        for name, out in _render_all(_text_report([pf])).items():
            if secret in detectors._normalize_for_scan(out):
                failures.append(f"{label}/{name}")
    if failures:
        return False, "boundary size leaks: " + ", ".join(failures)
    return True, "boundary sizes green"


CASES.append(("PASS3: boundary sizes around scan/clamp caps", pass3_boundary_sizes))


# ── 6. Malformed / unexpected structural values ────────────────────────────
def pass3_malformed_rule_nonstring():
    """A list (or other non-string) as pf.rule currently crashes every renderer
    because redact_display / the validation code assumes a string."""
    pf = ProvenanceFinding(
        rule=["prov-not-in-registry"], severity="high", ecosystem="npm",
        package="safe", manifest="m.json", detail="d")
    report = _text_report([pf])
    failures = []
    for name, renderer in [("text", render_text), ("json", render_json),
                           ("sarif", sarif.render_sarif)]:
        try:
            renderer(report)
            failures.append(f"{name} did not crash on list rule")
        except Exception as exc:
            failures.append(f"{name} crashed: {type(exc).__name__}: {exc}")
    # We expect no crash; any crash is a RED finding.
    if len(failures) == 3 and all("crashed" in f for f in failures):
        return False, "non-string rule crashes all renderers: " + "; ".join(failures)
    if failures:
        return False, "unexpected behavior with non-string rule: " + "; ".join(failures)
    return True, "non-string rule handled safely"


CASES.append(("PASS3: non-string rule value totality", pass3_malformed_rule_nonstring))


def pass3_malformed_ecosystem_nonstring():
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem=["npm"],
        package="safe", manifest="m.json", detail="d")
    report = _text_report([pf])
    failures = []
    for name, renderer in [("text", render_text), ("json", render_json),
                           ("sarif", sarif.render_sarif)]:
        try:
            renderer(report)
            failures.append(f"{name} did not crash on list ecosystem")
        except Exception as exc:
            failures.append(f"{name} crashed: {type(exc).__name__}: {exc}")
    if len(failures) == 3 and all("crashed" in f for f in failures):
        return False, "non-string ecosystem crashes all renderers: " + "; ".join(failures)
    if failures:
        return False, "unexpected behavior with non-string ecosystem: " + "; ".join(failures)
    return True, "non-string ecosystem handled safely"


CASES.append(("PASS3: non-string ecosystem value totality", pass3_malformed_ecosystem_nonstring))


def pass3_malformed_rule_validation():
    secret = _live_secret()
    for raw in [None, "", secret]:
        pf = ProvenanceFinding(
            rule=raw, severity="high", ecosystem="npm",
            package="safe", manifest="m.json", detail="d")
        report = _text_report([pf])
        for name, out in _render_all(report).items():
            if secret in out:
                return False, f"rule={raw!r} leaked secret in {name}"
            if name == "sarif":
                d = json.loads(out)
                rules = {r["id"]: r for r in d["runs"][0]["tool"]["driver"]["rules"]}
                res = d["runs"][0]["results"][0]
                if res["ruleId"] not in rules:
                    return False, f"rule={raw!r} produced dangling ruleId in SARIF"
    return True, "None/empty/secret rule values collapse safely"


CASES.append(("PASS3: None/empty/secret rule collapse", pass3_malformed_rule_validation))


def pass3_malformed_ecosystem_validation():
    secret = _live_secret()
    for raw in [None, "", secret]:
        pf = ProvenanceFinding(
            rule="prov-not-in-registry", severity="high", ecosystem=raw,
            package="safe", manifest="m.json", detail="d")
        report = _text_report([pf])
        for name, out in _render_all(report).items():
            if secret in out:
                return False, f"ecosystem={raw!r} leaked secret in {name}"
    return True, "None/empty/secret ecosystem values collapse safely"


CASES.append(("PASS3: None/empty/secret ecosystem collapse", pass3_malformed_ecosystem_validation))


# ── 7. Structural integrity + 8. benign invariance ─────────────────────────
def pass3_structural_integrity_and_benign_invariance():
    pf = ProvenanceFinding(
        rule="prov-not-in-registry", severity="high", ecosystem="npm",
        package="left-pad", manifest="package.json",
        detail="declared dependency not found in the npm registry")
    report = _text_report([pf])
    text = render_text(report)
    js = render_json(report)
    sarif_doc = sarif.render_sarif(report)

    failures = []
    if "left-pad" not in text or "left-pad" not in js or "left-pad" not in sarif_doc:
        failures.append("benign package name was altered")

    obj = json.loads(js)
    keys = sorted(obj.get("provenance", [{}])[0].keys())
    if keys != ["detail", "ecosystem", "manifest", "package", "rule", "severity"]:
        failures.append(f"JSON provenance keys changed: {keys}")
    types = {k: type(v).__name__ for k, v in obj["provenance"][0].items()}
    if not all(t == "str" for t in types.values()):
        failures.append(f"JSON provenance value types changed: {types}")

    d = json.loads(sarif_doc)
    if d.get("version") != "2.1.0":
        failures.append("SARIF version missing")
    rules = {r["id"]: r for r in d["runs"][0]["tool"]["driver"]["rules"]}
    for res in d["runs"][0]["results"]:
        if res["ruleId"] not in rules:
            failures.append(f"dangling ruleId {res['ruleId']}")
    if failures:
        return False, "structural/benign failure: " + "; ".join(failures)
    return True, "structural integrity + benign invariance green"


CASES.append(("PASS3: structural integrity + benign invariance",
              pass3_structural_integrity_and_benign_invariance))


# ── 9. Bypass hunt ─────────────────────────────────────────────────────────
def pass3_bypass_hunt():
    """Confirm no remaining pf.* interpolation or vars(pf)/asdict/repr/str path
    reaches a shareable output without scrubbing."""
    import os
    import re as _re
    src_root = os.path.join(os.path.dirname(__file__), "..", "src", "glassport")
    src_root = os.path.abspath(src_root)
    hits = []
    for root, _dirs, files in os.walk(src_root):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(root, fname)
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            # Direct pf.<field> interpolation in f-string or format
            for m in _re.finditer(r"[\"'][^\"']*\{pf\.[a-z]+\}[^\"']*[\"']", text):
                hits.append(f"{path}:{m.start()}: {m.group(0)[:80]}")
            # vars(pf), asdict(pf), repr(pf), str(pf)
            for m in _re.finditer(r"\b(vars|asdict|repr|str)\s*\(\s*pf\s*\)", text):
                hits.append(f"{path}:{m.start()}: {m.group(0)}")
    # Filter out the known-safe accesses we already reviewed
    safe_files = {"sarif.py", "audit.py"}
    unexpected = [h for h in hits
                  if not any(os.sep + s in h for s in safe_files)]
    if unexpected:
        return False, "unexpected pf rendering paths: " + "; ".join(unexpected)
    return True, "bypass hunt green (only known-safe pf accesses in sarif.py/audit.py)"


CASES.append(("PASS3: bypass hunt for pf.* rendering", pass3_bypass_hunt))


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
