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

from glassport.audit import Finding, Report, render_json, render_text
from glassport.provenance import ProvenanceFinding
from glassport import sarif
from glassport import detectors
from glassport.adapters.mcp_session import from_mcp_session
from glassport import report as report_mod


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


def _L(seq: int, direction: str, frame: dict) -> str:
    return json.dumps({"schema_version": "0.1", "seq": seq, "ts": f"t{seq}",
                       "dir": direction, "frame": frame, "raw": None})


def _handshake() -> list[str]:
    # Mirrors tests/test_detectors.py::handshake() exactly, including the
    # tool's inputSchema — that schema is load-bearing: calling with an
    # argument shape outside it (e.g. "data" when only "query"/"limit" are
    # declared, additionalProperties: False) triggers a schema-violation
    # annotation, and glassport's own report renders the flagged event's
    # raw content into a <pre> block for the analyst to review. THAT
    # rendering (via report.py's per-event content dump) is the real
    # attacker-reachable surface issue #64 closes; a tool declared with no
    # schema at all never reaches this render path, silently hiding the bug.
    return [
        _L(1, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26",
                                "capabilities": {},
                                "clientInfo": {"name": "grill"}}}),
        _L(2, "s2c", {"jsonrpc": "2.0", "id": 1,
                     "result": {"protocolVersion": "2025-03-26",
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "grill-server"}}}),
        _L(3, "c2s", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
        _L(4, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        _L(5, "s2c", {"jsonrpc": "2.0", "id": 2,
                     "result": {"tools": [{
                         "name": "web_search",
                         "inputSchema": {
                             "type": "object",
                             "properties": {"query": {"type": "string"},
                                           "limit": {"type": "integer"}},
                             "required": ["query"],
                             "additionalProperties": False}}]}}),
    ]


def _call(seq: int, rid: int, name: str, arguments: dict) -> str:
    return _L(seq, "c2s", {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                          "params": {"name": name, "arguments": arguments}})


def _result(seq: int, rid: int, payload: dict) -> str:
    return _L(seq, "s2c", {"jsonrpc": "2.0", "id": rid, "result": payload})


def _render_report(lines: list[str]) -> str:
    trace = from_mcp_session(lines)
    detectors.annotate(trace)
    return report_mod.render_html(trace, source_name="grill.jsonl")


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
# PASS3 — renderer-boundary defensive gaps (Kimi 3rd pass)
#
# Neither severity nor a non-string rule/ecosystem is attacker-reachable
# through the real evaluate() pipeline today (only `package` is manifest-
# derived — see tests/test_provenance.py::TestProvenanceFieldReachability).
# These are defense-in-depth locks against a future/buggy provenance source,
# not live exploits, and are asserted as "must not crash + must collapse to a
# safe sentinel" — not "must crash" (Kimi's pass-3 evidence, preserved
# unmodified on branch redteam/pass3-evidence, predates the fix and expected
# a crash; these cases assert the fixed, correct behavior).
# ═══════════════════════════════════════════════════════════════════════════
def _prov_report(**pf_kw):
    base = dict(rule="prov-not-in-registry", severity="high", ecosystem="npm",
                package="left-pad", manifest="package.json",
                detail="not found in registry")
    base.update(pf_kw)
    pf = ProvenanceFinding(**base)
    # A full profile dict — render_text() reads path/runtime/files_scanned/
    # depth/package_name, which the file's minimal _report() helper omits.
    return Report(
        profile={
            "name": "demo", "path": "/tmp/demo", "runtime": "python",
            "files_scanned": 1, "depth": {"ast": 1, "pattern": 0},
            "package_name": "", "version": "",
        },
        findings=[], deductions=[], score=50, grade="F", provenance=[pf])


class _Hostile:
    """A raising object: no dunder here may ever be invoked by a renderer."""
    def __str__(self): raise RuntimeError("str() invoked")
    def __bool__(self): raise RuntimeError("bool() invoked")
    def __eq__(self, other): raise RuntimeError("eq invoked")
    def __hash__(self): return 0


def pass3_severity_never_raw():
    secret = _live_secret()
    r = _prov_report(severity=secret)
    doc = sarif.render_sarif(r)
    if secret in doc or secret in render_json(r) or secret in render_text(r):
        return False, "secret-shaped severity emitted raw in some renderer"
    return True, "severity closed-mapping green across all renderers"


CASES.append(("PASS3: secret-shaped severity never emitted raw", pass3_severity_never_raw))


def pass3_non_string_rule_ecosystem_no_crash():
    for bad in (["a", "b"], 12345, None, {"x": 1}):
        for field in ("rule", "ecosystem"):
            r = _prov_report(**{field: bad})
            try:
                sarif.render_sarif(r)
                render_json(r)
                render_text(r)
            except Exception as exc:
                return False, f"{field}={bad!r} crashed: {type(exc).__name__}: {exc}"
    return True, "non-string rule/ecosystem: no crash across all renderers"


CASES.append(("PASS3: non-string rule/ecosystem does not crash any renderer",
              pass3_non_string_rule_ecosystem_no_crash))


def pass3_hostile_object_no_dunder_invoked():
    for field in ("rule", "ecosystem", "package", "manifest"):
        r = _prov_report(**{field: _Hostile()})
        try:
            sarif.render_sarif(r)
            render_json(r)
            render_text(r)
        except RuntimeError as exc:
            return False, f"{field}: a forbidden dunder was invoked: {exc}"
        except Exception as exc:
            return False, f"{field}: unexpected crash: {type(exc).__name__}: {exc}"
    return True, "hostile object never has str()/bool()/eq() invoked"


CASES.append(("PASS3: hostile object dunders never invoked",
              pass3_hostile_object_no_dunder_invoked))


def pass3_split_package_detail_classified():
    """Kimi PASS3-3a: package/detail split. Neither field is simultaneously
    attacker-controlled through the real pipeline (detail is a fixed
    glassport template). Glassport's guarantee: no CONTIGUOUS, directly-
    usable credential in the rendered text — verified with the PRODUCTION
    oracle. An aggressive independent oracle that strips ALL structural
    punctuation before searching is a different, broader question, tracked
    separately (see dogfood/findings/redaction-redteam.md) and is
    deliberately NOT the assertion here."""
    secret = _live_secret()
    r = _prov_report(package="sk-ant-api03-", detail="A" * 40 + "1234567890")
    text = render_text(r)
    if secret in detectors._normalize_for_scan(text):
        return False, "contiguous secret reconstructed in text (production oracle)"
    return True, "package/detail split: no contiguous usable credential (classified, see findings.md)"


CASES.append(("PASS3: package/detail split classified (not currently reachable)",
              pass3_split_package_detail_classified))


# ═══════════════════════════════════════════════════════════════════════════
# ISSUE #64 — combining-mark and small-capital (U+1D00) Unicode-normalization
# gap, closed. Confirmed reconstructable pre-fix via an INDEPENDENT oracle
# (deliberately not reusing glassport's own normalizer — a shared-normalizer
# oracle would agree with a blind spot in the thing under test) across both
# the provenance->SARIF/JSON/text path AND ordinary MCP tool-call arguments
# AND results rendered into report.html — the normalizer is shared beyond
# provenance, so both surfaces are locked here.
#
# _independent_reconstruct is a SEPARATE implementation from
# detectors._normalize_for_scan/_normalize_with_map (own category-strip,
# own NFKD+NFKC, own confusable table built from scratch) — using the
# production normalizer as the oracle here would silently agree with
# whatever blind spot the fix has, exactly the trap this section exists to
# avoid. It matches the oracle already proven against these two glyph
# classes during the fix's own investigation.
# ═══════════════════════════════════════════════════════════════════════════
import unicodedata as _unicodedata
import re as _re

# PR #66: extend the independent oracle so it can detect leaks the production
# normalizer does not yet cover — excluded U+1D00 small-capital glyphs and
# spacing combining marks (category Mc) in addition to the included glyphs and
# Mn/Me the fix already handles.
_INDEP_SMALLCAP = {
    # Included in PR #66
    0x1D00: 'A', 0x1D04: 'C', 0x1D05: 'D', 0x1D07: 'E',
    0x1D0A: 'J', 0x1D0B: 'K', 0x1D0D: 'M', 0x1D0F: 'O',
    0x1D18: 'P', 0x1D1B: 'T', 0x1D1C: 'U', 0x1D20: 'V',
    0x1D21: 'W', 0x1D22: 'Z',
    # Excluded single-letter small capitals (surface 1)
    0x1D03: 'B',   # LATIN LETTER SMALL CAPITAL BARRED B
    0x1D06: 'D',   # LATIN LETTER SMALL CAPITAL ETH
    0x1D08: 'E',   # LATIN SMALL LETTER TURNED OPEN E
    0x1D09: 'I',   # LATIN SMALL LETTER TURNED I
    0x1D0C: 'L',   # LATIN LETTER SMALL CAPITAL L WITH STROKE
    0x1D0E: 'N',   # LATIN LETTER SMALL CAPITAL REVERSED N
    0x1D10: 'O',   # LATIN LETTER SMALL CAPITAL OPEN O
    0x1D11: 'O',   # LATIN SMALL LETTER SIDEWAYS O
    0x1D12: 'O',   # LATIN SMALL LETTER SIDEWAYS OPEN O
    0x1D16: 'O',   # LATIN SMALL LETTER TOP HALF O
    0x1D17: 'O',   # LATIN SMALL LETTER BOTTOM HALF O
    0x1D19: 'R',   # LATIN LETTER SMALL CAPITAL REVERSED R
    0x1D1A: 'R',   # LATIN LETTER SMALL CAPITAL TURNED R
    0x1D1D: 'U',   # LATIN SMALL LETTER SIDEWAYS U
    0x1D1E: 'U',   # LATIN SMALL LETTER SIDEWAYS DIAERESIZED U
    0x1D1F: 'V',   # LATIN SMALL LETTER SIDEWAYS TURNED M
    0x1D23: 'Z',   # LATIN LETTER SMALL CAPITAL EZH
    0x1D24: 'Z',   # LATIN LETTER VOICED LARYNGEAL SPIRANT
    0x1D25: 'E',   # LATIN LETTER AIN
    # Excluded multi-letter small capitals (surface 1)
    0x1D01: 'AE',  # LATIN LETTER SMALL CAPITAL AE
    0x1D02: 'AE',  # LATIN SMALL LETTER TURNED AE
    0x1D13: 'O',   # LATIN SMALL LETTER SIDEWAYS O WITH STROKE
    0x1D14: 'OE',  # LATIN SMALL LETTER TURNED OE
    0x1D15: 'OU',  # LATIN LETTER SMALL CAPITAL OU
}


def _independent_reconstruct(text: str, secret: str) -> bool:
    # Strip control, format, nonspacing, enclosing, AND spacing combining marks
    # (Mc) so the oracle is strictly more aggressive than production.
    cleaned = "".join(ch for ch in text
                      if _unicodedata.category(ch) not in ("Cf", "Cc", "Mn", "Me", "Mc"))
    norm = _unicodedata.normalize(
        "NFKC", _unicodedata.normalize("NFKD", cleaned))
    folded = "".join(_INDEP_SMALLCAP.get(ord(c), c) for c in norm)
    if secret in folded:
        return True
    loose = _re.sub(r"[^A-Za-z0-9]", "", folded)
    loose_secret = _re.sub(r"[^A-Za-z0-9]", "", secret)
    return loose_secret in loose


def issue64_combining_mark_in_tool_argument():
    secret = _live_secret()
    obf = "".join(c + "̲" for c in secret)   # COMBINING LOW LINE on every char
    lines = _handshake() + [
        _call(6, 3, "web_search", {"data": obf}),
        _result(7, 3, {"content": [{"type": "text", "text": "ok"}]})]
    html = _render_report(lines)
    if _independent_reconstruct(html, secret):
        return False, "issue #64 CONFIRMED: combining-mark tool argument leaks into report.html"
    return True, "combining-mark tool argument green"


CASES.append(("ISSUE64: combining-mark obfuscated tool argument in report.html",
              issue64_combining_mark_in_tool_argument))


def issue64_combining_mark_in_tool_result():
    secret = _live_secret()
    obf = "".join(c + "̲" for c in secret)
    lines = _handshake() + [
        _call(6, 3, "web_search", {"query": "x"}),
        _result(7, 3, {"content": [{"type": "text", "text": obf}]})]
    html = _render_report(lines)
    if _independent_reconstruct(html, secret):
        return False, "issue #64 CONFIRMED: combining-mark tool result leaks into report.html"
    return True, "combining-mark tool result green"


CASES.append(("ISSUE64: combining-mark obfuscated tool result in report.html",
              issue64_combining_mark_in_tool_result))


def issue64_small_capital_in_tool_argument():
    secret = _live_secret()
    obf = secret.replace("A", "ᴀ")   # U+1D00, no Unicode decomposition
    lines = _handshake() + [
        _call(6, 3, "web_search", {"data": obf}),
        _result(7, 3, {"content": [{"type": "text", "text": "ok"}]})]
    html = _render_report(lines)
    if _independent_reconstruct(html, secret):
        return False, "issue #64 CONFIRMED: small-capital tool argument leaks into report.html"
    return True, "small-capital tool argument green"


CASES.append(("ISSUE64: small-capital obfuscated tool argument in report.html",
              issue64_small_capital_in_tool_argument))


def issue64_provenance_combining_mark_end_to_end():
    """Real manifest -> discover_deps() -> evaluate() -> SARIF, not a
    hand-built ProvenanceFinding. Closes the loop from the reachability
    proof to the actual artifact."""
    import shutil
    import tempfile
    from datetime import datetime, timezone
    from pathlib import Path
    from glassport.provenance import discover_deps, evaluate, Fetched

    secret = _live_secret()
    obf = "".join(c + "̲" for c in secret)
    d = Path(tempfile.mkdtemp())
    try:
        (d / "package.json").write_text(
            json.dumps({"dependencies": {obf: "1.0.0"}}), encoding="utf-8")
        deps = discover_deps(d)
        findings = evaluate(deps[0], Fetched(status="not_found", payload={}),
                            now=datetime.now(timezone.utc))
        report = _report(provenance=findings)
        doc = sarif.render_sarif(report)
        if _independent_reconstruct(doc, secret):
            return False, "issue #64 CONFIRMED: real-manifest combining-mark leaks into SARIF"
        return True, "real-manifest combining-mark provenance green"
    finally:
        shutil.rmtree(d)


CASES.append(("ISSUE64: real-manifest combining-mark obfuscated package -> SARIF",
              issue64_provenance_combining_mark_end_to_end))


# ═══════════════════════════════════════════════════════════════════════════
# PR #66 verification pass — issue #64 follow-up
#
# Attack the ACTUAL fix with an oracle independent of
# detectors._normalize_for_scan/_normalize_with_map. Surfaces:
#   1. Excluded U+1D00 small-capital glyphs
#   2. Combining-mark category coverage (Mc/Me, not just Mn)
#   3. Origin-mapping edge cases
#   4. Trailing-boundary repair
#   5. Multilingual false positives
#   6. Performance
#   7. Every rendered artifact path (SARIF, JSON audit, text audit, HTML)
# ═══════════════════════════════════════════════════════════════════════════
import random as _random
import time as _time


def _generic_secret_with(letter: str, length: int = 64) -> str:
    """A generic_api_key value containing `letter` multiple times, with high
    enough entropy to fire the built-in pattern when un-obfuscated."""
    rng = _random.Random(42)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    chars = [letter] * 8
    while len(chars) < length:
        chars.append(rng.choice(alphabet))
    rng.shuffle(chars)
    return f'api_key="{ "".join(chars) }"'


def _generic_secret_with_seq(seq: str, length: int = 64) -> str:
    """Like _generic_secret_with, but ensures `seq` appears contiguously."""
    rng = _random.Random(42)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    body = "".join(rng.choice(alphabet) for _ in range(length))
    for _ in range(6):
        pos = rng.randrange(0, length - len(seq) + 1)
        body = body[:pos] + seq + body[pos + len(seq):]
    return f'api_key="{body}"'


def _body_of(secret: str) -> str:
    return secret.split('"')[1]


def _check_redaction_leak(label: str, obfuscated: str, secret_body: str) -> tuple[bool, str]:
    """Returns (ok, detail). Fails if the independent oracle reconstructs the
    secret from the rendered/redacted output while production sees it as clean.
    """
    redacted = detectors.redact_secrets_strict(obfuscated)
    prod_sees = secret_body in detectors._normalize_for_scan(redacted)
    indep_reconstructs = _independent_reconstruct(redacted, secret_body)
    if indep_reconstructs:
        return False, (
            f"PR66 {label} CONFIRMED: independent oracle reconstructs; "
            f"production oracle sees_leak={prod_sees}"
        )
    return True, f"PR66 {label} green"


# ── Surface 1: excluded U+1D00 small-capital glyphs ─────────────────────────
def pr66_surface1_excluded_single_letter_smallcaps():
    """Excluded single-letter small capitals are NOT folded by production; an
    attacker can substitute one for its ASCII look-alike and leak a credential
    that the independent oracle folds back."""
    glyphs = [
        (0x1D03, "B", "barred-B"),
        (0x1D06, "D", "eth-D"),
        (0x1D08, "E", "turned-open-E"),
        (0x1D09, "I", "turned-I"),
        (0x1D0C, "L", "stroked-L"),
        (0x1D0E, "N", "reversed-N"),
        (0x1D10, "O", "open-O"),
        (0x1D11, "O", "sideways-O"),
        (0x1D12, "O", "sideways-open-O"),
        (0x1D16, "O", "top-half-O"),
        (0x1D17, "O", "bottom-half-O"),
        (0x1D19, "R", "reversed-R"),
        (0x1D1A, "R", "turned-R"),
        (0x1D1D, "U", "sideways-U"),
        (0x1D1E, "U", "sideways-diaeresized-U"),
        (0x1D1F, "V", "sideways-turned-M"),
        (0x1D23, "Z", "ezh"),
        (0x1D24, "Z", "laryngeal-spirant"),
        (0x1D25, "E", "ain"),
    ]
    fails = []
    for cp, letter, name in glyphs:
        secret = _generic_secret_with(letter)
        body = _body_of(secret)
        obf_body = body.replace(letter, chr(cp))
        obf = f'api_key="{obf_body}"'
        ok, detail = _check_redaction_leak(
            f"excluded small-cap {name} ({letter}->U+{cp:04X})", obf, body)
        if not ok:
            fails.append(detail)
    if fails:
        head = "; ".join(fails[:3])
        tail = f" ...and {len(fails) - 3} more" if len(fails) > 3 else ""
        return False, head + tail
    return True, "all excluded single-letter small-caps green"


CASES.append(("PR66-S1: excluded U+1D00 single-letter small capitals",
              pr66_surface1_excluded_single_letter_smallcaps))


def pr66_surface1_excluded_multiletter_smallcaps():
    """Excluded multi-letter small capitals (AE, OE, OU ligatures) likewise
    evade production normalization and reconstruct under the independent oracle."""
    glyphs = [
        (0x1D01, "AE", "small-cap-AE"),
        (0x1D02, "AE", "turned-AE"),
        (0x1D14, "OE", "turned-OE"),
        (0x1D15, "OU", "small-cap-OU"),
    ]
    fails = []
    for cp, seq, name in glyphs:
        secret = _generic_secret_with_seq(seq)
        body = _body_of(secret)
        obf_body = body.replace(seq, chr(cp))
        obf = f'api_key="{obf_body}"'
        ok, detail = _check_redaction_leak(
            f"excluded small-cap {name} ({seq}->U+{cp:04X})", obf, body)
        if not ok:
            fails.append(detail)
    if fails:
        return False, "; ".join(fails)
    return True, "all excluded multi-letter small-caps green"


CASES.append(("PR66-S1: excluded U+1D00 multi-letter small capitals",
              pr66_surface1_excluded_multiletter_smallcaps))


# ── Surface 2: combining-mark category coverage (Mc/Me) ─────────────────────
def pr66_surface2_combining_marks_mc_me():
    """Production strips only Mn (nonspacing) marks. Spacing combining marks
    (Mc) and enclosing marks (Me) are left in place and break the pattern; the
    independent oracle strips them and reconstructs the secret."""
    secret = _generic_secret_with("I")
    body = _body_of(secret)
    marks = [
        ("\u0903", "Devanagari visarga (Mc)"),
        ("\u0BC1", "Tamil vowel sign U (Mc)"),
        ("\u0BC2", "Tamil vowel sign UU (Mc)"),
        ("\u20DD", "combining enclosing circle (Me)"),
        ("\u20E4", "combining enclosing upward triangle (Me)"),
    ]
    fails = []
    for mark, name in marks:
        obf_body = mark.join(body)
        obf = f'api_key="{obf_body}"'
        ok, detail = _check_redaction_leak(f"combining mark {name}", obf, body)
        if not ok:
            fails.append(detail)
    if fails:
        return False, "; ".join(fails[:2]) + (" ..." if len(fails) > 2 else "")
    return True, "Mc/Me combining marks green"


CASES.append(("PR66-S2: Mc/Me combining-mark coverage",
              pr66_surface2_combining_marks_mc_me))


def pr66_surface2_composed_smallcap_plus_combining():
    """A mixed obfuscation: small-capital substitution plus Mn combining marks.
    Production folds the included small-capital (A->ᴀ) but keeps the Mn; the
    secret body normalizes to ASCII but the surrounding combining marks may
    still break contiguity if not handled."""
    secret = _live_secret()
    # U+1D00 is included in PR #66, Mn underline is also handled
    obf = "".join(c + "\u0332" for c in secret).replace("A", "\u1D00")
    ok, detail = _check_redaction_leak(
        "small-cap-A + Mn underline mix", obf, secret)
    if not ok:
        return False, detail
    return True, "small-cap + combining mix green"


CASES.append(("PR66-S2: small-capital + combining-mark composed obfuscation",
              pr66_surface2_composed_smallcap_plus_combining))


# ── Surface 3: origin-mapping edge cases ────────────────────────────────────
def pr66_surface3_secret_at_start_and_end():
    """Origin indices 0 and len-1 must map back correctly; no off-by-one
    leaves a leading/trailing byte of the secret behind."""
    secret = _generic_secret_with("S")
    body = _body_of(secret)
    # Wrap in a pattern so it fires; test leading/trailing invisible/Mn.
    for text in (secret, f'{secret}\u0332', f'\u200b{secret}', f'prefix {secret} suffix'):
        redacted = detectors.redact_secrets_strict(text)
        if _independent_reconstruct(redacted, body):
            return False, f"origin leak at boundary for {text[:60]!r}"
    return True, "start/end origin mapping green"


CASES.append(("PR66-S3: secret at start/end origin mapping",
              pr66_surface3_secret_at_start_and_end))


def pr66_surface3_adjacent_secrets_with_combining():
    """Two secrets separated by a dropped Mn mark must both be fully covered by
    the merged redaction span; no fragment from either survives."""
    body1 = _body_of(_generic_secret_with("A"))
    body2 = _body_of(_generic_secret_with("B"))
    text = f'api_key="{body1}\u0332{body2}"'
    redacted = detectors.redact_secrets_strict(text)
    if _independent_reconstruct(redacted, body1) or \
            _independent_reconstruct(redacted, body2):
        return False, "adjacent secrets with combining mark leak fragment"
    return True, "adjacent secrets with combining mark green"


CASES.append(("PR66-S3: adjacent secrets separated by combining mark",
              pr66_surface3_adjacent_secrets_with_combining))


def pr66_surface3_smallcap_inside_jwt():
    """A small-capital-obfuscated secret inside a JWT container must be
    suppressed by the structural-container logic, not leak as a fragment."""
    import base64 as _b64
    secret = _live_secret().replace("A", "\u1D00")
    header = _b64.urlsafe_b64encode(
        json.dumps({"alg": "none"}).encode()).rstrip(b"=")
    payload = _b64.urlsafe_b64encode(
        json.dumps({"key": secret}).encode()).rstrip(b"=")
    jwt = f"{header.decode()}.{payload.decode()}.{'s'*15}"
    redacted = detectors.redact_secrets_strict(jwt)
    if _independent_reconstruct(redacted, _live_secret()):
        return False, "small-cap secret inside JWT leaks"
    return True, "small-cap inside JWT green"


CASES.append(("PR66-S3: small-capital secret inside JWT container",
              pr66_surface3_smallcap_inside_jwt))


# ── Surface 4: trailing-boundary repair ─────────────────────────────────────
def pr66_surface4_trailing_mixed_invisible_mn():
    """A secret value immediately followed by a run of mixed invisible and Mn
    characters must have the entire trailing run swallowed by the redaction."""
    body = _body_of(_generic_secret_with("T"))
    trail = "\u200b\u0332\u200d\u0333\u2060\u0334" * 100
    text = f'api_key="{body}{trail}"'
    redacted = detectors.redact_secrets_strict(text)
    if _independent_reconstruct(redacted, body):
        return False, "mixed invisible/Mn trailing run leaks secret"
    if any(ch in redacted for ch in ("\u200b", "\u0332", "\u200d")):
        return False, "trailing invisible/Mn bytes survived redaction"
    return True, "trailing mixed invisible/Mn green"


CASES.append(("PR66-S4: mixed invisible/Mn trailing run",
              pr66_surface4_trailing_mixed_invisible_mn))


def pr66_surface4_no_over_redaction():
    """The trailing extension must stop at the first non-invisible/non-Mn
    character; legitimate text following a secret must not be redacted."""
    body = _body_of(_generic_secret_with("T"))
    text = f'api_key="{body}"X legitimate suffix'
    redacted = detectors.redact_secrets_strict(text)
    if "legitimate suffix" not in redacted or "X" not in redacted:
        return False, "trailing boundary over-redacted legitimate text"
    return True, "no over-redaction green"


CASES.append(("PR66-S4: trailing boundary does not over-extend",
              pr66_surface4_no_over_redaction))


# ── Surface 5: multilingual false positives ─────────────────────────────────
def pr66_surface5_multilingual_benign():
    """Scripts that legitimately use combining marks or phonetic small capitals
    must not trigger PII matches or unnecessary redaction."""
    samples = [
        "Tiếng Việt có nhiều dấu thanh điệu như á, à, ả, ã, ạ",
        "Èdè Gẹ̀ẹ́sì ni ènìyàn ń sọ láti ìpilẹ̀ṣẹ̀ ọ̀rọ̀",
        "ˈʃɪp ɑːˈstrɑːliə ˈɪŋɡlɪʃ",
        "ру́сский язы́к — великий и могу́чий",
        "þǣre ġefeaġenisse and þǣre worulde",
    ]
    for text in samples:
        if detectors._scan_pii(text):
            return False, f"false PII match in benign sample: {text[:50]!r}"
        redacted = detectors.redact_secrets_strict(text)
        if redacted == detectors._WITHHELD or "redacted" in redacted:
            return False, f"unnecessary redaction of benign sample: {text[:50]!r}"
    return True, "multilingual benign text green"


CASES.append(("PR66-S5: multilingual benign text false positives",
              pr66_surface5_multilingual_benign))


# ── Surface 6: performance ──────────────────────────────────────────────────
def pr66_surface6_performance():
    """Large invisible/Mn runs and many small matches must stay sub-second."""
    body = _body_of(_generic_secret_with("P"))
    # Match immediately followed by 500k mixed invisible/Mn
    payload1 = f'api_key="{body}"' + "\u200b\u0332" * 250_000
    start = _time.perf_counter()
    out1 = detectors.redact_secrets_strict(payload1)
    t1 = _time.perf_counter() - start

    # Many small matches with moderate trailing runs. Every secret is distinct
    # so _scan_normalized's value-based dedup does not drop spans.
    rng = _random.Random(42)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    lines = []
    for i in range(1000):
        parts = []
        for j in range(5):
            body = "".join(rng.choice(alphabet) for _ in range(60)) + f"{i:04d}{j}"
            parts.append(f'api_key="{body}"\u200d\u0332')
        lines.append("".join(parts))
    payload2 = "\n".join(lines)
    start = _time.perf_counter()
    out2 = detectors.redact_secrets_strict(payload2)
    t2 = _time.perf_counter() - start

    # All-combining-mark string with no valid match
    payload3 = "\u0332" * 500_000
    start = _time.perf_counter()
    out3 = detectors.redact_secrets_strict(payload3)
    t3 = _time.perf_counter() - start

    if t1 > 2.0 or t2 > 2.0 or t3 > 2.0:
        return False, f"performance regression: t1={t1:.2f}s t2={t2:.2f}s t3={t3:.2f}s"
    if out1 == detectors._WITHHELD or out2 == detectors._WITHHELD:
        return False, "large benign payloads were withheld"
    return True, f"performance green (t1={t1:.2f}s t2={t2:.2f}s t3={t3:.2f}s)"


CASES.append(("PR66-S6: performance under large invisible/Mn runs",
              pr66_surface6_performance))


# ── Surface 7: every rendered artifact path ─────────────────────────────────
def _prov_report_for_artifact(package, detail="detail"):
    """A Report whose single provenance finding carries attacker-controlled
    package/detail values, driven through all three audit renderers."""
    return Report(
        profile={
            "name": "demo", "path": "/tmp/demo", "runtime": "python",
            "files_scanned": 1, "depth": {"ast": 1, "pattern": 0},
            "package_name": "", "version": "",
        },
        findings=[], deductions=[], score=50, grade="F",
        provenance=[ProvenanceFinding(
            rule="prov-not-in-registry", severity="high", ecosystem="npm",
            package=package, manifest="package.json", detail=detail)])


def pr66_surface7_smallcap_in_all_renderers():
    """A small-capital-obfuscated secret in pf.package must be scrubbed in
    SARIF, JSON audit, and text audit."""
    secret = _live_secret()
    obf_pkg = secret.replace("A", "\u1D00")
    report = _prov_report_for_artifact(obf_pkg)
    for name, renderer in (("SARIF", sarif.render_sarif),
                           ("JSON", render_json),
                           ("TEXT", render_text)):
        try:
            doc = renderer(report)
        except Exception as exc:
            return False, f"{name} renderer crashed: {exc}"
        if _independent_reconstruct(doc, secret):
            return False, f"small-cap secret leaks via {name}"
    return True, "small-cap provenance green in SARIF/JSON/TEXT"


CASES.append(("PR66-S7: small-cap provenance in all audit renderers",
              pr66_surface7_smallcap_in_all_renderers))


def pr66_surface7_combining_mark_in_all_renderers():
    """A combining-mark-obfuscated secret in pf.package/detail must be scrubbed
    in SARIF, JSON audit, and text audit."""
    secret = _live_secret()
    obf_pkg = "".join(c + "\u0332" for c in secret)
    obf_detail = f"detail contains {obf_pkg}"
    report = _prov_report_for_artifact(obf_pkg, obf_detail)
    for name, renderer in (("SARIF", sarif.render_sarif),
                           ("JSON", render_json),
                           ("TEXT", render_text)):
        try:
            doc = renderer(report)
        except Exception as exc:
            return False, f"{name} renderer crashed: {exc}"
        if _independent_reconstruct(doc, secret):
            return False, f"combining-mark secret leaks via {name}"
    return True, "combining-mark provenance green in SARIF/JSON/TEXT"


CASES.append(("PR66-S7: combining-mark provenance in all audit renderers",
              pr66_surface7_combining_mark_in_all_renderers))


def pr66_surface7_html_details_pre_sibling_paths():
    """The issue #64 leak path was report.py's per-event <details><pre> dump of
    raw tool-call content. Verify that sibling paths (schema-violation raw
    frame, tool result, annotation explanation) are also scrubbed."""
    secret = _live_secret()
    obf = secret.replace("A", "\u1D00")
    # Tool argument obfuscation reaches the details<pre> block
    lines = _handshake() + [
        _call(6, 3, "web_search", {"data": obf}),
        _result(7, 3, {"content": [{"type": "text", "text": "ok"}]})]
    html = _render_report(lines)
    if _independent_reconstruct(html, secret):
        return False, "small-cap secret leaks through HTML details<pre> tool argument"

    # Tool result obfuscation
    lines = _handshake() + [
        _call(6, 3, "web_search", {"query": "x"}),
        _result(7, 3, {"content": [{"type": "text", "text": obf}]})]
    html = _render_report(lines)
    if _independent_reconstruct(html, secret):
        return False, "small-cap secret leaks through HTML details<pre> tool result"

    # Runtime session SARIF annotation path (already covered by P4 but re-check
    # with small-cap obfuscation)
    from glassport.interaction_trace import (
        InteractionTrace, Actor, ActorKind, ProtocolKind,
        Event, EventKind, Part, PartKind,
        Annotation, AnnotationKind,
    )
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
            explanation=f"tool call {obf}")],
        metadata={},
    )
    doc = sarif.render_session_sarif(trace, session_path="session.jsonl")
    if _independent_reconstruct(doc, secret):
        return False, "small-cap secret leaks through session SARIF annotation"
    return True, "HTML details<pre> sibling paths and session SARIF green"


CASES.append(("PR66-S7: HTML details<pre> and session SARIF sibling paths",
              pr66_surface7_html_details_pre_sibling_paths))


# ═══════════════════════════════════════════════════════════════════════════
# PR #67 verification pass — round-3 fix closure check
#
# Re-attack the SPECIFIC gaps Kimi's round-3 pass found, using the SAME
# independent oracle (above) and the SAME six real output surfaces. Do not
# expand into a general Unicode hunt.
# ═══════════════════════════════════════════════════════════════════════════

# Round-3 surface set (confirmed complete):
#   (a) sarif.render_sarif          (provenance package + detail)
#   (b) audit.render_json           (provenance)
#   (c) audit.render_text           (provenance)
#   (d) report.render_html          (tool-CALL-argument details<pre>)
#   (e) report.render_html          (tool-RESULT details<pre>)
#   (f) sarif.render_session_sarif  (runtime annotation-explanation)
_SURFACES = [
    ("SARIF-provenance", lambda obf, rpt: sarif.render_sarif(rpt)),
    ("JSON-audit", lambda obf, rpt: render_json(rpt)),
    ("TEXT-audit", lambda obf, rpt: render_text(rpt)),
    ("HTML-tool-call-arg",
     lambda obf, rpt: _render_report(_handshake() + [
         _call(6, 3, "web_search", {"data": obf}),
         _result(7, 3, {"content": [{"type": "text", "text": "ok"}]})])),
    ("HTML-tool-result",
     lambda obf, rpt: _render_report(_handshake() + [
         _call(6, 3, "web_search", {"query": "x"}),
         _result(7, 3, {"content": [{"type": "text", "text": obf}]})])),
    ("SARIF-session-annotation", lambda obf, rpt: _render_session_sarif(obf)),
]


def _render_session_sarif(obf: str) -> str:
    from glassport.interaction_trace import (
        InteractionTrace, Actor, ActorKind, ProtocolKind,
        Event, EventKind, Part, PartKind,
        Annotation, AnnotationKind,
    )
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
            explanation=f"tool call {obf}")],
        metadata={},
    )
    return sarif.render_session_sarif(trace, session_path="session.jsonl")


def _check_all_surfaces(secret_body: str, obf: str) -> tuple[bool, str]:
    """Drive one obfuscated value through all six round-3 surfaces."""
    rpt = _prov_report_for_artifact(obf, f"detail contains {obf}")
    for name, renderer in _SURFACES:
        try:
            doc = renderer(obf, rpt)
        except Exception as exc:
            return False, f"{name} crashed: {type(exc).__name__}: {exc}"
        if _independent_reconstruct(doc, secret_body):
            return False, f"{name} leaks secret"
    return True, "all six surfaces green"


# ── ITEM 1: 19 excluded single-letter small capitals ────────────────────────
def pr67_item1_single_letter_smallcaps_all_surfaces():
    """PR #67 must fold all 19 round-3 excluded single-letter U+1D00 glyphs
    and redact them through every real output surface. Prints the exact
    tested-codepoint list."""
    codepoints = [
        0x1D03, 0x1D06, 0x1D08, 0x1D09, 0x1D0C, 0x1D0E, 0x1D10, 0x1D11,
        0x1D12, 0x1D16, 0x1D17, 0x1D19, 0x1D1A, 0x1D1D, 0x1D1E, 0x1D1F,
        0x1D23, 0x1D24, 0x1D25,
    ]
    fails = []
    for cp in codepoints:
        letter = _INDEP_SMALLCAP[cp]
        secret = _generic_secret_with(letter)
        body = _body_of(secret)
        obf = body.replace(letter, chr(cp))
        ok, detail = _check_all_surfaces(body, obf)
        if not ok:
            fails.append(f"U+{cp:04X} ({letter}) -> {detail}")
    cplist = " ".join(f"U+{cp:04X}" for cp in codepoints)
    if fails:
        return False, f"tested {cplist} | failures: {'; '.join(fails[:3])}"
    return True, f"all 19 codepoints green across 6 surfaces: {cplist}"


CASES.append(("PR67-ITEM1: 19 single-letter small capitals across 6 surfaces",
              pr67_item1_single_letter_smallcaps_all_surfaces))


# ── ITEM 2: 4 excluded ligatures + origin-map boundary behavior ─────────────
def pr67_item2_ligatures_all_surfaces_and_origin():
    """PR #67 must fold the 4 excluded U+1D00 ligatures (AE/OE/OU), correctly
    fan one source index to two normalized chars, and redact fully at every
    boundary. The secret is a complete generic_api_key pattern so the scanner
    actually has something to match."""
    ligatures = [
        (0x1D01, "AE"),
        (0x1D02, "AE"),
        (0x1D14, "OE"),
        (0x1D15, "OU"),
    ]
    fails = []
    for cp, seq in ligatures:
        secret = _generic_secret_with_seq(seq)   # full 'api_key="..."'
        body = _body_of(secret)
        obf = secret.replace(seq, chr(cp))

        # origin-map fan-out: one ligature char -> two normalized chars, both
        # tagged to the SAME source index; no off-by-one at boundaries.
        prefix, suffix = "X", "Y"
        probe = prefix + chr(cp) + suffix
        norm, origin = detectors._normalize_with_map(probe)
        if norm != prefix + seq + suffix:
            fails.append(f"U+{cp:04X} normalize mismatch: {norm!r}")
            continue
        # the two expanded chars must share the ligature's source index
        lig_idx = probe.index(chr(cp))
        if origin != [0] * len(prefix) + [lig_idx, lig_idx] + [lig_idx + 1] * len(suffix):
            fails.append(f"U+{cp:04X} origin map {origin} != fan-out to {lig_idx}")
            continue

        # boundary: complete secret immediately before/after the ligature must
        # not leak a reconstructable fragment.
        for boundary in (secret + chr(cp), chr(cp) + secret):
            redacted = detectors.redact_secrets_strict(boundary)
            if _independent_reconstruct(redacted, body):
                fails.append(f"U+{cp:04X} boundary leak")
                break
        else:
            ok, detail = _check_all_surfaces(body, obf)
            if not ok:
                fails.append(f"U+{cp:04X} surface leak: {detail}")

    if fails:
        return False, "; ".join(fails)
    return True, "4 ligatures green: origin map + boundaries + 6 surfaces"


CASES.append(("PR67-ITEM2: 4 ligatures origin-map + boundaries + 6 surfaces",
              pr67_item2_ligatures_all_surfaces_and_origin))


# ── ITEM 3: Mc/Me combining marks across all surfaces ───────────────────────
def pr67_item3_mc_me_all_surfaces():
    """PR #67 must strip Mc (spacing combining) and Me (enclosing) marks for
    scanning and redact a complete secret obfuscated with them through all 6
    surfaces."""
    # Use a complete pattern so the scanner has a credential to match.
    secret = _live_secret()
    marks = [
        ("\u0903", "Devanagari-visarga-Mc"),
        ("\u0BC1", "Tamil-vowel-U-Mc"),
        ("\u0BC2", "Tamil-vowel-UU-Mc"),
        ("\u20DD", "combining-enclosing-circle-Me"),
        ("\u20E4", "combining-enclosing-triangle-Me"),
    ]
    fails = []
    for mark, name in marks:
        obf = mark.join(secret)
        ok, detail = _check_all_surfaces(secret, obf)
        if not ok:
            fails.append(f"{name}: {detail}")
    if fails:
        return False, "; ".join(fails[:2])
    return True, "Mc/Me marks green across 6 surfaces"


CASES.append(("PR67-ITEM3: Mc/Me marks across 6 surfaces",
              pr67_item3_mc_me_all_surfaces))


# ── ITEM 4: Greek/Cyrillic tail of U+1D00 block is excluded + documented ────
def pr67_item4_greek_cyrillic_tail_excluded():
    """PR #67's manifest must explicitly exclude U+1D26-U+1D2B with written
    rationales, not silently omit them."""
    tail = [0x1D26, 0x1D27, 0x1D28, 0x1D29, 0x1D2A, 0x1D2B]
    manifest = {e.codepoint: e for e in detectors._PHONETIC_EXT_MANIFEST}
    for cp in tail:
        e = manifest.get(cp)
        if e is None:
            return False, f"U+{cp:04X} missing from manifest"
        if e.included:
            return False, f"U+{cp:04X} unexpectedly included"
        if e.target != "":
            return False, f"U+{cp:04X} excluded but target non-empty"
        if "out of scope" not in e.rationale.lower():
            return False, f"U+{cp:04X} rationale lacks 'out of scope': {e.rationale}"
        if cp in detectors._CONFUSABLES:
            return False, f"U+{cp:04X} present in _CONFUSABLES despite exclusion"
    return True, "Greek/Cyrillic tail U+1D26-U+1D2B explicitly excluded and documented"


CASES.append(("PR67-ITEM4: Greek/Cyrillic tail excluded from manifest",
              pr67_item4_greek_cyrillic_tail_excluded))


# ── ITEM 5: false-positive fixtures + one additional sample per family ──────
def pr67_item5_false_positive_fixtures_plus_extra_samples():
    """Confirm PR #67's false-positive fixtures do not fire and do not get
    redacted/withheld; add one independent real-world sample per script family
    to sanity-check coverage."""
    # Independent additions (one per family covered by the PR's fixtures).
    extras = {
        "devanagari_extra": "ॐ असतो मा सद्गमय, तमसो मा ज्योतिर्गमय।",
        "tamil_extra": "அன்பே சிவம், அறிவே பொருள், ஒளியே வாழ்வு.",
        "sinhala_extra": "සියලු මනුෂ්‍යයන්ම නිදහස්ව උපත ලබති.",
        "arabic_diacritized_extra": "السَّلامُ عَلَيْكُمْ وَرَحْمَةُ اللَّهِ وَبَرَكَاتُهُ",
        "enclosing_extra": "Press 3⃣ then 5⃣ to vote.",
        "mixed_script_extra": "The Sanskrit ॐ and Tamil அன்பே both evoke divinity, IPA /ɑːnbeɪ/.",
    }
    for name, text in extras.items():
        if detectors._scan_pii(text):
            return False, f"extra sample {name} triggered false PII match"
        out = detectors.redact_secrets_strict(text)
        if out != text:
            return False, f"extra sample {name} was altered by redaction"
    return True, "independent false-positive samples green"


CASES.append(("PR67-ITEM5: extra false-positive samples per script family",
              pr67_item5_false_positive_fixtures_plus_extra_samples))


# ── ITEM 6: neutralize_text unchanged behavior on Mn/Mc/Me ──────────────────
def pr67_item6_neutralize_text_behavior_recorded():
    """PR #67 must not change neutralize_text's function body; record its
    actual behavior on bare Mn/Mc/Me and on runs exceeding the Zalgo threshold."""
    observations = []
    cases = [
        ("bare Mn", "\u0332"),
        ("bare Mc", "\u0903"),
        ("bare Me", "\u20DD"),
        ("Mn run x10", "A" + "\u0332" * 10),
        ("Mc run x10", "A" + "\u0903" * 10),
        ("Me run x10", "A" + "\u20DD" * 10),
    ]
    for name, text in cases:
        out = detectors.neutralize_text(text)
        kept = sum(1 for c in out if c in text)
        observations.append(f"{name}: keeps {kept} of {len(text)} input chars, sentinel={'‹combining…›' in out}")
    # Sanity: the function still reveals/combines marks rather than silently
    # dropping them (which would be a scan-side policy leaking into display).
    if detectors.neutralize_text("\u0332") == "":
        return False, "neutralize_text silently dropped bare Mn"
    if "‹combining…›" not in detectors.neutralize_text("A" + "\u0332" * 10):
        return False, "neutralize_text no longer collapses excessive Zalgo runs"
    return True, "neutralize_text unchanged; recorded: " + "; ".join(observations)


CASES.append(("PR67-ITEM6: neutralize_text Mn/Mc/Me behavior recorded",
              pr67_item6_neutralize_text_behavior_recorded))


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
