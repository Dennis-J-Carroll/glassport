"""
sarif.py — SARIF 2.1.0 export of a static audit Report for the GitHub
Security tab (code scanning) and any other SARIF consumer.

Two design choices make this actually render in GitHub rather than just
upload cleanly:

  * Locations are REPO-RELATIVE (Finding.path is already relative to the
    audited root, with a line). GitHub maps results onto the diff only
    when the artifactLocation.uri is a repo path — never a $HOME session
    file or a file:// URL, so we emit neither.

  * One severity vocabulary. Audit findings carry string severities and
    runtime detector annotations carry ints; _sarif_level() folds both
    onto the same SARIF level so a single report can mix sources without
    the CI counting two different scales.

    render_sarif(report) -> str           # SARIF JSON
"""
from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Union

from glassport.audit import Report, RULES_BY_ID

DRIVER_VERSION = "0.2.0"
_INFO_URI = "https://github.com/Dennis-J-Carroll/glassport"

# string (audit) and int (detector) severities collapse to one scale
_STR_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
              "low": "note", "note": "note", "info": "note"}
_INT_LEVEL = {3: "error", 2: "warning", 1: "note"}


def _sarif_level(severity: Union[str, int]) -> str:
    """Unified severity → SARIF level (error/warning/note)."""
    if isinstance(severity, bool):                  # bool is an int subclass
        severity = int(severity)
    if isinstance(severity, int):
        return _INT_LEVEL.get(severity, "warning")
    return _STR_LEVEL.get(str(severity).lower(), "warning")


def _sarif_document(rules: list, results: list, props: dict | None = None) -> str:
    """Wrap rules + results in the SARIF 2.1.0 run envelope. Shared by the
    static-audit and runtime-annotation renderers."""
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "glassport",
                "version": DRIVER_VERSION,
                "semanticVersion": DRIVER_VERSION,
                "informationUri": _INFO_URI,
                "rules": rules,
            }},
            "results": results,
            "columnKind": "utf16CodeUnits",
            "properties": props or {},
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _rule_object(rule_id: str, severity: str) -> dict:
    """SARIF reportingDescriptor, enriched from the audit rule catalog."""
    meta = RULES_BY_ID.get(rule_id)
    short = meta.title if meta else rule_id.replace("-", " ").title()
    full = meta.why if meta else short
    obj = {
        "id": f"glassport/{rule_id}",
        "name": rule_id,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "defaultConfiguration": {"level": _sarif_level(severity)},
        "properties": {"tags": ["security", "mcp", "glassport"]
                       + ([meta.category] if meta else [])},
    }
    if meta and meta.fix:
        obj["help"] = {"text": meta.fix}
    return obj


def _repo_uri(path: str, base: str) -> str:
    """Finding.path is relative to the audited root; prefix it with `base`
    (the audited root, itself relative to the repo root) so GitHub code
    scanning annotates the right file. Absolute paths pass through."""
    p = (path or "").replace("\\", "/")
    if not base or posixpath.isabs(p):
        return p
    return posixpath.normpath(posixpath.join(base.replace("\\", "/"), p))


def render_sarif(report: Report, base: str = "") -> str:
    """Render a static audit Report as a SARIF 2.1.0 document (JSON str).

    `base` is the audited root relative to the repository root (e.g.
    "mcp-servers/srv"); pass the path you handed to `audit` so result
    locations resolve from the repo root in the GitHub Security tab."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in report.findings:
        rule_id = f"glassport/{f.rule}"
        if rule_id not in rules:
            rules[rule_id] = _rule_object(f.rule, f.severity)
        meta = RULES_BY_ID.get(f.rule)
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f.detail or (meta.title if meta else f.rule)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _repo_uri(f.path, base)},
                    "region": {"startLine": max(1, int(f.line or 1))},
                },
            }],
            "partialFingerprints": {
                "glassportRulePath": f"{f.rule}:{f.path}:{f.line}"},
            "properties": {"severity": f.severity, "count": f.count},
        })

    return _sarif_document(list(rules.values()), results,
                           {"score": report.score, "grade": report.grade})


# subcategory -> human short description; fallback humanizes the slug
_RUNTIME_RULE_TEXT = {
    "fabricated_tool_call": "Tool call outside the declared surface",
    "capability_violation": "Server used a capability the client never granted",
    "schema_violation": "Call arguments violate the declared inputSchema",
    "unexpected_egress_host": "Tool call reached an undeclared host",
    "premature_call": "tools/call issued before notifications/initialized",
    "call_before_declaration": "tools/call before any tools/list was seen",
    "gate_blocked": "Gate blocked a call outside the declared surface",
    "gate_injected_response": "Gate synthesized the error reply",
    "gate_skipped": "Gate forwarded a call (no surface declared yet)",
    "detector_error": "A detector raised during analysis",
}


def _seq_to_line(session_path: str) -> dict:
    """Map each log entry's `seq` to its 1-based line number in the file.
    Empty/unreadable path -> {}. Lines without a seq are skipped."""
    out: dict = {}
    if not session_path:
        return out
    try:
        with open(session_path, encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    seq = json.loads(raw).get("seq")
                except json.JSONDecodeError:
                    continue
                if seq is not None:
                    out[seq] = lineno
    except OSError:
        pass
    return out


def _runtime_rule_object(ann) -> dict:
    """SARIF reportingDescriptor for one annotation's subcategory.

    The data_exfiltration detector mints subcategories dynamically
    (pii_<category>, pii_in_result_<category>), so match those by prefix
    rather than enumerating every PII category."""
    sub = ann.subcategory or "annotation"
    if sub in _RUNTIME_RULE_TEXT:
        short = _RUNTIME_RULE_TEXT[sub]
    elif sub.startswith("pii_in_result_"):
        short = "Secret or PII leaked back in a tool result"
    elif sub.startswith("pii_"):
        short = "Secret or PII in tool-call arguments"
    else:
        short = sub.replace("_", " ").capitalize()
    return {
        "id": f"glassport/{sub}",
        "name": sub,
        "shortDescription": {"text": short},
        "defaultConfiguration": {"level": _sarif_level(ann.severity)},
        "properties": {"tags": ["glassport", "runtime", ann.kind.value]},
    }


def render_session_sarif(trace, session_path: str = "", base: str = "") -> str:
    """Render a session trace's detector annotations as SARIF 2.1.0 (JSON str).

    Results are located into the session `.jsonl` itself: artifactLocation.uri
    is `session_path` (prefixed with `base` so it resolves from the repo root
    in the GitHub Security tab; absolute paths pass through unchanged),
    region.startLine is the annotation's event's line in that log. `seq` rides
    in partialFingerprints for stable identity."""
    seq_line = _seq_to_line(session_path)
    uri = _repo_uri(session_path, base)
    event_by_id = {e.id: e for e in trace.events}
    rules: dict = {}
    results: list = []

    for a in trace.annotations:
        rule_id = f"glassport/{a.subcategory or 'annotation'}"
        if rule_id not in rules:
            rules[rule_id] = _runtime_rule_object(a)
        ev = event_by_id.get(a.event_id)
        seq = ev.metadata.get("seq") if ev else None
        line = seq_line.get(seq, 1)
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(a.severity),
            "message": {"text": a.explanation or a.subcategory or rule_id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, int(line))},
                },
            }],
            "partialFingerprints": {
                "glassportSeq": f"{a.subcategory}:{seq}"},
            "properties": {"severity": a.severity, "kind": a.kind.value,
                           "subcategory": a.subcategory},
        })

    props = {"session": Path(session_path).name if session_path else "",
             "annotation_count": len(trace.annotations)}
    return _sarif_document(list(rules.values()), results, props)
