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
