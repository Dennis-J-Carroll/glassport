"""Canonical findings ledger for the 0.6.10 stabilization.

Atomic (tmp + rename), validate-before-write, idempotent upsert by id.
Consumers read the ledger; they never rewrite the canonical schema.
Only the General flips status provisional -> verified.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

REQUIRED_FIELDS = ("id", "title", "status", "severity", "metrics",
                   "provenance", "depends_on", "explanation")
VALID_STATUS = ("provisional", "verified")
VALID_SEVERITY = ("P0", "P1", "P2", "P3", "info")


def validate_finding(finding: dict) -> None:
    """Raise ValueError on any schema violation. Total over dict input."""
    if not isinstance(finding, dict):
        raise ValueError("finding must be a dict")
    for field in REQUIRED_FIELDS:
        if field not in finding:
            raise ValueError(f"finding missing required field: {field}")
    if not isinstance(finding["id"], str) or not finding["id"]:
        raise ValueError("finding id must be a non-empty string")
    if finding["status"] not in VALID_STATUS:
        raise ValueError(f"invalid status: {finding['status']!r}")
    if finding["severity"] not in VALID_SEVERITY:
        raise ValueError(f"invalid severity: {finding['severity']!r}")
    if not isinstance(finding["metrics"], dict):
        raise ValueError("metrics must be a dict")
    if not isinstance(finding["depends_on"], list):
        raise ValueError("depends_on must be a list")
    if not isinstance(finding["explanation"], str) or not finding["explanation"].strip():
        raise ValueError("explanation is required at append time")


def load_ledger(ledger_path: Path) -> dict:
    """Load and validate the whole ledger. Raises ValueError on corruption."""
    ledger_path = Path(ledger_path)
    if not ledger_path.exists():
        return {"schema": "glassport-stabilization-ledger/1", "findings": {}}
    with open(ledger_path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError("ledger missing findings map")
    if not isinstance(data["findings"], dict):
        raise ValueError("findings must be a map keyed by id")
    for fid, finding in data["findings"].items():
        validate_finding(finding)
        if finding["id"] != fid:
            raise ValueError(f"finding key {fid!r} != finding id {finding['id']!r}")
    return data


def upsert_finding(ledger_path: Path, finding: dict) -> None:
    """Validate, then atomically upsert one finding by id (idempotent)."""
    validate_finding(finding)
    ledger_path = Path(ledger_path)
    data = load_ledger(ledger_path)
    data["findings"][finding["id"]] = finding
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=ledger_path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, ledger_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
