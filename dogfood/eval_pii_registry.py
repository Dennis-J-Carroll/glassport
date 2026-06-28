#!/usr/bin/env python3
"""
Dogfood evaluation of the glassport 0.5.0 PII plugin registry + validator menu.

Campaigns:
  A. Precision on real filesystem-server traffic with realistic non-secrets
     (UUIDs, SHA-256 hashes, base64 blobs, 9-digit IDs, eyJ lookalikes).
  B. Recall with honeytokens injected into real filesystem traffic
     (real IBAN, Luhn-valid card, real-format JWT, canary API keys).
  C. Registry fail-safe for GLASSPORT_PII_PATTERNS
     (malformed JSON, bad regex, unknown validator, ReDoS regex).
  D. Checksum validator correctness + adversarial near-misses
     (IBAN, ABA, base58, JWT, UUID4).
  E. Evasion + DoS (zero-width, homoglyphs, ReDoS timing, oversize cap).
  F. SARIF + redaction integrity (no secret or prefix leaks).

Outputs dogfood/logs/pii_registry_eval_out.json.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from dogfood.driver import run_session, detect_log, summarize_log
from glassport.adapters.mcp_session import from_mcp_session, from_mcp_session_file
from glassport import detectors

if "src/glassport" not in detectors.__file__:
    raise RuntimeError(
        f"eval must use src/glassport, got {detectors.__file__}; "
        "run with PYTHONPATH=src"
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> float:
    return time.perf_counter()


def _rule_id_to_name(detect: dict) -> dict[str, str]:
    """Map SARIF ruleId -> name. ruleId is 'glassport/pii_*', name is 'pii_*'."""
    mapping: dict[str, str] = {}
    for run in detect.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid = rule.get("id", "")
            name = rule.get("name", "")
            if rid and name:
                mapping[rid] = name
    return mapping


def _rule_name(res: dict, mapping: dict[str, str]) -> str:
    rid = res.get("ruleId", "")
    return mapping.get(rid, rid)


def _categories(detect: dict) -> list[str]:
    """Extract PII subcategories from a SARIF detect result."""
    mapping = _rule_id_to_name(detect)
    out = []
    for run in detect.get("runs", []):
        for res in run.get("results", []):
            out.append(_rule_name(res, mapping))
    return out


def _pii_results(detect: dict) -> list[dict]:
    mapping = _rule_id_to_name(detect)
    out = []
    for run in detect.get("runs", []):
        for res in run.get("results", []):
            if _rule_name(res, mapping).startswith("pii_"):
                out.append(res)
    return out


def _clear_env():
    detectors.clear_custom_pii_patterns()
    os.environ.pop("GLASSPORT_PII_PATTERNS", None)


# ---------------------------------------------------------------------------
# Campaign A — Precision on real filesystem traffic
# ---------------------------------------------------------------------------


def campaign_precision() -> dict:
    """Run filesystem server over files full of realistic non-secrets."""
    _clear_env()
    allowed = Path(tempfile.mkdtemp(prefix="glassport-pii-precision-"))

    # Realistic non-secret payloads that might collide with PII patterns.
    precision_files = {
        "uuid.txt": "550e8400-e29b-41d4-a716-446655440000",
        "sha256.txt": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5.txt": "d41d8cd98f00b204e9800998ecf8427e",
        "base64_js.txt": "eyJnotavalidjwtsegment.aaaaaaa.bbbbbbb " * 10,  # eyJ lookalike, not a JWT
        "real_jwt.txt": _make_jwt(),  # real-format JWT in a server response
        "nine_digit.txt": "123456789 987654321 000000000",
        "iban_lookalike.txt": "GB99WEST12345698765432 NO1234567890123",
        "random_b64.txt": base64.b64encode(os.urandom(256)).decode(),
        "request_ids.txt": "req_550e8400e29b41d4a716446655440000 id-abc123def456",
    }
    for name, content in precision_files.items():
        (allowed / name).write_text(content, encoding="utf-8")

    calls = [
        {"name": "read_file", "arguments": {"path": str(allowed / name)}}
        for name in precision_files
    ] + [
        {"name": "list_directory", "arguments": {"path": str(allowed)}},
    ]

    result = run_session(
        name="pii-precision",
        cmd=["npx", "-y", "@modelcontextprotocol/server-filesystem", str(allowed)],
        calls=calls,
        timeout=60.0,
    )

    detect = detect_log(result.log_path) if result.log_path else {}
    pii = _pii_results(detect)

    return {
        "allowed_dir": str(allowed),
        "log_path": str(result.log_path) if result.log_path else None,
        "error": result.error,
        "stderr": result.stderr,
        "fp_count": len(pii),
        "false_positives": [
            {
                "ruleId": r.get("ruleId"),
                "message": r.get("message", {}).get("text", "")[:200],
            }
            for r in pii
        ],
    }


# ---------------------------------------------------------------------------
# Campaign B — Recall with honeytokens via real filesystem traffic
# ---------------------------------------------------------------------------


def _make_jwt() -> str:
    """Real-format HS256 JWT with a throwaway secret."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "canary", "iat": 1710000000}).encode()
    ).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(
        hmac.new(b"canary-secret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"


def campaign_recall() -> dict:
    """Inject honeytokens into filesystem tool args and file content."""
    _clear_env()
    allowed = Path(tempfile.mkdtemp(prefix="glassport-pii-recall-"))

    honeytokens = {
        "iban": "DE89370400440532013000",
        "credit_card": "4111111111111111",
        "ssn": "123-45-6789",
        "jwt": _make_jwt(),
        "aws_access": "AKIAIOSFODNN7EXAMPLE",
        "openai_key": "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
        "github_token": "ghp_" + "a" * 36,
        "database_url": "postgresql://user:p4ssw0rd@db.example.com:5432/app",
        "rsa_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBALRiMLAH...\n-----END RSA PRIVATE KEY-----",
    }

    # Write honeytokens into files and read them back; also put secrets in
    # tool-call arguments (write_file content) so severity-2 patterns like
    # jwt_token are scanned in args, not just severity-3 result scanning.
    (allowed / "tokens.txt").write_text(
        "\n".join(f"{k}={v}" for k, v in honeytokens.items()), encoding="utf-8"
    )
    (allowed / "iban.txt").write_text(honeytokens["iban"], encoding="utf-8")
    calls = [
        {"name": "read_file", "arguments": {"path": str(allowed / "tokens.txt")}},
        {"name": "write_file", "arguments": {
            "path": str(allowed / "cc.txt"),
            "content": honeytokens["credit_card"],
        }},
        {"name": "write_file", "arguments": {
            "path": str(allowed / "jwt.txt"),
            "content": honeytokens["jwt"],
        }},
        {"name": "read_file", "arguments": {"path": str(allowed / "iban.txt")}},
    ]

    result = run_session(
        name="pii-recall",
        cmd=["npx", "-y", "@modelcontextprotocol/server-filesystem", str(allowed)],
        calls=calls,
        timeout=60.0,
    )

    detect = detect_log(result.log_path) if result.log_path else {}
    found_subcats = set(_categories(detect))
    # Result-side leaks are reported as pii_in_result_<category>; treat them
    # as detections of the same category for recall scoring.
    found_cats = set()
    for sub in found_subcats:
        cat = sub.replace("pii_in_result_", "").replace("pii_", "")
        found_cats.add(cat)
    expected_cats = {
        "iban", "credit_card", "ssn", "jwt_token", "aws_access_key",
        "openai_key", "github_token", "database_url",
    }
    misses = sorted(expected_cats - found_cats)

    return {
        "allowed_dir": str(allowed),
        "log_path": str(result.log_path) if result.log_path else None,
        "error": result.error,
        "found_subcategories": sorted(found_subcats),
        "expected_categories": sorted(expected_cats),
        "missed_categories": misses,
        "recall_miss_count": len(misses),
    }


# ---------------------------------------------------------------------------
# Campaign C — Registry fail-safe
# ---------------------------------------------------------------------------


def _run_env_fail_safe(tmp: Path, filename: str, content: str) -> dict:
    _clear_env()
    bad = tmp / filename
    bad.write_text(content, encoding="utf-8")
    os.environ["GLASSPORT_PII_PATTERNS"] = str(bad)

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        # Force scan of built-in email pattern.
        lines = [
            json.dumps({"schema_version": "0.1", "seq": 1, "ts": "t1",
                        "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 1,
                        "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                        "capabilities": {}, "clientInfo": {"name": "test"}}},
                        "raw": None}),
            json.dumps({"schema_version": "0.1", "seq": 2, "ts": "t2",
                        "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 1,
                        "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                                   "serverInfo": {"name": "srv"}}}, "raw": None}),
            json.dumps({"schema_version": "0.1", "seq": 3, "ts": "t3",
                        "dir": "c2s", "frame": {"jsonrpc": "2.0",
                        "method": "notifications/initialized"}, "raw": None}),
            json.dumps({"schema_version": "0.1", "seq": 4, "ts": "t4",
                        "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 2,
                        "method": "tools/list"}, "raw": None}),
            json.dumps({"schema_version": "0.1", "seq": 5, "ts": "t5",
                        "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 2,
                        "result": {"tools": [{"name": "sync", "inputSchema": {"type": "object",
                         "properties": {"x": {"type": "string"}}, "required": ["x"]}}]}},
                        "raw": None}),
            json.dumps({"schema_version": "0.1", "seq": 6, "ts": "t6",
                        "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 3,
                        "method": "tools/call", "params": {"name": "sync",
                        "arguments": {"x": "reach bob@example.com"}}}, "raw": None}),
        ]
        try:
            anns = detectors.data_exfiltration(from_mcp_session(lines))
        except Exception as exc:
            return {"crashed": True, "exception": repr(exc), "stderr": err.getvalue()}

    cats = [a.metadata.get("pii_category") for a in anns]
    return {
        "crashed": False,
        "email_found": "email_address" in cats,
        "stderr": err.getvalue(),
        "annotations": len(anns),
    }


import contextlib


def campaign_registry_failsafe() -> dict:
    """Attack GLASSPORT_PII_PATTERNS env autoload."""
    tmp = Path(tempfile.mkdtemp(prefix="glassport-pii-failsafe-"))

    cases = [
        ("malformed_json", "{ this is not valid json "),
        ("non_array", '{"category":"x"}'),
        ("missing_field", '[{"category":"x","severity":3,"pattern":"foo"}]'),
        ("bad_severity", '[{"category":"x","severity":9,"pattern":"foo","description":"x"}]'),
        ("bad_regex", '[{"category":"x","severity":3,"pattern":"(unclosed","description":"x"}]'),
        ("unknown_validator", '[{"category":"x","severity":3,"pattern":"foo","validator":"no_such","description":"x"}]'),
        ("redos_regex", '[{"category":"x","severity":3,"pattern":"(a+)+$","validator":"entropy","description":"x"}]'),
    ]

    results = {}
    for label, content in cases:
        results[label] = _run_env_fail_safe(tmp, f"{label}.json", content)

    # Also confirm opt-in packs are off by default and on when pointed at.
    _clear_env()
    lines = [
        json.dumps({"schema_version": "0.1", "seq": 1, "ts": "t1",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 1,
                    "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                    "capabilities": {}, "clientInfo": {"name": "test"}}},
                    "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 2, "ts": "t2",
                    "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 1,
                    "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                               "serverInfo": {"name": "srv"}}}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 3, "ts": "t3",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0",
                    "method": "notifications/initialized"}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 4, "ts": "t4",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 2,
                    "method": "tools/list"}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 5, "ts": "t5",
                    "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 2,
                    "result": {"tools": [{"name": "sync", "inputSchema": {"type": "object",
                     "properties": {"x": {"type": "string"}}, "required": ["x"]}}]}},
                    "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 6, "ts": "t6",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 3,
                    "method": "tools/call", "params": {"name": "sync",
                    "arguments": {"x": "021000021"}}}, "raw": None}),
    ]
    off_default = detectors.data_exfiltration(from_mcp_session(lines))
    results["aba_off_by_default"] = {
        "aba_found": any(a.metadata.get("pii_category") == "aba_routing" for a in off_default),
    }

    _clear_env()
    os.environ["GLASSPORT_PII_PATTERNS"] = str(ROOT / "examples" / "pii-financial.json")
    on_pack = detectors.data_exfiltration(from_mcp_session(lines))
    results["aba_on_with_pack"] = {
        "aba_found": any(a.metadata.get("pii_category") == "aba_routing" for a in on_pack),
    }

    _clear_env()
    return {"tmp": str(tmp), "cases": results}


# ---------------------------------------------------------------------------
# Campaign D — Checksum correctness + near-misses
# ---------------------------------------------------------------------------


def campaign_checksums() -> dict:
    """Direct validator tests against valid, corrupted, and structurally-valid fakes."""
    _clear_env()

    iban_valid = ["DE89370400440532013000", "GB82WEST12345698765432"]
    iban_corrupt = ["DE89370400440532013001", "GB82WEST12345698765433"]

    aba_valid = ["021000021", "011401533"]
    aba_corrupt = ["021000022", "991000020"]  # 99 outside Fed range

    # Real BTC testnet address and a random base58 string.
    b58_valid = ["mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]
    b58_invalid = ["mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRhA"]  # corrupted checksum

    jwt_valid = [_make_jwt()]
    jwt_lookalike = ["eyJnotreal.invalid.signature"]

    uuid_valid = ["550e8400-e29b-41d4-a716-446655440000"]
    uuid_invalid = ["550e8400-e29b-41d4-5a71-644665544000"]  # version 5, variant wrong

    results = {
        "iban": {
            "tp": sum(detectors._iban_check(v) for v in iban_valid),
            "fp": sum(detectors._iban_check(v) for v in iban_corrupt),
        },
        "aba": {
            "tp": sum(detectors._aba_check(v) for v in aba_valid),
            "fp": sum(detectors._aba_check(v) for v in aba_corrupt),
        },
        "base58": {
            "tp": sum(detectors._base58check_check(v) for v in b58_valid),
            "fp": sum(detectors._base58check_check(v) for v in b58_invalid),
        },
        "jwt": {
            "tp": sum(detectors._jwt_check(v) for v in jwt_valid),
            "fp": sum(detectors._jwt_check(v) for v in jwt_lookalike),
        },
        "uuid4": {
            "tp": sum(detectors._uuid4_check(v) for v in uuid_valid),
            "fp": sum(detectors._uuid4_check(v) for v in uuid_invalid),
        },
    }

    # End-to-end: corrupted IBAN must not fire default pattern.
    lines = [
        json.dumps({"schema_version": "0.1", "seq": 1, "ts": "t1",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 1,
                    "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                    "capabilities": {}, "clientInfo": {"name": "test"}}},
                    "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 2, "ts": "t2",
                    "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 1,
                    "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                               "serverInfo": {"name": "srv"}}}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 3, "ts": "t3",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0",
                    "method": "notifications/initialized"}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 4, "ts": "t4",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 2,
                    "method": "tools/list"}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 5, "ts": "t5",
                    "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 2,
                    "result": {"tools": [{"name": "sync", "inputSchema": {"type": "object",
                     "properties": {"x": {"type": "string"}}, "required": ["x"]}}]}},
                    "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 6, "ts": "t6",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 3,
                    "method": "tools/call", "params": {"name": "sync",
                    "arguments": {"x": " ".join(iban_corrupt)}}}, "raw": None}),
    ]
    anns = detectors.data_exfiltration(from_mcp_session(lines))
    results["corrupted_iban_e2e_no_fire"] = not any(
        a.metadata.get("pii_category") == "iban" for a in anns
    )

    return results


# ---------------------------------------------------------------------------
# Campaign E — Evasion + DoS
# ---------------------------------------------------------------------------


def _build_log_with_arg(x: str) -> list[str]:
    return [
        json.dumps({"schema_version": "0.1", "seq": 1, "ts": "t1",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 1,
                    "method": "initialize", "params": {"protocolVersion": "2025-03-26",
                    "capabilities": {}, "clientInfo": {"name": "test"}}},
                    "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 2, "ts": "t2",
                    "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 1,
                    "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                               "serverInfo": {"name": "srv"}}}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 3, "ts": "t3",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0",
                    "method": "notifications/initialized"}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 4, "ts": "t4",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 2,
                    "method": "tools/list"}, "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 5, "ts": "t5",
                    "dir": "s2c", "frame": {"jsonrpc": "2.0", "id": 2,
                    "result": {"tools": [{"name": "sync", "inputSchema": {"type": "object",
                     "properties": {"x": {"type": "string"}}, "required": ["x"]}}]}},
                    "raw": None}),
        json.dumps({"schema_version": "0.1", "seq": 6, "ts": "t6",
                    "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 3,
                    "method": "tools/call", "params": {"name": "sync",
                    "arguments": {"x": x}}}, "raw": None}),
    ]


def campaign_evasion_dos() -> dict:
    """Zero-width, homoglyphs, ReDoS, oversize."""
    _clear_env()

    base_cc = "4111111111111111"
    zwsp = "\u200b"
    obfuscated_cc = zwsp.join(base_cc)
    fullwidth_cc = "".join(chr(ord(c) + 0xFEE0) for c in base_cc)

    zwsp_hits = detectors.data_exfiltration(from_mcp_session(_build_log_with_arg(obfuscated_cc)))
    fullwidth_hits = detectors.data_exfiltration(from_mcp_session(_build_log_with_arg(fullwidth_cc)))

    # ReDoS timing per pattern family against ~1 MB adversarial input.
    redos_inputs = {
        "iban": "GB" + "99" + "A" * 500_000,
        "jwt": "eyJ" + "a" * 500_000 + ".eyJ.a",
        "base58_pack": "1" * 500_000,
        "email": "a" * 500_000 + "@x.co",
        "credit_card": "4" * 500_000,
    }
    timings = {}
    for name, payload in redos_inputs.items():
        t0 = _now()
        detectors._scan_pii(payload)
        timings[name] = round((_now() - t0) * 1000, 2)

    # Oversize: secret at start should be caught; secret at end of 2 MB should be missed.
    big_prefix = "x" * (detectors.MAX_SCAN_BYTES + 100_000)
    oversize_start = base_cc + big_prefix
    oversize_end = big_prefix + base_cc
    hits_start = detectors._scan_pii(oversize_start)
    hits_end = detectors._scan_pii(oversize_end)

    return {
        "zero_width": {
            "hit": any(a.metadata.get("pii_category") == "credit_card" for a in zwsp_hits),
        },
        "fullwidth": {
            "hit": any(a.metadata.get("pii_category") == "credit_card" for a in fullwidth_hits),
        },
        "redos_ms_1mb": timings,
        "oversize": {
            "cap_bytes": detectors.MAX_SCAN_BYTES,
            "secret_at_start_hit": any(p.category == "credit_card" for p, _ in hits_start),
            "secret_at_end_hit": any(p.category == "credit_card" for p, _ in hits_end),
        },
    }


# ---------------------------------------------------------------------------
# Campaign F — SARIF + redaction integrity
# ---------------------------------------------------------------------------


def campaign_redaction() -> dict:
    """Confirm no raw secret or prefix leaks in SARIF or text output."""
    _clear_env()
    allowed = Path(tempfile.mkdtemp(prefix="glassport-pii-redact-"))

    secrets = {
        "cc": "4111111111111111",
        "iban": "DE89370400440532013000",
        "jwt": _make_jwt(),
        "openai": "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
    }
    (allowed / "secret.txt").write_text(
        "\n".join(secrets.values()), encoding="utf-8"
    )

    result = run_session(
        name="pii-redaction",
        cmd=["npx", "-y", "@modelcontextprotocol/server-filesystem", str(allowed)],
        calls=[{"name": "read_file", "arguments": {"path": str(allowed / "secret.txt")}}],
        timeout=60.0,
    )

    detect = detect_log(result.log_path) if result.log_path else {}
    detect_text = json.dumps(detect, ensure_ascii=False)
    summary = summarize_log(result.log_path) if result.log_path else {}
    summary_text = json.dumps(summary, ensure_ascii=False)

    leaks = []
    for name, secret in secrets.items():
        for label, text in [("sarif", detect_text), ("summarize", summary_text)]:
            if secret in text:
                leaks.append(f"{name} raw secret leaked in {label}")
            if secret[:6] in text:
                leaks.append(f"{name} 6-char prefix leaked in {label}")

    return {
        "allowed_dir": str(allowed),
        "log_path": str(result.log_path) if result.log_path else None,
        "leaks": leaks,
        "pii_count": len(_pii_results(detect)),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> dict:
    _clear_env()
    report = {
        "campaign_a_precision": campaign_precision(),
        "campaign_b_recall": campaign_recall(),
        "campaign_c_registry_failsafe": campaign_registry_failsafe(),
        "campaign_d_checksums": campaign_checksums(),
        "campaign_e_evasion_dos": campaign_evasion_dos(),
        "campaign_f_redaction": campaign_redaction(),
    }
    out = ROOT / "dogfood" / "logs" / "pii_registry_eval_out.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, default=str))
    return report


if __name__ == "__main__":
    main()
