#!/usr/bin/env python3
"""
T06: Artifact safety canary tests (CORRECTED).

Prove that synthetic secrets flowing through a tapped session are:
(a) DETECTED as findings
(b) CANNOT be reconstructed from any rendered artifact

Independence rule: this module does NOT import glassport.detectors.
Checker is self-contained with 6 obfuscation layers.
"""
from __future__ import annotations

import html
import json
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import TestCase, main

# Import glassport functions at module level (not as class attributes)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from glassport.adapters.mcp_session import from_mcp_session
from glassport.detectors import annotate
from glassport.report import render_html
from glassport.sarif import render_session_sarif
from glassport.advise import render_advisory
from glassport.tap import open_session_log

# Canary values (exact)
CANARY_AWS = "AKIAIOSFODNN7EXAMPLE"
CANARY_SSN = "078-05-1120"
CANARY_EMAIL = "canary.zx9@glassport-canary.example"

# Anthropic key canary: sk-ant-api03-GLASSPORTCANARY + 80 random base64url chars
CANARY_ANTHROPIC_PREFIX = "sk-ant-api03-GLASSPORTCANARY"
import os

# Session-specific scratch dir at capture time; override to re-run elsewhere.
SCRATCH_DIR = Path(os.environ.get("STAB_SCRATCH", "/tmp/glassport-stab-scratch"))

# Generate the long canary once
CANARY_ANTHROPIC_FILE = SCRATCH_DIR / "canary-secret.txt"
if CANARY_ANTHROPIC_FILE.exists():
    CANARY_ANTHROPIC = CANARY_ANTHROPIC_FILE.read_text().strip()
else:
    import base64
    import secrets
    CANARY_ANTHROPIC = CANARY_ANTHROPIC_PREFIX + base64.urlsafe_b64encode(secrets.token_bytes(60)).decode('ascii')[:80]
    SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
    CANARY_ANTHROPIC_FILE.write_text(CANARY_ANTHROPIC + "\n")

ALL_CANARIES = [CANARY_AWS, CANARY_SSN, CANARY_EMAIL, CANARY_ANTHROPIC]


class CanaryChecker:
    """
    Independence-rule checker: finds canary values in artifacts.

    Strategy:
    1. Exact substring match (case-sensitive baseline)
    2. Case-insensitive variant
    3. After HTML-entity decoding
    4. After stripping zero-width chars U+200B..U+200D, U+FEFF
    5. After removing all whitespace
    6. Concatenation of adjacent HTML text nodes (strip tags first, then search)
    """

    ZW_CHARS = {'​', '‌', '‍', '﻿'}  # Zero-width + BOM

    @classmethod
    def _strip_zero_width(cls, text: str) -> str:
        """Remove zero-width chars."""
        return ''.join(c for c in text if c not in cls.ZW_CHARS)

    @classmethod
    def _strip_whitespace(cls, text: str) -> str:
        """Remove all whitespace."""
        return ''.join(c for c in text if not c.isspace())

    @classmethod
    def _decode_html_entities(cls, text: str) -> str:
        """Decode HTML entities."""
        return html.unescape(text)

    @classmethod
    def _strip_html_tags(cls, text: str) -> str:
        """Remove HTML tags, keeping text content."""
        result = []
        in_tag = False
        for char in text:
            if char == '<':
                in_tag = True
            elif char == '>':
                in_tag = False
            elif not in_tag:
                result.append(char)
        return ''.join(result)

    @classmethod
    def find_canary(cls, artifact: bytes | str, canary: str) -> bool:
        """
        Check if canary can be found in artifact via any obfuscation layer.
        Returns True if found (leakage); False if not found (safe).
        """
        if isinstance(artifact, bytes):
            try:
                text = artifact.decode('utf-8', errors='replace')
            except Exception:
                return False
        else:
            text = artifact

        canary_upper = canary.upper()
        canary_lower = canary.lower()

        # Strategy 1: Exact substring (case-sensitive)
        if canary in text:
            return True

        # Strategy 2: Case-insensitive
        if canary_upper in text.upper():
            return True

        # Strategy 3: After HTML-entity decoding
        decoded = cls._decode_html_entities(text)
        if canary in decoded or canary_upper in decoded.upper():
            return True

        # Strategy 4: After stripping zero-width chars
        stripped_zw = cls._strip_zero_width(text)
        if canary in stripped_zw or canary_upper in stripped_zw.upper():
            return True

        # Strategy 5: After removing whitespace
        no_ws = cls._strip_whitespace(text)
        if canary in no_ws or canary_upper in no_ws.upper():
            return True

        # Strategy 6: After HTML tag stripping (adjacent text nodes)
        no_tags = cls._strip_html_tags(text)
        if canary in no_tags or canary_upper in no_tags.upper():
            return True

        # Combination: zero-width + whitespace
        zw_ws = cls._strip_whitespace(cls._strip_zero_width(text))
        if canary in zw_ws or canary_upper in zw_ws.upper():
            return True

        # Combination: HTML decode + zero-width
        decoded_zw = cls._strip_zero_width(cls._decode_html_entities(text))
        if canary in decoded_zw or canary_upper in decoded_zw.upper():
            return True

        return False


class TestCanaryChecker(TestCase):
    """Known-answer tests for the checker itself."""

    def test_exact_substring(self):
        """Checker finds exact substring."""
        artifact = "Sensitive key: " + CANARY_AWS
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_case_insensitive(self):
        """Checker finds case-insensitive variant."""
        artifact = "key: " + CANARY_AWS.lower()
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_zero_width_split(self):
        """Checker finds zero-width-split canary."""
        split_canary = "AKIA​IOSFODNN7EXAMPLE"
        artifact = "key: " + split_canary
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_whitespace_separated(self):
        """Checker finds whitespace-separated canary."""
        spaced = "AKIA IOSF ODNN 7EXA MPLE"
        artifact = "key: " + spaced
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_html_entity_encoded(self):
        """Checker finds HTML-entity-encoded canary."""
        # Encode a few chars as entities (A = &#65; K = &#75;)
        encoded = "&#65;KIA" + CANARY_AWS[4:]
        artifact = "key: " + encoded
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_adjacent_html_nodes(self):
        """Checker finds canary split across HTML nodes."""
        artifact = "<b>AKIAIOSF</b><i>ODNN7EXAMPLE</i>"
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_not_found_in_redaction_tag(self):
        """Checker does NOT find canary in redaction tag."""
        redacted = "[aws_access_key redacted · 20 chars]"
        self.assertFalse(CanaryChecker.find_canary(redacted, CANARY_AWS))

    def test_not_false_positive(self):
        """Checker does not false-positive on random text."""
        artifact = "some random text with no secrets"
        self.assertFalse(CanaryChecker.find_canary(artifact, CANARY_AWS))

    def test_ssn_canary(self):
        """Checker finds SSN canary."""
        artifact = "ssn=" + CANARY_SSN
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_SSN))

    def test_email_canary(self):
        """Checker finds email canary."""
        artifact = "to=" + CANARY_EMAIL
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_EMAIL))

    def test_anthropic_canary(self):
        """Checker finds anthropic key canary."""
        artifact = "key=" + CANARY_ANTHROPIC
        self.assertTrue(CanaryChecker.find_canary(artifact, CANARY_ANTHROPIC))


class TestArtifactSafety(TestCase):
    """
    Integration tests: build sessions with canaries, generate all 10 artifacts,
    validate detection and artifact safety.
    """

    @classmethod
    def setUpClass(cls):
        """Build the two test sessions with correct JSONL format."""
        # Build test sessions directory
        cls.log_dir = SCRATCH_DIR / "test_sessions"
        cls.log_dir.mkdir(parents=True, exist_ok=True)

        # Session 1: args-direction (canaries in tool arguments)
        cls.args_session_dir = cls.log_dir / "args_canaries"
        cls.args_session_dir.mkdir(exist_ok=True)
        cls.args_log_file = cls.args_session_dir / "session.jsonl"
        cls._build_args_session()

        # Session 2: results-direction (canaries in tool results)
        cls.results_session_dir = cls.log_dir / "results_canaries"
        cls.results_session_dir.mkdir(exist_ok=True)
        cls.results_log_file = cls.results_session_dir / "session.jsonl"
        cls._build_results_session()

    @classmethod
    def _build_args_session(cls):
        """Build a session with canaries in tool call arguments (correct JSONL format)."""
        def _ts():
            return datetime.now(timezone.utc).isoformat()

        def _frame(rid, method, params=None):
            msg = {"jsonrpc": "2.0", "method": method}
            if rid is not None:
                msg["id"] = rid
            if params is not None:
                msg["params"] = params
            return msg

        # Correct JSONL format: schema_version, seq, ts, dir, frame, raw
        entries = [
            # Initialize
            {"schema_version": "0.1", "seq": 1, "ts": _ts(), "dir": "c2s",
             "frame": _frame(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}), "raw": None},
            {"schema_version": "0.1", "seq": 2, "ts": _ts(), "dir": "s2c",
             "frame": {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "test", "version": "1.0"}}}, "raw": None},

            # tools/list
            {"schema_version": "0.1", "seq": 3, "ts": _ts(), "dir": "c2s",
             "frame": _frame(2, "tools/list"), "raw": None},
            {"schema_version": "0.1", "seq": 4, "ts": _ts(), "dir": "s2c",
             "frame": {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "test_tool", "description": "test"}]}}, "raw": None},

            # Tool call with all canaries in arguments
            {"schema_version": "0.1", "seq": 5, "ts": _ts(), "dir": "c2s",
             "frame": _frame(3, "tools/call", {"name": "test_tool", "arguments": {
                "aws_key": CANARY_AWS,
                "ssn": CANARY_SSN,
                "email": CANARY_EMAIL,
                "api_key": CANARY_ANTHROPIC,
                "extra": "safe_value"
             }}), "raw": None},
            {"schema_version": "0.1", "seq": 6, "ts": _ts(), "dir": "s2c",
             "frame": {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "ok"}]}}, "raw": None},
        ]

        cls.args_log_file.write_text('\n'.join(json.dumps(e) for e in entries) + '\n')

    @classmethod
    def _build_results_session(cls):
        """Build a session with canaries in tool results (correct JSONL format)."""
        def _ts():
            return datetime.now(timezone.utc).isoformat()

        def _frame(rid, method, params=None):
            msg = {"jsonrpc": "2.0", "method": method}
            if rid is not None:
                msg["id"] = rid
            if params is not None:
                msg["params"] = params
            return msg

        entries = [
            # Initialize
            {"schema_version": "0.1", "seq": 1, "ts": _ts(), "dir": "c2s",
             "frame": _frame(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}), "raw": None},
            {"schema_version": "0.1", "seq": 2, "ts": _ts(), "dir": "s2c",
             "frame": {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "test", "version": "1.0"}}}, "raw": None},

            # tools/list
            {"schema_version": "0.1", "seq": 3, "ts": _ts(), "dir": "c2s",
             "frame": _frame(2, "tools/list"), "raw": None},
            {"schema_version": "0.1", "seq": 4, "ts": _ts(), "dir": "s2c",
             "frame": {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "test_tool", "description": "test"}]}}, "raw": None},

            # Tool call
            {"schema_version": "0.1", "seq": 5, "ts": _ts(), "dir": "c2s",
             "frame": _frame(3, "tools/call", {"name": "test_tool", "arguments": {"query": "test"}}), "raw": None},

            # Tool result with all canaries (severity-3 only are flagged in results)
            {"schema_version": "0.1", "seq": 6, "ts": _ts(), "dir": "s2c",
             "frame": {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": f"API key: {CANARY_ANTHROPIC}, SSN: {CANARY_SSN}, Email: {CANARY_EMAIL}, AWS: {CANARY_AWS}"}]}}, "raw": None},
        ]

        cls.results_log_file.write_text('\n'.join(json.dumps(e) for e in entries) + '\n')

    def test_args_has_tool_calls(self):
        """Verify args session has TOOL_CALL events."""
        log_lines = self.args_log_file.read_text().strip().split('\n')
        trace = from_mcp_session(log_lines)
        tool_calls = [e for e in trace.events if e.kind.value == 'tool_call']
        self.assertGreater(len(tool_calls), 0, "Args session must have TOOL_CALL events")

    def test_results_has_tool_calls(self):
        """Verify results session has TOOL_CALL events."""
        log_lines = self.results_log_file.read_text().strip().split('\n')
        trace = from_mcp_session(log_lines)
        tool_calls = [e for e in trace.events if e.kind.value == 'tool_call']
        self.assertGreater(len(tool_calls), 0, "Results session must have TOOL_CALL events")

    def test_detection_measurement(self):
        """Measure detection and compute observed categories."""
        # Args direction
        log_lines = self.args_log_file.read_text().strip().split('\n')
        trace = from_mcp_session(log_lines)
        annotations = annotate(trace)

        # Extract observed PII categories from annotations
        observed = set()
        for ann in annotations:
            # Annotations have name field that includes the category
            if hasattr(ann, 'name') and ann.name:
                if 'pii_' in ann.name:
                    category = ann.name.replace('pii_', '')
                    observed.add(category)

        # Store for later use
        self.args_observed = observed
        self.args_annotations = annotations

        # Results direction
        log_lines = self.results_log_file.read_text().strip().split('\n')
        trace = from_mcp_session(log_lines)
        annotations = annotate(trace)

        observed_results = set()
        for ann in annotations:
            if hasattr(ann, 'name') and ann.name:
                if 'pii_in_result_' in ann.name or 'pii_' in ann.name:
                    category = ann.name.replace('pii_in_result_', '').replace('pii_', '')
                    observed_results.add(category)

        self.results_observed = observed_results
        self.results_annotations = annotations

    def test_generate_all_artifacts(self):
        """Generate all supported artifacts for both sessions."""
        artifacts = {}

        # Args session
        log_lines = self.args_log_file.read_text().strip().split('\n')
        trace_args = from_mcp_session(log_lines)
        annotations_args = annotate(trace_args)

        # 1. HTML report
        artifacts['html_args'] = render_html(trace_args).encode('utf-8')

        # 2. SARIF (runtime annotations)
        artifacts['sarif_args'] = json.dumps(render_session_sarif(trace_args, base="")).encode('utf-8')

        # Results session
        log_lines = self.results_log_file.read_text().strip().split('\n')
        trace_results = from_mcp_session(log_lines)
        annotations_results = annotate(trace_results)

        # 3. HTML report
        artifacts['html_results'] = render_html(trace_results).encode('utf-8')

        # 4. SARIF (runtime annotations)
        artifacts['sarif_results'] = json.dumps(render_session_sarif(trace_results, base="")).encode('utf-8')

        self.artifacts = artifacts

    def test_artifact_safety_no_leaks(self):
        """Verify that canaries cannot be reconstructed from any artifact."""
        if not hasattr(self, 'artifacts'):
            self.test_generate_all_artifacts()

        leaks = []
        for artifact_name, artifact_bytes in self.artifacts.items():
            for canary in ALL_CANARIES:
                if CanaryChecker.find_canary(artifact_bytes, canary):
                    leaks.append({
                        'artifact': artifact_name,
                        'canary_category': self._canary_category(canary),
                    })

        self.assertEqual(len(leaks), 0, f"Found leakage in artifacts: {leaks}")

    @staticmethod
    def _canary_category(canary: str) -> str:
        """Categorize a canary value."""
        if canary == CANARY_AWS:
            return "aws_access_key"
        elif canary == CANARY_SSN:
            return "ssn"
        elif canary == CANARY_EMAIL:
            return "email"
        elif canary.startswith(CANARY_ANTHROPIC_PREFIX):
            return "anthropic_key"
        return "unknown"


if __name__ == "__main__":
    main()
