"""Public stdio gate markers must not disclose peer-chosen tool names."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from urllib.parse import quote

from glassport import __version__, bundle, evidence, tap
from glassport.decision_journal import (DETECTOR_ENGINE_VERSION, JOURNAL_SCHEMA,
                                        POLICY_VERSION)


class _Sink(io.BytesIO):
    def close(self):
        pass  # pump closes its destination; test needs the upstream count.


def _line(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


class TestPublicGate(unittest.TestCase):
    _PUBLIC_KEYS = frozenset("""
        $schema action analysis artifacts audit bundle_schema bundler canonicalization
        code columnKind commit created_at delivery detector_engine dir driver
        entries entries_written epoch epochs evidence evidence_level findings
        frames_seen gate glassport_version hashes header informationUri journal
        journal_profiles journal_schema level limits location log_bytes log_sha256
        message mode name partialFingerprints path policy_version profile properties
        raw_hashes raw_tier reason redacted replay_argv results ruleId rule_id_sha256
        rules runs sarif schema schema_version semanticVersion seq seq_range
        severity sha-256 sha256 source stable_id started_at strict text tool
        tool_sha256 trailer_log_sha256 transport ts type uri version versions wire
        wire_seq write_failures
        authorization candidate_action candidate_block delivery_n enforce enforced
        event_seq faults_total final_record_sha256 findings_digest findings_total
        host_sha256 idle_ttl intent intent_n journal_limits kind max_epochs
        max_faults max_findings max_frame_bytes max_identifier_chars
        max_name_chars max_pending max_records max_sessions max_sse_ids
        max_state_bytes max_tools n outcome path_sha256 pattern_digest
        pattern_snapshot_exact pattern_status persisted port prev_sha256 records
        registry_limits remote scheme session_limits status wire_b64_sha256
        wire_entry_sha256
    """.split())

    @classmethod
    def _public_string_allowed(cls, value: str) -> bool:
        fixed = (cls._PUBLIC_KEYS | evidence.GATE_ACTIONS | evidence.GATE_REASONS |
                 evidence.LEVELS | {
                     "redacted", "stdio", "http", "gate", "observe", "wrap",
                     "c2s", "s2c", "wire", "audit", "glassport.header",
                     "glassport.metrics", "RFC8785", bundle.SCHEMA, "withheld",
                     "Redacted in public bundle", "glassport/public-redacted",
                     "error", "warning", "note", "utf16CodeUnits", "glassport",
                     "https://json.schemastore.org/sarif-2.1.0.json",
                     "https://github.com/Dennis-J-Carroll/glassport", "2.1.0",
                     tap.SCHEMA_VERSION, __version__, DETECTOR_ENGINE_VERSION,
                     JOURNAL_SCHEMA, POLICY_VERSION,
                     "url_userinfo", "url_query", "url_fragment", "url_path",
                     "header_values", "stdio_decoded_text_no_raw_bytes",
                     "no_journal_for_path", "default_profile", "strict_profile",
                     "authorization_not_evaluated", "no_signature",
                     "public_redaction_not_replay_equivalent",
                     "public_raw_bytes_removed", "public_peer_text_removed",
                     "public_gate_tool_hashed",
                     "public_remote_host_hashed", "allow", "not_evaluated",
                     "reproducible", "sent", "upstream_response", "warn",
                 })
        return bool(
            value in fixed or
            re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{24}(?:-[0-9a-f]{8}(?:-[0-9]+)?)?", value) or
            re.fullmatch(r"epoch-\d{4}", value) or
            re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?\+00:00", value) or
            re.fullmatch(r"(?:evidence/(?:stdio|epoch-\d{4})\.(?:wire|journal)\.jsonl|"
                         r"index/findings\.sarif\.json|manifest\.json|manifest\.sig)", value)
        )

    def test_every_public_string_leaf_is_fixed_or_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, _, _ = self._capture(Path(tmp), "unknown_tool")
            self.assertFalse(self._public_string_allowed("c2stQUFBQUFB"))
            assert_public_strings(self, out / "public")

    def test_gate_projection_keeps_only_fixed_codes_and_tool_digest(self):
        marker = {"action": "blocked", "reason": "no_surface_timeout",
                  "tool": "peer-tool", "declared": ["peer-list"], "uri": "peer-uri",
                  "also_skipped": ["pii_scan_error"],
                  "evidence_level": evidence.BLOCKED_EVIDENCE_GAP}
        projected = bundle._public_gate(marker)
        self.assertEqual(projected, {
            "action": "blocked", "reason": "no_surface_timeout",
            "tool_sha256": hashlib.sha256(b"peer-tool").hexdigest(),
            "also_skipped": ["pii_scan_error"],
            "evidence_level": evidence.BLOCKED_EVIDENCE_GAP})
        marker.update(action="peer-action", reason="peer-reason",
                      also_skipped=["pii_scan_error", "peer-reason"])
        projected = bundle._public_gate(marker)
        self.assertEqual(projected["action"], "redacted")
        self.assertEqual(projected["reason"], "redacted")
        self.assertNotIn("also_skipped", projected)
        self.assertIsNone(bundle._public_gate({})["tool_sha256"])

    def test_remote_projection_hashes_operator_host(self):
        projected = bundle._public_remote({
            "scheme": "https", "host": "private.example", "port": 8443,
            "path_sha256": "a" * 64, "uri": "peer-controlled"})
        self.assertEqual(projected, {
            "scheme": "https",
            "host_sha256": hashlib.sha256(b"private.example").hexdigest(),
            "path_sha256": "a" * 64})
        self.assertEqual(bundle._public_remote({"scheme": "peer", "host": None}), {
            "scheme": "redacted", "host_sha256": None, "path_sha256": None})

    def _capture(self, root: Path, tool: str):
        gate = tap.Gate()
        log_path = root / "stdio.jsonl"
        log = tap.open_session_log(log_path, transport="stdio", mode="gate")
        self.assertIsNotNone(log)
        upstream = _Sink()
        downstream = _Sink()

        def send(direction, frame):
            tap.pump(io.BytesIO(_line(frame)), upstream if direction == "c2s" else downstream,
                     log, direction, gate=gate, client_write=downstream.write)

        send("c2s", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        send("s2c", {"jsonrpc": "2.0", "id": 1,
                     "result": {"tools": [{"name": "search"}]}})
        send("c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": tool, "arguments": {}}})
        log.write_metrics()
        log.close()
        manifest = bundle.build_bundle([log_path], None, None, root / "bundle",
                                       redact=True)
        return root / "bundle", manifest, upstream.getvalue()

    def test_encoded_canary_in_tool_name_stays_out_of_public_tier(self):
        secret = "sk-" + "A" * 40
        tool = base64.b64encode(secret.encode()).decode()
        with tempfile.TemporaryDirectory() as tmp:
            out, manifest, upstream = self._capture(Path(tmp), tool)
            self.assertEqual(upstream.count(b'"method":"tools/call"'), 0)
            raw = out / manifest["evidence"]["epochs"][0]["wire"]["path"]
            self.assertTrue(any(json.loads(line).get("gate", {}).get("tool") == tool
                                for line in raw.read_text().splitlines()))
            encoded = {
                "plain": secret.encode(),
                "hex lower": secret.encode().hex().encode(),
                "hex upper": secret.encode().hex().upper().encode(),
                "percent": quote(secret, safe="").encode(),
                "json unicode": "".join(f"\\u{byte:04x}" for byte in secret.encode()).encode(),
            }
            for alignment in range(3):
                encoded[f"base64 alignment {alignment}"] = (
                    base64.b64encode(b"x" * alignment + secret.encode())[4:-4])
            for path in (out / "public").rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    for form, value in encoded.items():
                        self.assertNotIn(value, data, f"{path}: {form}")


def assert_public_strings(test: unittest.TestCase, public: Path):
    """Every public JSON key and string value must be fixed or structured."""
    unknown = {}

    def walk(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                if not TestPublicGate._public_string_allowed(key):
                    unknown.setdefault(key, f"{path}: key")
                walk(child, f"{path}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}/{index}")
        elif isinstance(value, str):
            if not TestPublicGate._public_string_allowed(value):
                unknown.setdefault(value, f"{path}: value")

    for path in public.rglob("*"):
        if path.is_file() and path.suffix in (".json", ".jsonl"):
            for line in path.read_text().splitlines():
                walk(json.loads(line), str(path))
    if unknown:
        test.fail(f"unexpected public strings: {sorted(unknown)}")


if __name__ == "__main__":
    unittest.main()
