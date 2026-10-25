"""Closed evidence-level claims across journal, gate marker, and readers."""
from __future__ import annotations

import ast

import json
import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from glassport import decision_journal as dj, detectors, evidence, sarif, tap
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.interaction_trace import AnnotationKind, Event


class TestEvidenceVocabulary(unittest.TestCase):
    def test_stdio_gate_reason_classifier_covers_source(self):
        tree = ast.parse(inspect.getsource(tap.Gate))
        emitted = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if (isinstance(key, ast.Constant) and key.value == "reason"
                            and isinstance(value, ast.Constant)
                            and isinstance(value.value, str)):
                        emitted.add(value.value)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "_note_skip":
                emitted.update(arg.value for arg in node.args
                               if isinstance(arg, ast.Constant)
                               and isinstance(arg.value, str))
        classified = {
            **{r: evidence.BLOCKED_ADMISSION for r in evidence._ADMISSION_REASONS},
            **{r: evidence.BLOCKED_EVIDENCE_GAP for r in evidence._GAP_REASONS},
            **{r: evidence.BLOCKED_POLICY for r in (
                "attestation_failed", "params_too_deep", "params_too_large",
                "retry_loop_exceeded", "taint_detected", "schema_violation",
                "pii_exfiltration", "gate_blocked")},
        }
        self.assertEqual(emitted - set(classified), set())
        for reason in emitted:
            self.assertEqual(evidence.gate_level({"action": "blocked",
                                                  "reason": reason}),
                             classified[reason])

    def test_every_gate_path_has_a_closed_level(self):
        cases = [
            ({"action": "blocked", "reason": "uninspectable_frame"},
             evidence.BLOCKED_ADMISSION),
            ({"action": "blocked", "reason": "gate_check_error"},
             evidence.BLOCKED_EVIDENCE_GAP),
            ({"action": "blocked", "reason": "pii_exfiltration"},
             evidence.BLOCKED_POLICY),
            ({"action": "injected"}, evidence.INJECTED_LOCALLY),
            ({"action": "gate_skipped", "reason": "no_surface_timeout"},
             evidence.FORWARDED),
            ({"action": "quarantined"}, evidence.BLOCKED_POLICY),
            ({"action": "quarantine_replacement"}, evidence.INJECTED_LOCALLY),
            ({"action": "quarantine_dropped", "reason": "frame_too_deep"},
             evidence.BLOCKED_ADMISSION),
            ({"action": "quarantine_withheld", "reason": "quarantine_scan_error"},
             evidence.BLOCKED_EVIDENCE_GAP),
        ]
        for marker, expected in cases:
            with self.subTest(marker=marker):
                self.assertEqual(evidence.gate_level(marker), expected)
                self.assertIn(expected, evidence.LEVELS)

    def test_delivery_does_not_claim_remote_execution(self):
        for outcome, code, expected in (
            ("sent", "upstream_response", evidence.FORWARDED),
            ("blocked", "http_gate_blocked", evidence.BLOCKED_POLICY),
            ("blocked", "http_gate_strict_blocked", evidence.BLOCKED_EVIDENCE_GAP),
            ("not_attempted", "invalid_mcp_request", evidence.BLOCKED_ADMISSION),
            ("unknown", "send_indeterminate", evidence.ANALYZED),
        ):
            with self.subTest(outcome=outcome, code=code):
                self.assertEqual(evidence.delivery_level(
                    outcome=outcome, code=code, candidate_action="allow",
                    analyzed=True), expected)
        self.assertNotEqual(evidence.FORWARDED, evidence.EXTERNALLY_CONFIRMED)

    def test_gate_marker_reader_and_sarif_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.jsonl"
            log = tap.SessionLog(path)
            log.record("c2s", b'{"jsonrpc":"2.0","id":7,"method":"tools/call",'
                       b'"params":{"name":"ghost","arguments":{}}}\n',
                       gate={"action": "blocked", "tool": "ghost",
                             "reason": "uninspectable_frame"})
            log.close()
            wire = json.loads(path.read_text().splitlines()[0])
            self.assertEqual(wire["gate"]["evidence_level"], "blocked_admission")
            trace = from_mcp_session_file(path)
            detectors.annotate(trace)
            result = json.loads(sarif.render_session_sarif(trace, str(path)))
            gate_result = next(r for r in result["runs"][0]["results"]
                               if r["ruleId"] == "glassport/gate_blocked")
            self.assertEqual(gate_result["properties"]["evidence_level"],
                             "blocked_admission")


class TestStrictOwnIdLimit(unittest.TestCase):
    def test_own_id_limit_does_not_waive_exclusion_in_either_mode(self):
        event = Event.tool_call("agent", "ghost", {}, metadata={"seq": 6})
        fabricated = detectors._ann(
            event, AnnotationKind.HALLUCINATION, "fabricated_tool_call",
            "outside surface", severity=3, no_declaration_seen=False)
        for reason, expected_default, expected_strict in (
            ("request_correlation", True, True),
            ("request_correlation_saturated", False, True),
        ):
            limit = detectors._ann(event, AnnotationKind.ANOMALY,
                                   "analysis_limit", "limit", severity=1,
                                   reason=reason)
            observation = SimpleNamespace(event=event,
                                          annotations=(fabricated, limit),
                                          diagnostic=None)
            with tempfile.TemporaryDirectory() as tmp:
                for strict, expected in ((False, expected_default),
                                         (True, expected_strict)):
                    journal = dj.DecisionJournal(Path(tmp) / str(strict),
                                                 SimpleNamespace(),
                                                 mode=dj.MODE_GATE, strict=strict)
                    self.assertEqual(journal.evaluate(observation), expected)
                    journal.close()
