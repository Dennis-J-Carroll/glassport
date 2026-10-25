"""Strict HTTP gate: prove refusal through upstream receipt, not reply alone."""
import json
from unittest import mock

from glassport import decision_journal as dj
from glassport import decision_replay as dr
from glassport import detectors, tap
from glassport.incremental import DetectorEngine
from glassport.interaction_trace import AnnotationKind, EventKind
from tests.test_http_gate import GateCase, Upstream


STRICT_MARKER = "http_gate_strict_blocked"


class TestStrictHttpGate(GateCase):
    def test_strict_journal_replays_equivalent(self):
        self.proxy(strict=True)
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call("ghost")
        self.assert_blocked(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent["evidence_level"], "blocked_policy")
        self.assertEqual(delivery["evidence_level"], "blocked_policy")
        epoch = intent["epoch"]
        replay = dr.verify_journal(self.journal.path_for(epoch),
                                   self.observer.log_dir / f"{epoch}.jsonl")
        self.assertEqual(replay.status, "equivalent", replay.as_dict())
        self.assertGreater(replay.compared, 0)

    def assert_strict_blocked(self, body, before, reason, rid=7):
        self.quiesce()
        frame = json.loads(body)
        self.assertEqual(frame["id"], rid)
        self.assertEqual(frame["error"]["code"], -32000)
        self.assertEqual(frame["error"]["data"],
                         {"glassport": STRICT_MARKER, "reason": reason})
        self.assertEqual(self.upstream_calls(), before,
                         "strict refusal reached upstream")

    def check_annotation_gap(self, subcategory):
        self.proxy(strict=True)
        self.handshake()
        self.quiesce()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        original = DetectorEngine.on_event

        def with_gap(engine, event, state):
            findings = list(original(engine, event, state))
            if event.kind == EventKind.TOOL_CALL:
                findings.append(detectors._ann(
                    event, AnnotationKind.ANOMALY, subcategory,
                    "simulated incomplete evidence", severity=1))
            return findings

        with mock.patch.object(DetectorEngine, "on_event", with_gap):
            _, body = self.call("search")
        self.assert_strict_blocked(body, before, subcategory)
        intent, delivery = self.last_call_records(since=since)
        self.assertIn(subcategory, [f["subcategory"] for f in intent["findings"]])
        self.assertFalse(intent["candidate_block"])
        self.assertTrue(intent["enforce"])
        self.assertEqual(intent["evidence_level"], "blocked_evidence_gap")
        self.assertEqual(delivery["outcome"], "blocked")
        self.assertEqual(delivery["evidence_level"], "blocked_evidence_gap")
        self.assertTrue(delivery["enforced"])
        self.assertEqual(delivery["code"], STRICT_MARKER)
        self.assertEqual(delivery["reason"], subcategory)

    def test_detector_error_blocks(self):
        self.check_annotation_gap("detector_error")

    def test_analysis_limit_blocks(self):
        self.check_annotation_gap("analysis_limit")

    def test_declaration_unavailable_blocks(self):
        self.check_annotation_gap("declaration_unavailable")

    def test_http_observation_unavailable_blocks(self):
        self.check_annotation_gap("http_observation_unavailable")

    def test_call_before_any_declaration_blocks(self):
        self.proxy(strict=True)
        self.handshake(declare=False)
        before = self.upstream_calls()
        _, body = self.call("search")
        self.assert_strict_blocked(body, before, "call_before_declaration")

    def test_analysis_diagnostic_blocks_without_folded_event(self):
        self.proxy(strict=True)
        self.handshake()
        before = self.upstream_calls()
        original = DetectorEngine.on_event

        def fail_call(engine, event, state):
            if event.kind == EventKind.TOOL_CALL:
                raise RuntimeError("analysis failed")
            return original(engine, event, state)

        with mock.patch.object(DetectorEngine, "on_event", fail_call):
            _, body = self.call("search", rid="request-7")
        self.assert_strict_blocked(body, before, "http_analysis_failed",
                                   rid="request-7")

    def test_failed_wire_append_blocks_and_does_not_commit_correlation(self):
        self.proxy(strict=True)
        self.handshake()
        self.quiesce()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        original = tap.SessionLog.write_entry

        def fail_call(log, entry, text=None):
            frame = entry.get("frame")
            if (entry.get("dir") == "c2s" and isinstance(frame, dict)
                    and frame.get("method") == "tools/call"):
                return False
            return original(log, entry, text)

        with mock.patch.object(tap.SessionLog, "write_entry", fail_call):
            _, body = self.call("search")
        self.assert_strict_blocked(body, before, "http_log_failed")
        intent, delivery = self.last_call_records(since=since)
        self.assertFalse(intent["persisted"])
        self.assertEqual(intent["diagnostic"], "http_log_failed")
        self.assertEqual(delivery["code"], STRICT_MARKER)
        self.assertEqual(delivery["reason"], "http_log_failed")

    def test_taint_pii_and_schema_remain_warnings(self):
        self.proxy(strict=True)
        original = Upstream._result

        def with_schema(upstream, frame):
            result = original(upstream, frame)
            if frame.get("method") == "tools/list":
                result["result"]["tools"][0]["inputSchema"] = {
                    "type": "object", "required": ["q"],
                    "properties": {"q": {"type": "string"}}}
            return result

        with mock.patch.object(Upstream, "_result", with_schema):
            self.handshake()
            before = self.upstream_calls()
            _, body = self.call("search", args={
                "payload": "[SYSTEM]", "key": "sk-ant-api03-" + "A" * 40})
        self.assert_forwarded(body, before)
        intents = [r for r in self.records("intent")
                   if any(f["subcategory"] == "schema_violation"
                          for f in r["findings"])]
        self.assertEqual(len(intents), 1)
        categories = {f["subcategory"] for f in intents[0]["findings"]}
        self.assertTrue({"role_switch_delimiter", "pii_anthropic_key",
                         "schema_violation"} <= categories, categories)
        self.assertFalse(intents[0]["enforce"])

    def test_strict_profile_and_old_policy_replay(self):
        self.proxy(strict=True)
        self.handshake()
        self.call("search")
        self.quiesce()
        profiles = self.records("profile")
        self.assertTrue(profiles)
        self.assertTrue(all(r["strict"] is True for r in profiles))
        self.assertTrue(all(r["policy_version"] == "glassport.policy/2"
                            for r in profiles))
        journal_file = self.journal.path_for(profiles[0]["epoch"])
        wire_file = self.observer.log_dir / f"{profiles[0]['epoch']}.jsonl"
        changed = []
        for line in journal_file.read_text().splitlines():
            record = json.loads(line)
            if record["kind"] == "profile":
                record["policy_version"] = "glassport.policy/1"
            changed.append(json.dumps(record))
        journal_file.write_text("\n".join(changed) + "\n")
        replay = dr.verify_journal(journal_file, wire_file)
        self.assertEqual(replay.status, "unsupported")
        self.assertEqual(replay.reasons, ["profile_mismatch_policy_version"])
