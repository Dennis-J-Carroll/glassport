"""Policy stays explicit, event-scoped, and reproducible from wire evidence."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
import unittest

from glassport.adapters.mcp_session import MCPTraceBuilder, from_mcp_session
from glassport.detectors import annotate
from glassport.incremental import DetectorEngine
from glassport.interaction_trace import Annotation, AnnotationKind, EventKind
from glassport.policy import Action, decide
from tests.test_detectors import call, handshake


def finding(subcategory="fabricated_tool_call", severity=3, **metadata):
    return Annotation("ann", "event", AnnotationKind.HALLUCINATION,
                      subcategory=subcategory, severity=severity, metadata=metadata)


class TestPolicy(unittest.TestCase):
    def test_blocking_requires_explicit_policy_and_observed_declaration(self):
        ann = finding(no_declaration_seen=False, declaration_seq=5)
        self.assertEqual(decide("event", [ann]).action, Action.WARN)
        blocked = decide("event", [ann], block_fabricated=True)
        self.assertEqual(blocked.action, Action.BLOCK)
        self.assertEqual(blocked.reason, "outside_observed_surface")
        self.assertEqual(blocked.annotation_ids, (ann.id,))
        for metadata in ({}, {"no_declaration_seen": True}, {"no_declaration_seen": 0}):
            ann.metadata = metadata
            self.assertEqual(decide("event", [ann], block_fabricated=True).action, Action.WARN)

    def test_other_high_severity_findings_never_trigger_fabricated_rule(self):
        for subcategory in ("pii_private_key", "unexpected_egress_host", "capability_violation",
                            "detector_error", "gate_blocked"):
            with self.subTest(subcategory=subcategory):
                ann = finding(subcategory, no_declaration_seen=False)
                self.assertEqual(decide("event", [ann], block_fabricated=True).action, Action.WARN)
        ann = finding(severity=2, no_declaration_seen=False)
        self.assertEqual(decide("event", [ann], block_fabricated=True).action, Action.WARN)
        ann.severity, ann.kind = 3, AnnotationKind.ANOMALY
        self.assertEqual(decide("event", [ann], block_fabricated=True).action, Action.WARN)

    def test_prior_events_and_session_diagnostics_cannot_block_current_event(self):
        stale = finding(no_declaration_seen=False)
        global_diagnostic = finding("detector_error", 2)
        global_diagnostic.event_id = ""
        decision = decide("new_event", [stale, global_diagnostic], block_fabricated=True)
        self.assertEqual(decision.action, Action.ALLOW)
        self.assertEqual(decision.annotation_ids, ())

    def test_info_gate_records_and_zero_severity_findings_are_not_actions(self):
        info = finding("gate_allowed")
        info.kind = AnnotationKind.INFO
        decision = decide("event", [info, finding(severity=0)], block_fabricated=True)
        self.assertEqual(decision.action, Action.ALLOW)
        self.assertEqual(decision.reason, "no_actionable_findings")
        self.assertEqual(decision.annotation_ids, ())

    def test_decision_is_immutable_deterministic_and_contains_no_payload(self):
        ann = finding(no_declaration_seen=False, tool="secret-tool-payload")
        ann.explanation = "secret-explanation-payload"
        second = finding("schema_violation", 2)
        second.id = "aaa"
        before = deepcopy([ann, second])
        decision = decide("event", iter([ann, second, ann]))
        self.assertEqual(decision, decide("event", reversed([ann, second])))
        self.assertEqual([ann, second], before)
        self.assertNotIn("secret-", repr(decision))
        with self.assertRaises(FrozenInstanceError):
            decision.action = Action.BLOCK

    def test_invalid_event_ids_rejected(self):
        for event_id in ("", None, 42):
            with self.subTest(event_id=event_id), self.assertRaises(ValueError):
                decide(event_id, [])

    def test_block_option_requires_boolean(self):
        for option in ("false", "true", 1, None):
            with self.subTest(option=option), self.assertRaises(ValueError):
                decide("event", [finding(no_declaration_seen=False)], block_fabricated=option)

    def test_severity_one_observations_remain_visible(self):
        ann = finding("call_before_declaration", 1)
        decision = decide("event", [ann], block_fabricated=True)
        self.assertEqual(decision.action, Action.WARN)
        self.assertEqual(decision.annotation_ids, (ann.id,))

    def test_live_decisions_reconstruct_from_persisted_wire(self):
        cases = (
            (handshake()[:3], "outside", Action.WARN),
            (handshake(tools=[]), "outside", Action.BLOCK),
            (handshake(), "web_search", Action.ALLOW),
            (handshake(), "outside", Action.BLOCK),
        )
        for prefix, name, expected in cases:
            with self.subTest(name=name, prefix=len(prefix)):
                lines = prefix + [call(6, 3, name, {"query": "hello"})]
                builder, engine = MCPTraceBuilder(retain_events=False), DetectorEngine()
                live = []
                for line in lines:
                    event = builder.ingest_frame(json.loads(line))
                    findings = engine.on_event(event, builder.state)
                    if event.kind == EventKind.TOOL_CALL:
                        live.append(decide(event.id, findings, block_fabricated=True))
                batch = from_mcp_session(lines)
                batch_findings = annotate(batch)
                replayed = [decide(e.id, batch_findings, block_fabricated=True)
                            for e in batch.events if e.kind == EventKind.TOOL_CALL]
                self.assertEqual([(d.action, d.reason) for d in live],
                                 [(d.action, d.reason) for d in replayed])
                # No declaration produces a low observation warning, never a block.
                self.assertEqual(live[-1].action, expected)
                batch_by_id = {a.id: a for a in batch_findings}
                for decision in replayed:
                    self.assertTrue(all(batch_by_id[aid].event_id == decision.event_id
                                        for aid in decision.annotation_ids))
                self.assertEqual(builder.events, [])


if __name__ == "__main__":
    unittest.main()
