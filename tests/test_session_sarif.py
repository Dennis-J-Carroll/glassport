"""
Tests for sarif.render_session_sarif() — SARIF 2.1.0 export of runtime
detector annotations, located into the session .jsonl log. Pure stdlib.

Per project doctrine these drive the REAL adapter: a tap log is written
to a temp file, lifted through from_mcp_session_file(), annotated, and
rendered — never a hand-built trace.
"""
import json
import os
import tempfile
import unittest

from glassport import sarif
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.detectors import annotate


class TestSharedEnvelope(unittest.TestCase):
    def test_sarif_document_minimal_envelope(self):
        out = json.loads(sarif._sarif_document([], [], {"k": "v"}))
        self.assertEqual(out["version"], "2.1.0")
        self.assertIn("$schema", out)
        self.assertEqual(len(out["runs"]), 1)
        self.assertEqual(out["runs"][0]["tool"]["driver"]["name"], "glassport")
        self.assertEqual(out["runs"][0]["results"], [])
        self.assertEqual(out["runs"][0]["properties"], {"k": "v"})


def L(seq, direction, frame, gate=None):
    rec = {"schema_version": "0.1", "seq": seq, "ts": f"t{seq}",
           "dir": direction, "frame": frame, "raw": None}
    if gate is not None:
        rec["gate"] = gate
    return json.dumps(rec)


def handshake(tools):
    """initialize -> result -> initialized -> tools/list -> result."""
    return [
        L(1, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26",
                                "capabilities": {},
                                "clientInfo": {"name": "c"}}}),
        L(2, "s2c", {"jsonrpc": "2.0", "id": 1,
                     "result": {"protocolVersion": "2025-03-26",
                                "capabilities": {"tools": {}},
                                "serverInfo": {"name": "s"}}}),
        L(3, "c2s", {"jsonrpc": "2.0", "method": "notifications/initialized"}),
        L(4, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        L(5, "s2c", {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}),
    ]


def render_lines(lines):
    """Write lines to a temp .jsonl, lift via the real adapter, annotate,
    and render. Returns (parsed_sarif_dict, session_path)."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    trace = from_mcp_session_file(path)
    trace.annotations.extend(annotate(trace))
    doc = json.loads(sarif.render_session_sarif(trace, path))
    return doc, path


class TestRenderSessionSarif(unittest.TestCase):
    def _fabricated(self):
        # web_search declared; calling shadow_tool is a fabricated call (sev 3)
        lines = handshake([{"name": "web_search"}]) + [
            L(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "shadow_tool", "arguments": {}}}),
        ]
        return render_lines(lines)

    def test_valid_envelope(self):
        doc, _ = self._fabricated()
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "glassport")

    def test_fabricated_call_is_error_level(self):
        doc, _ = self._fabricated()
        res = [r for r in doc["runs"][0]["results"]
               if r["ruleId"] == "glassport/fabricated_tool_call"]
        self.assertTrue(res)
        self.assertEqual(res[0]["level"], "error")          # sev 3 -> error

    def test_result_locates_at_real_jsonl_line(self):
        doc, path = self._fabricated()
        res = [r for r in doc["runs"][0]["results"]
               if r["ruleId"] == "glassport/fabricated_tool_call"][0]
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], path)
        # the shadow_tool call is the 6th line written
        self.assertEqual(loc["region"]["startLine"], 6)

    def test_seq_in_partial_fingerprints(self):
        doc, _ = self._fabricated()
        res = [r for r in doc["runs"][0]["results"]
               if r["ruleId"] == "glassport/fabricated_tool_call"][0]
        self.assertIn("glassportSeq", res["partialFingerprints"])
        self.assertTrue(res["partialFingerprints"]["glassportSeq"]
                        .endswith(":6"))

    def test_distinct_subcategory_yields_one_rule(self):
        doc, _ = self._fabricated()
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertIn("glassport/fabricated_tool_call", rule_ids)

    def test_gate_info_included_as_note(self):
        # a blocked tools/call carries a gate marker; gate_actions emits a
        # gate_blocked INFO annotation (severity 1 -> note), not dropped
        lines = handshake([{"name": "web_search"}]) + [
            L(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "shadow_tool", "arguments": {}}},
              gate={"action": "blocked", "tool": "shadow_tool"}),
        ]
        doc, _ = render_lines(lines)
        gate = [r for r in doc["runs"][0]["results"]
                if r["ruleId"] == "glassport/gate_blocked"]
        self.assertTrue(gate, "gate_blocked INFO record must be emitted")
        self.assertEqual(gate[0]["level"], "note")
