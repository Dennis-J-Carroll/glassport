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


class TestSharedEnvelope(unittest.TestCase):
    def test_sarif_document_minimal_envelope(self):
        out = json.loads(sarif._sarif_document([], [], {"k": "v"}))
        self.assertEqual(out["version"], "2.1.0")
        self.assertIn("$schema", out)
        self.assertEqual(len(out["runs"]), 1)
        self.assertEqual(out["runs"][0]["tool"]["driver"]["name"], "glassport")
        self.assertEqual(out["runs"][0]["results"], [])
        self.assertEqual(out["runs"][0]["properties"], {"k": "v"})
