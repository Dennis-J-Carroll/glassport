"""
Tests for the tap CLI surface: the `detect` subcommand and the
`summarize --json` flag. Sessions are synthesized with the same
helpers test_detectors uses, written to disk, and run through
tap.main() exactly as the console script would.

Pure stdlib, run with:  python3 -m unittest tests.test_cli
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from glassport import tap
from tests.test_detectors import handshake, call, result, L


def write_session(tmp: str, lines: list[str]) -> Path:
    p = Path(tmp) / "session.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def run_main(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = tap.main(argv)
    return rc, buf.getvalue()


class TestDetectCommand(unittest.TestCase):
    def test_clean_session_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, handshake() +
                              [call(6, 3, "web_search", {"query": "x"})])
            rc, out = run_main(["detect", str(p)])
        self.assertEqual(rc, 0)
        self.assertIn("no findings", out)

    def test_findings_exit_one_with_severity_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, handshake() +
                              [call(6, 3, "shadow_tool", {})])
            rc, out = run_main(["detect", str(p)])
        self.assertEqual(rc, 1)
        self.assertIn("fabricated_tool_call", out)
        self.assertIn("[HIGH]", out)

    def test_usage_on_wrong_arity(self):
        rc, _ = run_main(["detect"])
        self.assertEqual(rc, 2)

    def test_sarif_flag_emits_runtime_sarif(self):
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, handshake() +
                              [call(6, 3, "shadow_tool", {})])
            rc, out = run_main(["detect", "--sarif", str(p)])
        self.assertEqual(rc, 0)                      # sarif mode never exit-1
        doc = _json.loads(out)                       # stdout is pure SARIF
        self.assertEqual(doc["version"], "2.1.0")
        rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
        self.assertIn("glassport/fabricated_tool_call", rule_ids)

    def test_usage_mentions_detect_and_serve(self):
        rc, out = run_main(["--help"])
        self.assertEqual(rc, 0)
        self.assertIn("detect", out)
        self.assertIn("serve", out)


class TestSummarizeJson(unittest.TestCase):
    def test_json_output_is_structured(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, handshake() +
                              [call(6, 3, "web_search", {"query": "x"}),
                               call(7, 4, "shadow_tool", {})])
            rc, out = run_main(["summarize", "--json", str(p)])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["session"], p.name)
        self.assertEqual(data["declared_tools"], ["web_search"])
        self.assertEqual(data["called_tools"], ["web_search", "shadow_tool"])
        self.assertEqual(data["fabricated_calls"],
                         [{"seq": 7, "tool": "shadow_tool"}])
        self.assertIn("context_violations", data)
        self.assertIn("frames_parsed", data)

    def test_plain_summarize_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, handshake())
            rc, out = run_main(["summarize", str(p)])
        self.assertEqual(rc, 0)
        self.assertIn("declared tools", out)

    def test_usage_on_wrong_arity(self):
        rc, _ = run_main(["summarize", "--json"])
        self.assertEqual(rc, 2)


class TestSummarizeErrorTaxonomy(unittest.TestCase):
    """An MCP server can fail two distinct ways: a JSON-RPC protocol
    error (the `error` member — malformed/unknown method) and a valid
    tools/call result that carries isError=true (the tool ran, the
    operation failed). summarize must not conflate them."""

    def _session(self, tmp: str) -> Path:
        return write_session(tmp, handshake() + [
            # a normal tool call whose RESULT is a server-side failure
            call(6, 3, "web_search", {"query": "x"}),
            result(7, 3, {"content": [{"type": "text",
                                       "text": "search backend unavailable"}],
                          "isError": True}),
            # a genuine JSON-RPC protocol error not tied to any tools/call
            # (the adapter renders this as a PartKind.ERROR)
            L(8, "s2c", {"jsonrpc": "2.0", "id": 99,
                         "error": {"code": -32600,
                                   "message": "invalid request"}}),
        ])

    def test_iserror_result_lands_in_tool_errors_not_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run_main(["summarize", "--json", str(self._session(tmp))])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        tool_seqs = [e["seq"] for e in data["tool_errors"]]
        proto_seqs = [e["seq"] for e in data["protocol_errors"]]
        self.assertIn(7, tool_seqs)            # isError result is a tool error
        self.assertNotIn(7, proto_seqs)        # ...not a protocol error
        self.assertIn("search backend unavailable",
                      data["tool_errors"][0]["message"])

    def test_real_protocol_error_stays_in_protocol_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, out = run_main(["summarize", "--json", str(self._session(tmp))])
        data = json.loads(out)
        proto_seqs = [e["seq"] for e in data["protocol_errors"]]
        tool_seqs = [e["seq"] for e in data["tool_errors"]]
        self.assertIn(8, proto_seqs)           # the JSON-RPC error frame
        self.assertNotIn(8, tool_seqs)

    def test_plain_text_has_separate_tool_errors_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run_main(["summarize", str(self._session(tmp))])
        self.assertEqual(rc, 0)
        self.assertIn("tool errors", out)
        self.assertIn("search backend unavailable", out)


if __name__ == "__main__":
    unittest.main()
