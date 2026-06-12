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
from tests.test_detectors import handshake, call


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


if __name__ == "__main__":
    unittest.main()
