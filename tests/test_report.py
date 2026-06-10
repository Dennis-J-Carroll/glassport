"""
Tests for report.render_html() / report.report() — the M3 static HTML
session report.

The renderer draws a trace plus whatever annotations are already on it;
it never runs detectors itself. These tests build synthetic tap logs
with the same helpers as test_detectors, annotate them, and assert on
the HTML string. Pure stdlib, run with:
    python3 -m unittest tests.test_report
"""
import json
import re
import tempfile
import unittest
from pathlib import Path

from adapters.mcp_session import from_mcp_session
import detectors
import report as report_mod
from tests.test_detectors import handshake, call, result


def render(lines, annotate=True):
    trace = from_mcp_session(lines)
    if annotate:
        detectors.annotate(trace)
    return report_mod.render_html(trace, source_name="test.jsonl")


class TestDocument(unittest.TestCase):
    def test_complete_html5_document(self):
        h = render(handshake())
        self.assertTrue(h.lstrip().startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", h)
        self.assertIn('charset="utf-8"', h)

    def test_no_js_and_self_contained(self):
        h = render(handshake())
        self.assertNotIn("<script", h.lower())
        self.assertNotIn("javascript:", h.lower())
        self.assertNotIn("http://", h)
        self.assertNotIn("https://", h)

    def test_phone_viewport(self):
        self.assertIn('name="viewport"', render(handshake()))


class TestContent(unittest.TestCase):
    def test_declared_and_called_tools_listed(self):
        h = render(handshake() + [call(6, 3, "web_search", {"query": "x"}),
                                  result(7, 3)])
        self.assertIn("web_search", h)
        self.assertIn("tools/call", h)

    def test_events_render_in_wire_order(self):
        h = render(handshake() + [call(6, 3, "web_search", {"query": "x"}),
                                  result(7, 3)])
        seqs = [int(m) for m in re.findall(r'data-seq="(\d+)"', h)]
        self.assertTrue(seqs, "timeline rows must carry data-seq")
        self.assertEqual(seqs, sorted(seqs))

    def test_unparsed_raw_line_rendered(self):
        raw_entry = json.dumps({"schema_version": "0.1", "seq": 6, "ts": "t6",
                                "dir": "s2c", "frame": None,
                                "raw": "NOT JSON garbage"})
        h = render(handshake() + [raw_entry])
        self.assertIn("NOT JSON garbage", h)

    def test_clean_session_verdict(self):
        h = render(handshake() + [call(6, 3, "web_search", {"query": "x"}),
                                  result(7, 3)])
        self.assertIn("CLEAN", h)
        # no annotation boxes rendered (CSS may still mention the selector)
        self.assertNotIn('class="ann"', h)

    def test_result_links_back_to_call_seq(self):
        h = render(handshake() + [call(6, 3, "web_search", {"query": "x"}),
                                  result(7, 3)])
        self.assertIn("seq 6", h)   # the reply row points at its request


class TestAnnotations(unittest.TestCase):
    def test_fabricated_call_rendered_sev3(self):
        h = render(handshake() + [call(6, 3, "arxiv_lookup", {"q": "x"})])
        self.assertIn('data-sev="3"', h)
        self.assertIn("fabricated_tool_call", h)
        self.assertIn("outside the declared surface", h)

    def test_schema_violation_rendered_sev2(self):
        h = render(handshake() + [call(6, 3, "web_search", {})])
        self.assertIn('data-sev="2"', h)
        self.assertIn("schema_violation", h)

    def test_verdict_reflects_max_severity(self):
        h = render(handshake() + [call(6, 3, "arxiv_lookup", {})])
        self.assertIn("HOSTILE OR HALLUCINATED", h)
        self.assertNotIn("CLEAN", h)


class TestEscaping(unittest.TestCase):
    def test_wire_content_cannot_inject_html(self):
        evil = "<img src=x onerror=alert(1)>"
        tools = [{"name": evil,
                  "inputSchema": {"type": "object", "properties": {},
                                  "additionalProperties": False}}]
        lines = handshake(tools=tools) + [
            call(6, 3, evil, {"</pre><b>x</b>": "<script>alert(2)</script>"}),
        ]
        h = render(lines)
        self.assertNotIn("<img", h)
        self.assertNotIn("<script>", h)
        self.assertNotIn("</pre><b>", h)
        self.assertIn("&lt;img", h)


class TestReportFile(unittest.TestCase):
    def _write_log(self, tmp, lines):
        p = Path(tmp) / "session.jsonl"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_writes_html_next_to_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = self._write_log(tmp, handshake())
            out = report_mod.report(log)
            self.assertEqual(out, log.with_suffix(".html"))
            text = out.read_text(encoding="utf-8")
            self.assertTrue(text.lstrip().startswith("<!DOCTYPE html>"))
            self.assertIn("session.jsonl", text)

    def test_explicit_output_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = self._write_log(tmp, handshake())
            target = Path(tmp) / "custom_name.html"
            out = report_mod.report(log, out_path=target)
            self.assertEqual(out, target)
            self.assertTrue(target.exists())

    def test_report_runs_detectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = self._write_log(
                tmp, handshake() + [call(6, 3, "arxiv_lookup", {})])
            out = report_mod.report(log)
            self.assertIn("fabricated_tool_call",
                          out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
