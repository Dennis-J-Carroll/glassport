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

from glassport.adapters.mcp_session import from_mcp_session
from glassport import detectors
from glassport import report as report_mod
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


class TestUnicodeDeception(unittest.TestCase):
    """html.escape neutralizes markup but not deceptive Unicode; the renderer
    must REVEAL bidi/invisible/homoglyph bytes as visible ‹U+XXXX› sentinels so
    a hostile server can't spoof the report a human reads."""

    def test_bidi_override_revealed_not_survived(self):
        evil = "admin‮gpj.exe"          # RTL override reorders glyphs
        h = render(handshake() + [call(6, 3, evil, {"query": "x"})])
        self.assertNotIn("‮", h)
        self.assertIn("‹U+202E›", h)

    def test_homoglyph_and_invisible_revealed(self):
        evil = "obեy‍ˋ"        # Armenian e + ZWJ + grave twin
        h = render(handshake() + [call(6, 3, evil, {"query": "x"})])
        for cp in ("ե", "‍", "ˋ"):
            self.assertNotIn(cp, h)
        for tag in ("‹U+0565›", "‹U+200D›",
                    "‹U+02CB›"):
            self.assertIn(tag, h)

    def test_ordinary_text_untouched(self):
        h = render(handshake() + [call(6, 3, "web_search", {"query": "café 中文"})])
        self.assertIn("café 中文", h)           # legit non-ASCII must pass through
        self.assertNotIn("‹U+", h)             # no spurious sentinels


class TestSecretRedaction(unittest.TestCase):
    """A tool argument or result carrying a live credential must never reach the
    rendered HTML verbatim — the report is a shareable artifact."""

    def test_secret_in_args_redacted(self):
        secret = "postgres://admin:s3cr3tpassw0rd@db.internal:5432/prod"
        # precondition: the detector recognizes this value as a secret
        self.assertTrue(detectors._scan_pii(json.dumps({"dsn": secret})),
                        "fixture value must be detectable for the test to mean anything")
        h = render(handshake() + [call(6, 3, "web_search",
                                       {"query": "x", "dsn": secret})])
        self.assertNotIn("s3cr3tpassw0rd", h)
        self.assertIn("redacted", h)


class TestBounding(unittest.TestCase):
    """A hostile server can send a multi-megabyte field or a Zalgo stack; the
    report must stay bounded and readable, and truncation must not leak a
    secret across the cut."""

    def test_huge_field_is_truncated_and_output_bounded(self):
        big = "A" * 2_000_000
        h = render(handshake() + [call(6, 3, big, {"query": "x"})])
        self.assertLess(len(h.encode("utf-8")), 2_000_000)   # not ~8MB
        self.assertIn("chars truncated", h)

    def test_truncation_does_not_leak_a_straddling_secret(self):
        secret = "postgres://admin:s3cr3tpassw0rd@db.internal:5432/prod"
        # place the secret right at the display-cap boundary
        pad = "A" * (detectors.MAX_RENDER_CHARS - 10)
        h = render(handshake() + [call(6, 3, "web_search",
                                       {"q": pad + secret})])
        self.assertNotIn("s3cr3tpassw0rd", h)

    def test_zalgo_run_collapsed(self):
        import unicodedata
        name = "tool" + "e" + "́̂̃̄̅̆̇̈" * 4
        h = render(handshake() + [call(6, 3, name, {"query": "x"})])
        run = worst = 0
        for ch in h:
            if unicodedata.category(ch) in ("Mn", "Mc", "Me"):
                run += 1; worst = max(worst, run)
            else:
                run = 0
        self.assertLessEqual(worst, 4)
        self.assertIn("‹combining…›", h)


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


_OBF_SECRET = "sk-ant-api03-" + "aB" * 20 + "1234567890"
_OBFS = {
    "zwj":       lambda s: s[:6] + "‍" + s[6:],
    "fullwidth": lambda s: s.translate(
        {ord(c): ord(c) + 0xFEE0 for c in s if "!" <= c <= "~"}),
    "cyrillic":  lambda s: s.replace("a", "а"),          # U+0430
    "multi":     lambda s: (s[:4] + "‍" + s[4:8].replace("a", "а")
                            + "​" + s[8:]),               # zwj + homoglyph + zwsp
}


class TestReportRedactsObfuscated(unittest.TestCase):
    def test_no_reconstructable_secret_in_report(self):
        for name, obf in _OBFS.items():
            lines = handshake() + [
                call(6, 3, "web_search", {"data": obf(_OBF_SECRET)}),
                result(7, 3)]
            h = render(lines)
            # normalize the whole artifact: any obfuscated survivor reconstructs
            self.assertNotIn(_OBF_SECRET, detectors._normalize_for_scan(h), name)


if __name__ == "__main__":
    unittest.main()
