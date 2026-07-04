"""
tail_only surfacing (roadmap P0.3).

The streaming adapter drops the head of very large logs and sets
trace.metadata["tail_only"] = True. Doctrine: "assert only what the wire
proves" — a report that omits the head without saying so asserts a
completeness the wire never proved. These tests lock three surfaces
(summarize, report, watch) plus the batch adapter growing the same tail
cap so batch and streaming agree on large files.

Pure stdlib, run with:  python3 -m unittest tests.test_tail_surfacing
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from glassport import report as report_mod
from glassport import tap, watch
from glassport.adapters import mcp_session
from glassport.adapters.mcp_session import from_mcp_session_file
from tests.test_detectors import handshake, call


def write_session(tmp, name, lines) -> Path:
    p = Path(tmp) / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def big_session(tmp, name="20260101T000000Z_srv_1.jsonl") -> Path:
    # head = handshake, tail = many calls; a small cap cuts the handshake off
    lines = handshake() + [call(6 + i, 3 + i, "web_search", {"q": "x" * 40})
                           for i in range(60)]
    return write_session(tmp, name, lines)


class TestBatchTailCap(unittest.TestCase):
    def test_small_file_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            trace = from_mcp_session_file(p)
        self.assertFalse(trace.metadata.get("tail_only"))

    def test_oversize_file_goes_tail_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = big_session(tmp)
            trace = from_mcp_session_file(p, tail_cap_bytes=2000)
        self.assertTrue(trace.metadata.get("tail_only"))
        # the head (tools/list handshake) was cut off
        self.assertEqual(trace.declared_tools(), set())

    def test_explicit_cap_none_disables(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = big_session(tmp)
            trace = from_mcp_session_file(p, tail_cap_bytes=None)
        self.assertFalse(trace.metadata.get("tail_only"))
        self.assertEqual(trace.declared_tools(), {"web_search"})


class TestSummarizeSurfacing(unittest.TestCase):
    def _summarize(self, path, cap, as_json):
        out, err = io.StringIO(), io.StringIO()
        old = mcp_session.TAIL_CAP_BYTES
        mcp_session.TAIL_CAP_BYTES = cap
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                rc = tap.summarize(path, as_json=as_json)
        finally:
            mcp_session.TAIL_CAP_BYTES = old
        return rc, out.getvalue(), err.getvalue()

    def test_json_completeness_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = big_session(tmp)
            rc, out, err = self._summarize(p, 2000, as_json=True)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["completeness"],
                         "partial_tail_only")
        self.assertIn("WARN", err)

    def test_json_completeness_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            rc, out, err = self._summarize(p, 10 ** 9, as_json=True)
        self.assertEqual(json.loads(out)["completeness"], "complete")
        self.assertNotIn("WARN", err)

    def test_text_mode_warns_on_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = big_session(tmp)
            rc, out, err = self._summarize(p, 2000, as_json=False)
        self.assertIn("tail-only", err)


class TestReportSurfacing(unittest.TestCase):
    def test_partial_banner_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            trace = from_mcp_session_file(p)
        trace.metadata["tail_only"] = True
        html = report_mod.render_html(trace, "s.jsonl")
        self.assertIn("PARTIAL", html)
        self.assertIn("tail-only", html)

    def test_no_banner_when_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            trace = from_mcp_session_file(p)
        html = report_mod.render_html(trace, "s.jsonl")
        self.assertNotIn("PARTIAL", html)


class TestWatchSurfacing(unittest.TestCase):
    def test_fingerprint_carries_tail_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            trace = from_mcp_session_file(p)
        trace.metadata["tail_only"] = True
        fp = watch.fingerprint(trace, "s.jsonl")
        self.assertTrue(fp["tail_only"])

    def test_drift_emits_low_confidence_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            trace = from_mcp_session_file(p)
        base = watch.merge(watch.new_baseline(),
                           watch.fingerprint(trace, "a.jsonl"))
        trace.metadata["tail_only"] = True
        fp = watch.fingerprint(trace, "b.jsonl")
        kinds = [d.kind for d in watch.drift(base, fp)]
        self.assertIn("tail_only_partial", kinds)

    def test_no_notice_when_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake())
            trace = from_mcp_session_file(p)
        base = watch.merge(watch.new_baseline(),
                           watch.fingerprint(trace, "a.jsonl"))
        fp = watch.fingerprint(trace, "b.jsonl")
        kinds = [d.kind for d in watch.drift(base, fp)]
        self.assertNotIn("tail_only_partial", kinds)


if __name__ == "__main__":
    unittest.main()
