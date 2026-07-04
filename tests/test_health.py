"""
Self-metrics + `glassport health` (roadmap H1.09).

The ironic gap: an observability tool with no internal metrics. The tap
now writes one `{"type": "glassport.metrics", ...}` JSONL line at
session end — same file as the wire log, tagged so every analysis
consumer filters it out — and `glassport health` aggregates the last N
sessions into "is the tap healthy?".

Doctrine: the metrics line carries only what the tap itself witnessed
(frames, blocked count, duration, bytes). Detector errors are computed
offline by health, never asserted by the tap.

Pure stdlib, run with:  python3 -m unittest tests.test_health
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from glassport import health as health_mod
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.tap import SessionLog
from glassport import report as report_mod
from tests.test_detectors import handshake


def write_session(tmp, name, lines, metrics=None) -> Path:
    p = Path(tmp) / name
    body = list(lines)
    if metrics is not None:
        body.append(json.dumps({"type": "glassport.metrics", **metrics}))
    p.write_text("\n".join(body) + "\n", encoding="utf-8")
    return p


class TestMetricsLine(unittest.TestCase):
    def test_session_log_write_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            log = SessionLog(p)
            log.record("c2s", b'{"jsonrpc":"2.0","id":1,"method":"x"}\n')
            log.write_metrics(frames_blocked=2, session_duration_s=1.5)
            log.close()
            last = json.loads(p.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(last["type"], "glassport.metrics")
        self.assertEqual(last["frames_seen"], 1)
        self.assertEqual(last["frames_blocked"], 2)
        self.assertEqual(last["session_duration_s"], 1.5)
        self.assertGreater(last["log_bytes"], 0)

    def test_adapter_skips_metrics_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake(),
                              metrics={"frames_seen": 5})
            trace = from_mcp_session_file(p)
        # the metrics line is self-observation, not wire traffic:
        # no event, no unparsed-raw artifact
        self.assertFalse(any(e.metadata.get("unparsed")
                             for e in trace.events))
        self.assertEqual(trace.declared_tools(), {"web_search"})

    def test_metrics_never_reaches_report_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_session(tmp, "s.jsonl", handshake(),
                              metrics={"frames_seen": 5})
            html = report_mod.render_html(from_mcp_session_file(p), "s")
        self.assertNotIn("glassport.metrics", html)


class TestHealthCommand(unittest.TestCase):
    def run_health(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = health_mod.main(argv)
        return rc, out.getvalue()

    def test_aggregates_recent_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_session(tmp, "20260101T000000Z_a_1.jsonl", handshake(),
                          metrics={"frames_seen": 5, "frames_blocked": 1,
                                   "session_duration_s": 2.0,
                                   "log_bytes": 100})
            write_session(tmp, "20260102T000000Z_b_2.jsonl", handshake(),
                          metrics={"frames_seen": 7, "frames_blocked": 0,
                                   "session_duration_s": 3.0,
                                   "log_bytes": 200})
            rc, out = self.run_health(["--log-dir", tmp, "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["sessions"], 2)
        self.assertEqual(data["frames_seen"], 12)
        self.assertEqual(data["frames_blocked"], 1)
        self.assertEqual(data["sessions_missing_metrics"], 0)
        self.assertIn("detector_errors", data)

    def test_session_without_metrics_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_session(tmp, "20260101T000000Z_a_1.jsonl", handshake())
            rc, out = self.run_health(["--log-dir", tmp, "--json"])
        data = json.loads(out)
        self.assertEqual(data["sessions_missing_metrics"], 1)

    def test_text_mode_one_line_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_session(tmp, "20260101T000000Z_a_1.jsonl", handshake(),
                          metrics={"frames_seen": 5})
            rc, out = self.run_health(["--log-dir", tmp])
        self.assertEqual(rc, 0)
        self.assertIn("healthy", out.lower())

    def test_empty_dir_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = self.run_health(["--log-dir", tmp])
        self.assertEqual(rc, 0)
        self.assertIn("no sessions", out.lower())


if __name__ == "__main__":
    unittest.main()
