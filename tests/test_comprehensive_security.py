"""
Comprehensive security hardening tests for glassport.

These tests probe the attack surface that an MCP server, a malicious client,
or a tampered session log can present to glassport itself. They cover:

  * adversarial wire inputs and parsing robustness
  * gate enforcement edge cases and concurrency
  * static-audit containment and symlink safety
  * the glassport MCP server's tool inputs (path traversal, etc.)
  * tap/session-log fault isolation
  * report/HTML output safety
  * resource limits and DoS resistance

Every failing test here is a finding: either a crash (availability) or a
bypass (integrity/confidentiality). Run with:

    python3 -m pytest tests/test_comprehensive_security.py -v
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from glassport import audit, detectors, report as report_mod, server as server_mod
from glassport.adapters.mcp_session import from_mcp_session
from glassport.tap import Gate, SessionLog, pump, run_tap
from tests.test_detectors import L, call, handshake, result


def subcats(anns):
    return [a.subcategory for a in anns]


# ─────────────────────────────────────────────────────────────────────────────
# A. Adversarial wire inputs
# ─────────────────────────────────────────────────────────────────────────────
class TestAdversarialWireInputs(unittest.TestCase):
    """The adapter must never crash on attacker-controlled log bytes."""

    def test_missing_seq_is_accepted(self):
        line = json.dumps({"schema_version": "0.1", "ts": "t", "dir": "c2s",
                           "frame": {"jsonrpc": "2.0", "id": 1,
                                     "method": "tools/list"},
                           "raw": None})
        trace = from_mcp_session([line])
        self.assertEqual(len(trace.events), 1)
        self.assertIsNone(trace.events[0].metadata.get("seq"))

    def test_null_frame_and_raw_both_none(self):
        line = json.dumps({"schema_version": "0.1", "seq": 1, "ts": "t",
                           "dir": "c2s", "frame": None, "raw": None})
        trace = from_mcp_session([line])
        # nothing meaningful to emit, but it must not crash
        self.assertIsInstance(trace, object)

    def test_invalid_utf8_replaced_not_crashed(self):
        # the tap uses errors="replace"; the adapter must survive the result
        raw = b'{"schema_version":"0.1","seq":1,"ts":"t","dir":"c2s",'
        raw += b'"frame":{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        raw += b'"params":{"name":"x","arguments":{}}},"raw":null}'
        raw = raw.replace(b'"x"', b'"\xff\xfe"')  # invalid utf-8 inside name
        trace = from_mcp_session([raw.decode("utf-8", errors="replace")])
        # should ingest without raising; the exact event shape is secondary
        self.assertGreaterEqual(len(trace.events), 0)

    def test_very_long_argument_value_is_capped(self):
        # A multi-megabyte argument must not wedge the PII scanner. The
        # scanner caps each blob at MAX_SCAN_BYTES, so this should complete
        # in well under a second even on a huge value.
        huge = "x" * (2 * 1024 * 1024)
        lines = handshake() + [call(6, 3, "web_search", {"query": huge})]
        trace = from_mcp_session(lines)
        start = time.perf_counter()
        detectors.data_exfiltration(trace)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 2.0,
                        "scanning a 2 MB argument took too long")

    def test_deeply_nested_arguments_dont_stack_overflow(self):
        nested: dict = {}
        cur = nested
        for _ in range(500):
            cur["next"] = {}
            cur = cur["next"]
        lines = handshake() + [call(6, 3, "web_search", {"query": nested})]
        trace = from_mcp_session(lines)
        # host extraction and PII scan recurse; must not blow the stack
        detectors.data_exfiltration(trace)


class TestDetectorReDoS(unittest.TestCase):
    """Detector regexes must not catastrophically backtrack on hostile input."""

    def test_email_pattern_fast_on_no_at_sign(self):
        # The original email regex was O(2^N)-equivalent on long strings with
        # no '@'. The bounded quantifier version must stay linear.
        huge = "x" * 200_000
        start = time.perf_counter()
        hits = detectors._scan_pii(huge)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0,
                        f"email scan took {elapsed:.1f}s on {len(huge)} chars")
        self.assertEqual(hits, [])

    def test_email_pattern_still_catches_valid_address(self):
        hits = detectors._scan_pii("contact alice@example.com please")
        cats = {p.category for p, _ in hits}
        self.assertIn("email_address", cats)


# ─────────────────────────────────────────────────────────────────────────────
# B. Gate enforcement edge cases
# ─────────────────────────────────────────────────────────────────────────────
class TestGateEdgeCases(unittest.TestCase):
    """The gate must enforce the declared surface under adversarial input."""

    def test_gate_blocks_non_string_tool_name(self):
        g = Gate()
        g.observe_s2c((json.dumps({"jsonrpc": "2.0", "id": 2,
                                   "result": {"tools": [{"name": "ok"}]}})
                       + "\n").encode())
        action, resp, info = g.check_c2s(
            (json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": 12345, "arguments": {}}})
            + "\n").encode())
        self.assertEqual(action, "block")
        self.assertEqual(info["action"], "blocked")

    def test_gate_empty_tools_list_blocks_everything(self):
        g = Gate()
        g.observe_s2c((json.dumps({"jsonrpc": "2.0", "id": 2,
                                   "result": {"tools": []}})
                       + "\n").encode())
        action, _, _ = g.check_c2s(
            (json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": "anything"}})
            + "\n").encode())
        self.assertEqual(action, "block")

    def test_gate_holds_multiple_concurrent_calls(self):
        g = Gate(hold_timeout=5.0)
        results: dict[str, tuple] = {}

        def fire(tool):
            ln = (json.dumps({"jsonrpc": "2.0", "id": 1,
                              "method": "tools/call",
                              "params": {"name": tool, "arguments": {}}})
                  + "\n").encode()
            results[tool] = g.check_c2s(ln)

        t1 = threading.Thread(target=fire, args=("declared",), daemon=True)
        t2 = threading.Thread(target=fire, args=("undeclared",), daemon=True)
        t1.start()
        t2.start()
        time.sleep(0.15)
        self.assertTrue(t1.is_alive() or t2.is_alive(),
                        "concurrent calls should be held, not both decided")
        g.observe_s2c((json.dumps({"jsonrpc": "2.0", "id": 2,
                                   "result": {"tools": [{"name": "declared"}]}})
                       + "\n").encode())
        t1.join(timeout=5)
        t2.join(timeout=5)
        self.assertEqual(results["declared"][0], "forward")
        self.assertEqual(results["undeclared"][0], "block")

    def test_gate_latest_declaration_is_contract_after_hold(self):
        g = Gate(hold_timeout=5.0)
        ln = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "first", "arguments": {}}})
              + "\n").encode()

        result = {}
        t = threading.Thread(target=lambda: result.setdefault("r", g.check_c2s(ln)),
                             daemon=True)
        t.start()
        time.sleep(0.1)
        # first declaration allows 'first'
        g.observe_s2c((json.dumps({"jsonrpc": "2.0", "id": 2,
                                   "result": {"tools": [{"name": "first"}]}})
                       + "\n").encode())
        # immediately redeclare a smaller surface before the held call wakes
        g.observe_s2c((json.dumps({"jsonrpc": "2.0", "id": 3,
                                   "result": {"tools": [{"name": "second"}]}})
                       + "\n").encode())
        t.join(timeout=5)
        # the latest declaration shrinks the contract
        self.assertEqual(result["r"][0], "block")


# ─────────────────────────────────────────────────────────────────────────────
# C. Static audit containment
# ─────────────────────────────────────────────────────────────────────────────
class TestAuditContainment(unittest.TestCase):
    """The audit must not escape the directory it was asked to read."""

    def test_audit_does_not_follow_file_symlinks_outside_root(self):
        # If an audited tree contains a symlink to a file outside the root,
        # the scanner must skip it. Reading through it would leak arbitrary
        # files on the host.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "audit_root"
            root.mkdir()
            secret = Path(tmp) / "secret.txt"
            secret.write_text("AKIA" + "X" * 16 + "\n", encoding="utf-8")
            (root / "link.py").symlink_to(secret)
            (root / "real.py").write_text("x = 1\n", encoding="utf-8")

            report = audit.audit_path(root)
            paths = {f.path for f in report.findings}
            self.assertNotIn("secret.txt", paths)
            # real.py should still be scanned
            self.assertEqual(report.profile["files_scanned"], 1)

    def test_audit_does_not_follow_directory_symlinks_outside_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "audit_root"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "evil.py").write_text("eval(x)\n", encoding="utf-8")
            (root / "nested").symlink_to(outside)
            (root / "real.py").write_text("x = 1\n", encoding="utf-8")

            report = audit.audit_path(root)
            self.assertNotIn("evil.py", {f.path for f in report.findings})
            self.assertEqual(report.profile["files_scanned"], 1)

    def test_audit_survives_permission_denied_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            p = root / "locked.py"
            p.write_text("eval(x)\n", encoding="utf-8")
            os.chmod(p, 0o000)
            try:
                report = audit.audit_path(root)
                # must complete without raising; may or may not see the file
                self.assertIsNotNone(report.score)
            finally:
                os.chmod(p, 0o644)

    def test_audit_of_single_file_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "server.py"
            p.write_text("eval(x)\n", encoding="utf-8")
            report = audit.audit_path(p)
            self.assertIn("exec-dynamic", {f.rule for f in report.findings})


# ─────────────────────────────────────────────────────────────────────────────
# D. glassport MCP server tool security
# ─────────────────────────────────────────────────────────────────────────────
class TestServeToolSecurity(unittest.TestCase):
    """The `serve` MCP tools must treat their arguments as untrusted."""

    def _tool(self, name, arguments, log_dir):
        src = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1,
                                      "method": "tools/call",
                                      "params": {"name": name,
                                                 "arguments": arguments}})
                          + "\n")
        out = io.StringIO()
        server_mod.serve(src, out, log_dir=Path(log_dir))
        return json.loads(out.getvalue().splitlines()[0])

    def test_analyze_session_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir()
            # create a file outside log_dir that the tool must NOT read
            outside = Path(tmp) / "secret.jsonl"
            outside.write_text("SECRET\n", encoding="utf-8")
            resp = self._tool("analyze_session",
                              {"session_path": str(outside)}, log_dir)
        self.assertTrue(resp["result"].get("isError"),
                        "path traversal outside log_dir must be rejected")

    def test_get_gate_status_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir()
            outside = Path(tmp) / "secret.jsonl"
            outside.write_text("SECRET\n", encoding="utf-8")
            resp = self._tool("get_gate_status",
                              {"session_path": str(outside)}, log_dir)
        self.assertTrue(resp["result"].get("isError"),
                        "path traversal outside log_dir must be rejected")

    def test_analyze_session_accepts_log_dir_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir()
            sess = log_dir / "20260101T000000Z_srv_1.jsonl"
            sess.write_text("\n".join(handshake()), encoding="utf-8")
            resp = self._tool("analyze_session",
                              {"session_path": str(sess)}, log_dir)
        self.assertFalse(resp["result"].get("isError", False))

    def test_analyze_session_requires_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            resp = self._tool("analyze_session", {}, tmp)
        self.assertTrue(resp["result"].get("isError"))


# ─────────────────────────────────────────────────────────────────────────────
# E. Tap / session log fault isolation
# ─────────────────────────────────────────────────────────────────────────────
class TestTapFaultIsolation(unittest.TestCase):
    """The relay is sacred: logging failures must not kill the session."""

    def test_run_tap_survives_unwritable_log_dir(self):
        # If the log directory cannot be created, the tap should still spawn
        # the child and relay traffic (even if it cannot log). We run run_tap
        # in a subprocess because it installs signal handlers that would
        # interfere with the test runner.
        with tempfile.TemporaryDirectory() as tmp:
            bad_log = Path(tmp) / "not_a_dir"
            bad_log.write_text("i am a file, not a directory\n")
            script = Path(tmp) / "runner.py"
            script.write_text(
                '''from glassport.tap import run_tap
import sys
from pathlib import Path
rc = run_tap([sys.executable, '-c',
              'import sys; sys.stdout.write("hello\\\\n")'],
             log_dir=Path(sys.argv[1]), gate=None)
sys.exit(rc)
''',
                encoding="utf-8")
            env = {**os.environ,
                   "PYTHONPATH": str(Path(__file__).resolve().parent.parent
                                    / "src")}
            child = subprocess.run(
                [sys.executable, str(script), str(bad_log)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                env=env)
            self.assertEqual(child.returncode, 0,
                             "tap must relay child even when logging fails: "
                             + child.stderr.decode("utf-8", errors="replace"))
            self.assertIn(b"hello", child.stdout)

    def test_session_log_record_never_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = SessionLog(Path(tmp) / "s.jsonl")
            # deliberately broken bytes that cannot decode cleanly
            log.record("c2s", b"\xff\xfe\n")
            log.record("s2c", b"valid line\n")
            log.close()
            text = (Path(tmp) / "s.jsonl").read_text(encoding="utf-8")
            self.assertIn("valid line", text)

    def test_pump_broken_pipe_does_not_crash(self):
        src = io.BytesIO(b"line1\nline2\n")
        dst = io.BytesIO()
        dst.close = lambda: None  # type: ignore[method-assign]

        def broken_write(b):
            raise BrokenPipeError()

        dst.write = broken_write  # type: ignore[method-assign]
        # pump catches BrokenPipeError and exits cleanly
        pump(src, dst, None, "c2s")
        self.assertTrue(True, "pump must not raise on BrokenPipeError")


# ─────────────────────────────────────────────────────────────────────────────
# F. Report HTML safety
# ─────────────────────────────────────────────────────────────────────────────
class TestReportHtmlSafety(unittest.TestCase):
    """The report must neutralize hostile content from the wire."""

    def test_javascript_url_in_tool_description_is_escaped(self):
        tools = [{
            "name": "fetch",
            "description": "Open javascript:alert(1)",
            "inputSchema": {"type": "object",
                            "properties": {"url": {"type": "string"}}}
        }]
        lines = handshake(tools=tools) + [
            call(6, 3, "fetch", {"url": "javascript:alert(1)"})]
        html = report_mod.render_html(from_mcp_session(lines), "test.jsonl")
        # The literal URL scheme text is fine inside a <pre> block; what
        # matters is that it cannot become an active href/src attribute.
        self.assertNotIn("<a", html.lower())
        self.assertNotIn("<script", html.lower())
        self.assertIn("javascript:alert(1)", html)

    def test_svg_onload_payload_is_escaped(self):
        evil = '<svg onload="alert(1)">'
        lines = handshake() + [call(6, 3, "web_search", {"query": evil})]
        html = report_mod.render_html(from_mcp_session(lines), "test.jsonl")
        self.assertNotIn("<svg", html)
        self.assertIn("&lt;svg", html)

    def test_report_handles_very_large_annotation_count(self):
        lines = handshake()
        # many fabricated calls
        for i in range(250):
            lines.append(call(6 + i, 100 + i, f"bad_{i}", {}))
        trace = from_mcp_session(lines)
        detectors.annotate(trace)
        html = report_mod.render_html(trace, "test.jsonl")
        self.assertIn("HOSTILE OR HALLUCINATED", html)


# ─────────────────────────────────────────────────────────────────────────────
# G. Detector robustness
# ─────────────────────────────────────────────────────────────────────────────
class TestDetectorRobustness(unittest.TestCase):
    """Detectors must degrade gracefully on malformed trace state."""

    def test_schema_violation_with_non_object_schema(self):
        tools = [{
            "name": "weird",
            "inputSchema": "not an object"  # type: ignore[dict-item]
        }]
        lines = handshake(tools=tools) + [
            call(6, 3, "weird", {"x": 1})]
        trace = from_mcp_session(lines)
        # must not raise
        detectors.annotate(trace)

    def test_pii_scan_on_non_string_keys(self):
        # JSON keys are always strings, but the serialized blob may contain
        # secrets in keys in unusual encodings; scanning must not crash.
        lines = handshake() + [call(6, 3, "web_search",
                                    {"key-with-" + "A" * 80: "value"})]
        trace = from_mcp_session(lines)
        detectors.data_exfiltration(trace)

    def test_capability_violation_on_notification_not_request(self):
        # server sends sampling/createMessage as a notification (no id).
        # It is not a request the client must grant; should not flag.
        lines = handshake(client_caps={}) + [
            L(6, "s2c", {"jsonrpc": "2.0", "method": "sampling/createMessage",
                         "params": {}}),
        ]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertNotIn("capability_violation", subcats(anns))


if __name__ == "__main__":
    unittest.main()
