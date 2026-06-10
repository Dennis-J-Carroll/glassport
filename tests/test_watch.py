"""
Tests for watch.py — M4 cross-session drift detection.

fingerprint() summarizes one session; drift() compares a fingerprint
against the merged baseline of every prior session; watch_dir() runs the
whole pipeline over a directory of tap logs, grouped by server identity.
Pure stdlib, run with:  python3 -m unittest tests.test_watch
"""
import json
import tempfile
import unittest
from pathlib import Path

from adapters.mcp_session import from_mcp_session
import watch
from tests.test_detectors import L, handshake, call, result


def fp(lines, source="s.jsonl"):
    return watch.fingerprint(from_mcp_session(lines), source_name=source)


def session(tools=None, calls=(), extra=()):
    """handshake + tool calls (auto seq/rid) + extra raw lines."""
    lines = handshake(tools=tools)
    seq, rid = 6, 3
    for name, args in calls:
        lines.append(call(seq, rid, name, args))
        seq += 1
        lines.append(result(seq, rid))
        seq += 1
        rid += 1
    return lines + list(extra)


def rename_server(lines, name):
    """Rewrite serverInfo in the initialize result."""
    out = []
    for ln in lines:
        e = json.loads(ln)
        f = e.get("frame") or {}
        if isinstance(f.get("result"), dict) and "serverInfo" in f["result"]:
            f["result"]["serverInfo"] = {"name": name, "version": "9.9"}
        out.append(json.dumps(e))
    return out


def kinds(findings):
    return [d.kind for d in findings]


CLEAN = (("web_search", {"query": "x"}),)


class TestFingerprint(unittest.TestCase):
    def test_basic_fields(self):
        f = fp(session(calls=CLEAN))
        self.assertEqual(f["declared_tools"], ["web_search"])
        self.assertEqual(f["called_tools"], ["web_search"])
        self.assertEqual(f["fabricated_tools"], [])
        self.assertEqual(f["server_name"], "test-server")
        json.dumps(f)  # must be JSON-serializable as-is

    def test_schema_hash_key_order_invariant(self):
        a = [{"name": "t", "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"]}}]
        b = [{"name": "t", "inputSchema": {
            "required": ["q"],
            "properties": {"q": {"type": "string"}},
            "type": "object"}}]
        c = [{"name": "t", "inputSchema": {
            "type": "object",
            "properties": {"q": {"type": "string"},
                           "extra": {"type": "string"}},
            "required": ["q"]}}]
        ha = fp(session(tools=a))["schema_hashes"]["t"]
        hb = fp(session(tools=b))["schema_hashes"]["t"]
        hc = fp(session(tools=c))["schema_hashes"]["t"]
        self.assertEqual(ha, hb)
        self.assertNotEqual(ha, hc)

    def test_hosts_extracted_from_args_and_results(self):
        lines = handshake() + [
            call(6, 3, "web_search",
                 {"query": "x", "url": "https://API.Example.com/v1?q=1"}),
            result(7, 3, {"content": [
                {"type": "text",
                 "text": "fetched (https://cdn.evil.net/asset.js)"}]}),
        ]
        hosts = fp(lines)["hosts"]
        self.assertIn("api.example.com", hosts)   # lowercased
        self.assertIn("cdn.evil.net", hosts)      # trailing ')' stripped

    def test_server_requests_recorded(self):
        lines = session(calls=CLEAN) + [
            L(20, "s2c", {"jsonrpc": "2.0", "id": 9,
                          "method": "sampling/createMessage", "params": {}}),
        ]
        self.assertIn("sampling/createMessage", fp(lines)["server_requests"])

    def test_fabricated_recorded(self):
        f = fp(session(calls=(("shadow_tool", {}),)))
        self.assertIn("shadow_tool", f["fabricated_tools"])


class TestDrift(unittest.TestCase):
    def baseline_from(self, *fps):
        base = watch.new_baseline()
        for f in fps:
            watch.merge(base, f)
        return base

    def test_first_session_is_baseline_not_drift(self):
        self.assertEqual(watch.drift(watch.new_baseline(),
                                     fp(session(calls=CLEAN))), [])

    def test_identical_sessions_no_drift(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        self.assertEqual(watch.drift(base, fp(session(calls=CLEAN))), [])

    def test_new_declared_tool_sev2(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        two = [{"name": "web_search"}, {"name": "shell_exec"}]
        findings = watch.drift(base, fp(session(tools=two)))
        self.assertIn("new_declared_tool", kinds(findings))
        f = next(d for d in findings if d.kind == "new_declared_tool")
        self.assertEqual(f.severity, 2)
        self.assertIn("shell_exec", f.explanation)

    def test_removed_declared_tool_sev1(self):
        two = [{"name": "web_search"}, {"name": "file_read"}]
        base = self.baseline_from(fp(session(tools=two)))
        findings = watch.drift(base, fp(session()))  # web_search only
        f = next(d for d in findings if d.kind == "removed_declared_tool")
        self.assertEqual(f.severity, 1)
        self.assertIn("file_read", f.explanation)

    def test_no_tools_list_does_not_mean_removal(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        bare = [call(1, 1, "web_search", {"query": "x"})]  # no handshake
        findings = watch.drift(base, fp(bare))
        self.assertNotIn("removed_declared_tool", kinds(findings))

    def test_schema_change_sev2(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        changed = [{"name": "web_search",
                    "inputSchema": {"type": "object",
                                    "properties": {"q": {"type": "string"}}}}]
        findings = watch.drift(base, fp(session(tools=changed)))
        f = next(d for d in findings if d.kind == "schema_changed")
        self.assertEqual(f.severity, 2)
        self.assertIn("web_search", f.explanation)

    def test_new_fabricated_tool_sev3(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        findings = watch.drift(base, fp(session(calls=(("exfil", {}),))))
        f = next(d for d in findings if d.kind == "new_fabricated_tool")
        self.assertEqual(f.severity, 3)
        self.assertIn("exfil", f.explanation)

    def test_new_host_sev2(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        drifted = session(calls=(
            ("web_search", {"query": "x", "url": "https://evil.example/p"}),))
        findings = watch.drift(base, fp(drifted))
        f = next(d for d in findings if d.kind == "new_host")
        self.assertEqual(f.severity, 2)
        self.assertIn("evil.example", f.explanation)

    def test_new_server_request_sev2(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        drifted = session(calls=CLEAN) + [
            L(20, "s2c", {"jsonrpc": "2.0", "id": 9,
                          "method": "roots/list", "params": {}}),
        ]
        findings = watch.drift(base, fp(drifted))
        f = next(d for d in findings if d.kind == "new_server_request")
        self.assertEqual(f.severity, 2)

    def test_server_identity_change_sev2(self):
        base = self.baseline_from(fp(session(calls=CLEAN)))
        renamed = rename_server(session(calls=CLEAN), "other-server")
        findings = watch.drift(base, fp(renamed))
        f = next(d for d in findings if d.kind == "server_identity_changed")
        self.assertEqual(f.severity, 2)

    def test_first_call_of_declared_tool_sev1(self):
        two = [{"name": "web_search"}, {"name": "file_read"}]
        base = self.baseline_from(fp(session(tools=two, calls=CLEAN)))
        drifted = session(tools=two, calls=CLEAN + (("file_read", {}),))
        findings = watch.drift(base, fp(drifted))
        f = next(d for d in findings if d.kind == "new_called_tool")
        self.assertEqual(f.severity, 1)

    def test_merge_accumulates_no_reflag(self):
        two = [{"name": "web_search"}, {"name": "shell_exec"}]
        base = self.baseline_from(fp(session()), fp(session(tools=two)))
        # third session identical to second: shell_exec already seen
        self.assertEqual(watch.drift(base, fp(session(tools=two))), [])


class TestWatchDir(unittest.TestCase):
    def _write(self, tmp, name, lines):
        p = Path(tmp) / name
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_drift_appears_in_third_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "01_srv_1.jsonl", session(calls=CLEAN))
            self._write(tmp, "02_srv_2.jsonl", session(calls=CLEAN))
            self._write(tmp, "03_srv_3.jsonl",
                        session(calls=(("exfil", {}),)))
            groups = watch.watch_dir(tmp)
            self.assertEqual(len(groups), 1)
            rows = next(iter(groups.values()))
            self.assertEqual([r["source"] for r in rows],
                             ["01_srv_1.jsonl", "02_srv_2.jsonl",
                              "03_srv_3.jsonl"])
            self.assertEqual(rows[0]["findings"], [])   # baseline
            self.assertEqual(rows[1]["findings"], [])   # clean
            self.assertIn("new_fabricated_tool", kinds(rows[2]["findings"]))

    def test_servers_do_not_cross_contaminate(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._write(tmp, "01_a_1.jsonl", session(calls=CLEAN))
            self._write(tmp, "02_b_1.jsonl",
                        rename_server(session(calls=CLEAN), "other-server"))
            groups = watch.watch_dir(tmp)
            self.assertEqual(len(groups), 2)
            for rows in groups.values():
                # each server's first session is its own baseline
                self.assertEqual(rows[0]["findings"], [])


if __name__ == "__main__":
    unittest.main()
