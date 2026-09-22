"""
Tests for watch.py — M4 cross-session drift detection.

fingerprint() summarizes one session; drift() compares a fingerprint
against the merged baseline of every prior session; watch_dir() runs the
whole pipeline over a directory of tap logs, grouped by server identity.
Pure stdlib, run with:  python3 -m unittest tests.test_watch
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from glassport.adapters.mcp_session import from_mcp_session
from glassport import watch
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
        # removes "query"/"limit" and adds "q" -> a removed property, so
        # Task 8's classifier correctly calls this mutative (severity 3),
        # not the flat severity-2 every schema change got pre-Task-8.
        changed = [{"name": "web_search",
                    "inputSchema": {"type": "object",
                                    "properties": {"q": {"type": "string"}}}}]
        findings = watch.drift(base, fp(session(tools=changed)))
        f = next(d for d in findings if d.kind == "schema_changed")
        self.assertEqual(f.severity, 3)
        self.assertEqual(f.detail["change_kind"], "mutative")
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


class TestJSDDrift(unittest.TestCase):
    def baseline_from(self, *fps):
        base = watch.new_baseline()
        for f in fps:
            watch.merge(base, f)
        return base

    def test_tool_call_counts_present_in_fingerprint(self):
        f = fp(session(calls=(("search", {}), ("search", {}), ("fetch", {}))))
        self.assertEqual(f["tool_call_counts"], {"search": 2, "fetch": 1})

    def test_jsd_drift_flagged_on_vocabulary_shift(self):
        history = [fp(session(calls=(("query_database", {}),) * 10))
                   for _ in range(5)]
        base = self.baseline_from(*history)
        shifted = fp(session(calls=(("execute_powershell", {}),) * 10))
        findings = watch.drift(base, shifted)
        jsd = [d for d in findings if d.kind == "jsd_drift"]
        self.assertEqual(len(jsd), 1)
        self.assertGreater(jsd[0].detail["jsd"], 0.5)
        self.assertEqual(jsd[0].severity, 3)

    def test_jsd_drift_absent_on_stable_vocabulary(self):
        history = [fp(session(calls=(("query_database", {}),) * 10))
                   for _ in range(5)]
        base = self.baseline_from(*history)
        stable = fp(session(calls=(("query_database", {}),) * 10))
        findings = watch.drift(base, stable)
        self.assertEqual([d for d in findings if d.kind == "jsd_drift"], [])


class TestTemporalIntegrity(unittest.TestCase):
    def test_fingerprint_captures_ttl_fields(self):
        lines = handshake(tools=[{"name": "search"}])[:4] + [
            L(5, "s2c", {"jsonrpc": "2.0", "id": 2,
                        "result": {"tools": [{"name": "search"}],
                                   "ttlMs": 60000, "cacheScope": "public"}}),
        ]
        f = fp(lines)
        self.assertEqual(f["tools_list_ttl_ms"], 60000)
        self.assertEqual(f["tools_list_cache_scope"], "public")

    def test_premature_list_changed_flagged(self):
        lines = [
            json.dumps({"schema_version": "0.1", "seq": 1,
                        "ts": "2026-01-01T00:00:00+00:00", "dir": "c2s",
                        "frame": {"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/list"}}),
            json.dumps({"schema_version": "0.1", "seq": 2,
                        "ts": "2026-01-01T00:00:01+00:00", "dir": "s2c",
                        "frame": {"jsonrpc": "2.0", "id": 1,
                          "result": {"tools": [{"name": "search"}],
                                     "ttlMs": 3600000}}}),  # 1 hour
            json.dumps({"schema_version": "0.1", "seq": 3,
                        "ts": "2026-01-01T00:00:06+00:00", "dir": "s2c",
                        "frame": {"jsonrpc": "2.0",
                                  "method": "notifications/tools/list_changed"}}),
        ]
        f = fp(lines)
        self.assertTrue(f["premature_list_changed"])

    def test_list_changed_after_ttl_expiry_not_flagged(self):
        lines = [
            json.dumps({"schema_version": "0.1", "seq": 1,
                        "ts": "2026-01-01T00:00:00+00:00", "dir": "c2s",
                        "frame": {"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/list"}}),
            json.dumps({"schema_version": "0.1", "seq": 2,
                        "ts": "2026-01-01T00:00:01+00:00", "dir": "s2c",
                        "frame": {"jsonrpc": "2.0", "id": 1,
                          "result": {"tools": [{"name": "search"}],
                                     "ttlMs": 1000}}}),  # 1 second
            json.dumps({"schema_version": "0.1", "seq": 3,
                        "ts": "2026-01-01T00:00:05+00:00", "dir": "s2c",
                        "frame": {"jsonrpc": "2.0",
                                  "method": "notifications/tools/list_changed"}}),
        ]
        f = fp(lines)
        self.assertFalse(f["premature_list_changed"])


class TestSchemaChangeClassification(unittest.TestCase):
    def baseline_from(self, *fps):
        base = watch.new_baseline()
        for f in fps:
            watch.merge(base, f)
        return base

    def test_additive_schema_change_classified(self):
        old = [{"name": "t", "inputSchema": {"type": "object",
                "properties": {"a": {"type": "string"}}, "required": ["a"]}}]
        new = [{"name": "t", "inputSchema": {"type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                "required": ["a"]}}]
        base = self.baseline_from(fp(session(tools=old)))
        findings = watch.drift(base, fp(session(tools=new)))
        f = next(d for d in findings if d.kind == "schema_changed")
        self.assertEqual(f.detail["change_kind"], "additive")
        self.assertEqual(f.severity, 2)

    def test_mutative_schema_change_classified(self):
        old = [{"name": "t", "inputSchema": {"type": "object",
                "properties": {"a": {"type": "string"}}, "required": ["a"]}}]
        new = [{"name": "t", "inputSchema": {"type": "object",
                "properties": {"a": {"type": "integer"}}, "required": ["a"]}}]
        base = self.baseline_from(fp(session(tools=old)))
        findings = watch.drift(base, fp(session(tools=new)))
        f = next(d for d in findings if d.kind == "schema_changed")
        self.assertEqual(f.detail["change_kind"], "mutative")
        self.assertEqual(f.severity, 3)


class TestSchemaChangeReview(unittest.TestCase):
    def test_boolean_property_changes_are_reported_without_crashing(self):
        for old_spec, new_spec in (({"type": "string"}, True),
                                   ({"type": "string"}, False),
                                   (True, {"type": "string"}),
                                   (False, True), (True, False)):
            with self.subTest(old=old_spec, new=new_spec):
                old = [{"name": "t", "inputSchema": {
                    "type": "object", "properties": {"x": old_spec}}}]
                new = [{"name": "t", "inputSchema": {
                    "type": "object", "properties": {"x": new_spec}}}]
                base = watch.merge(watch.new_baseline(), fp(session(tools=old)))
                findings = watch.drift(base, fp(session(tools=new)))
                finding = next(d for d in findings if d.kind == "schema_changed")
                self.assertEqual(finding.detail["change_kind"], "mutative")
                self.assertEqual(finding.severity, 3)

    def test_unchanged_boolean_property_allows_additive_classification(self):
        old = {"properties": {"x": True}}
        new = {"properties": {"x": True, "y": {"type": "string"}}}
        self.assertEqual(watch._classify_schema_change(old, new), "additive")

    def test_malformed_schema_fields_do_not_crash(self):
        # A malformed baseline gives no reliable reference: unknown. A
        # malformed replacement breaks the declared contract: mutative, so
        # malformation cannot be used to lower a finding's severity.
        valid = {"properties": {"x": {"type": "string"}}, "required": ["x"]}
        for malformed in ({"properties": ["x"]},
                          {"properties": {"x": "string"}},
                          {"properties": {"x": {}}, "required": [{}]},
                          {"properties": {"x": {}}, "required": "x"}):
            with self.subTest(schema=malformed):
                self.assertEqual(watch._classify_schema_change(valid, malformed), "mutative")
                self.assertEqual(watch._classify_schema_change(malformed, valid), "unknown")

    def drift_finding(self, old_schema, new_schema):
        old = [{"name": "t", "inputSchema": old_schema}]
        new = [{"name": "t", "inputSchema": new_schema}]
        base = watch.merge(watch.new_baseline(), fp(session(tools=old)))
        findings = watch.drift(base, fp(session(tools=new)))
        return next(d for d in findings if d.kind == "schema_changed")

    def test_null_fields_cannot_downgrade_mutative_changes(self):
        old = {"type": "object", "required": ["x"],
               "properties": {"x": {"type": "string"}, "y": {"type": "string"}}}
        cases = {
            "type_change_with_null_required": {
                "type": "object", "required": None,
                "properties": {"x": {"type": "object"}, "y": {"type": "string"}}},
            "removal_with_null_required": {
                "type": "object", "required": None,
                "properties": {"x": {"type": "string"}}},
            "null_properties": {"type": "object", "properties": None},
            "malformed_sibling_spec": {
                "type": "object", "required": ["x"],
                "properties": {"x": {"type": "object"}, "y": "string"}},
        }
        for label, new in cases.items():
            with self.subTest(case=label):
                finding = self.drift_finding(old, new)
                self.assertEqual(finding.detail["change_kind"], "mutative")
                self.assertEqual(finding.severity, 3)

    def test_null_fields_in_baseline_do_not_mask_later_changes(self):
        old = {"type": "object", "required": None,
               "properties": {"x": {"type": "string"}}}
        mutated = {"type": "object", "required": None,
                   "properties": {"x": {"type": "integer"}}}
        finding = self.drift_finding(old, mutated)
        self.assertEqual(finding.detail["change_kind"], "mutative")
        self.assertEqual(finding.severity, 3)
        extended = {"type": "object", "required": None,
                    "properties": {"x": {"type": "string"}, "z": {"type": "string"}}}
        self.assertEqual(watch._classify_schema_change(old, extended), "additive")


class TestTemporalIntegrityReview(unittest.TestCase):
    def entry(self, seq, second, direction, frame):
        return json.dumps({"schema_version": "0.1", "seq": seq,
                           "ts": f"2026-01-01T00:00:{second:02d}+00:00",
                           "dir": direction, "frame": frame})

    def listed(self, seq, second, rid, extra=None, method="tools/list"):
        return [
            self.entry(seq, second, "c2s", {"jsonrpc": "2.0", "id": rid, "method": method}),
            self.entry(seq + 1, second + 1, "s2c", {"jsonrpc": "2.0", "id": rid,
                       "result": {"tools": [{"name": "search"}], **(extra or {})}}),
        ]

    def changed(self, seq, second, direction="s2c"):
        return self.entry(seq, second, direction, {
            "jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

    def test_premature_finding_survives_following_refresh(self):
        lines = self.listed(1, 0, 1, {"ttlMs": 60000}) + [self.changed(3, 6)]
        self.assertTrue(fp(lines)["premature_list_changed"])
        refreshed = lines + self.listed(4, 7, 2, {"ttlMs": 60000})
        self.assertTrue(fp(refreshed)["premature_list_changed"])
        base = watch.merge(watch.new_baseline(), fp(self.listed(1, 0, 1)))
        self.assertIn("premature_list_changed", kinds(watch.drift(base, fp(refreshed))))

    def test_omitted_cache_fields_clear_previous_declaration(self):
        lines = self.listed(1, 0, 1, {"ttlMs": 60000, "cacheScope": "public"})
        lines += self.listed(3, 7, 2) + [self.changed(5, 9)]
        f = fp(lines)
        self.assertIsNone(f["tools_list_ttl_ms"])
        self.assertIsNone(f["tools_list_cache_scope"])
        self.assertFalse(f["premature_list_changed"])

    def test_each_notification_uses_its_preceding_ttl(self):
        lines = self.listed(1, 0, 1, {"ttlMs": 1000}) + [self.changed(3, 5)]
        lines += self.listed(4, 6, 2, {"ttlMs": 1000}) + [self.changed(6, 10)]
        self.assertFalse(fp(lines)["premature_list_changed"])

    def test_unrelated_result_does_not_reset_declaration_window(self):
        lines = self.listed(1, 0, 1, {"ttlMs": 60000})
        lines += self.listed(3, 5, 2, {"ttlMs": 0}, method="ping")
        lines += [self.changed(5, 9)]
        f = fp(lines)
        self.assertTrue(f["premature_list_changed"])
        self.assertEqual(f["tools_list_ttl_ms"], 60000)

    def test_client_notification_is_not_a_server_surface_change(self):
        lines = self.listed(1, 0, 1, {"ttlMs": 60000})
        lines += [self.changed(3, 2, direction="c2s")]
        self.assertFalse(fp(lines)["premature_list_changed"])

    def test_malformed_timestamps_and_ttls_do_not_crash_analysis(self):
        for timestamp in (None, 3, "bad", "2026-01-01T00:00:01"):
            with self.subTest(timestamp=timestamp):
                lines = self.listed(1, 0, 1, {"ttlMs": 60000})
                listed = json.loads(lines[1])
                listed["ts"] = timestamp
                lines[1] = json.dumps(listed)
                lines += [self.changed(3, 2)]
                self.assertFalse(fp(lines)["premature_list_changed"])
        for ttl in (True, "60000", [], -1, float("inf"), float("nan")):
            with self.subTest(ttl=ttl):
                lines = self.listed(1, 0, 1, {"ttlMs": ttl}) + [self.changed(3, 1)]
                self.assertFalse(fp(lines)["premature_list_changed"])


if __name__ == "__main__":
    unittest.main()
