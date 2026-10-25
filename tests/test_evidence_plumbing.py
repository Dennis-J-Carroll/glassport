"""Phase 3a capture provenance, integrity, stable identities, and limits."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from glassport import decision_journal as dj, decision_replay as dr
from glassport import detectors, sarif, tap
from glassport.adapters.mcp_session import from_mcp_session, from_mcp_session_file
from glassport.limits import compute_limits
from tests.test_decision_journal import JournalCase, rewrite_chained, wire
from tests.test_detectors import call, handshake
from tests.test_http_gate import GateCase


class TestSessionHeaderTrailer(unittest.TestCase):
    def test_write_receipts_hash_exact_persisted_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.jsonl"
            log = tap.SessionLog(path)
            entry = {"seq": 1, "frame": {"text": "é"}}
            receipt = log.write_entry(entry)
            self.assertEqual(receipt,
                             hashlib.sha256(path.read_bytes()).hexdigest())
            before = path.stat().st_size
            journal_receipt = log.write_json({"kind": "profile", "epoch": "é"})
            self.assertEqual(journal_receipt,
                             hashlib.sha256(path.read_bytes()[before:]).hexdigest())
            log.close()

    def test_new_capture_hashes_exact_pretrailer_bytes_and_redacts_url(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
                os.environ, {"GLASSPORT_COMMIT": "abcdef1234567"}):
            path = Path(tmp) / "s.jsonl"
            log = tap.open_session_log(
                path, transport="http", mode="gate", strict=True,
                remote_url="https://alice:secret@example.test/s/path-canary/mcp?token=secret#secret")
            self.assertIsNotNone(log)
            log.record("c2s", b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n')
            log.write_metrics()
            log.close()
            lines = path.read_bytes().splitlines(keepends=True)
            header, entry, trailer = [json.loads(line) for line in lines]
            self.assertEqual(header["type"], "glassport.header")
            self.assertEqual(header["schema_version"], "0.2")
            self.assertEqual(header["commit"], "abcdef1234567")
            self.assertEqual((header["transport"], header["mode"], header["strict"]),
                             ("http", "gate", True))
            self.assertEqual(header["remote"], {
                "scheme": "https", "host": "example.test", "port": None,
                "path_sha256": hashlib.sha256(b"/s/path-canary/mcp").hexdigest(),
            })
            self.assertNotIn(b"path-canary", lines[0])
            self.assertNotIn(b"alice", lines[0])
            self.assertNotIn(b"secret", lines[0])
            self.assertIn("header_values", header["redacted"])
            self.assertEqual(header["journal_schema"], dj.JOURNAL_SCHEMA)
            self.assertEqual(entry["schema_version"], "0.2")
            self.assertEqual(trailer["entries_written"], 1)
            self.assertEqual(trailer["seq_range"], [1, 1])
            self.assertEqual(trailer["write_failures"], 0)
            self.assertEqual(trailer["log_sha256"],
                             hashlib.sha256(b"".join(lines[:-1])).hexdigest())
            trace = from_mcp_session_file(path)
            self.assertEqual(len(trace.events), 1)
            doc = json.loads(sarif.render_session_sarif(trace, str(path)))
            self.assertEqual(doc["runs"][0]["artifacts"][0]["hashes"]["sha-256"],
                             trailer["log_sha256"])

    def test_unknown_commit_stays_null(self):
        with mock.patch.dict(os.environ, {"GLASSPORT_COMMIT": "not-a-commit"}):
            self.assertIsNone(tap.build_session_header(
                transport="stdio", mode="wrap")["commit"])

    def test_failed_append_exposes_gap_and_excludes_failed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.jsonl"
            log = tap.open_session_log(path)
            original = log._fh
            writer = mock.Mock(wraps=original)
            attempts = 0

            def flaky(text):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("disk full")
                return original.write(text)

            writer.write.side_effect = flaky
            log._fh = writer
            self.assertIsNone(log.record("c2s", b'{"method":"one"}\n'))
            self.assertIsNotNone(log.record("c2s", b'{"method":"two"}\n'))
            log.write_metrics()
            log.close()
            lines = path.read_bytes().splitlines(keepends=True)
            trailer = json.loads(lines[-1])
            self.assertEqual(trailer["entries_written"], 1)
            self.assertEqual(trailer["seq_range"], [1, 2])
            self.assertEqual(trailer["write_failures"], 1)
            self.assertEqual(trailer["log_sha256"],
                             hashlib.sha256(b"".join(lines[:-1])).hexdigest())


class TestHeaderReaders(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "s.jsonl"
        log = tap.open_session_log(self.path)
        self.assertIsNotNone(log)
        self.assertIsNotNone(log.record(
            "c2s", b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'))
        log.write_metrics()
        log.close()

    def test_adapter_skips_header_and_trailer(self):
        trace = from_mcp_session_file(self.path)
        self.assertEqual([e.metadata.get("seq") for e in trace.events], [1])

    def test_watch_fingerprint_skips_header(self):
        from glassport.watch import watch_paths
        groups = watch_paths([self.path])
        self.assertEqual(sum(map(len, groups.values())), 1)
        self.assertTrue(next(iter(groups.values()))[0]["fingerprint"]["first_ts"])

    def test_tui_ingest_and_picker_skip_header(self):
        from glassport import tui
        self.assertEqual(len(tui._ingest(self.path).events), 1)
        self.assertEqual(tui.list_sessions(self.path.parent)[0].frames, 1)

    def test_console_trace_skips_header(self):
        from glassport.console import _Handler
        handler = _Handler.__new__(_Handler)
        self.assertEqual(len(handler._trace_for(self.path).events), 1)

    def test_prune_analysis_skips_header(self):
        from glassport.prune import _has_detector_error
        self.assertFalse(_has_detector_error(self.path))

    def test_health_uses_trailer_after_header(self):
        from glassport.health import _metrics_of
        self.assertEqual(_metrics_of(self.path)["entries_written"], 1)

    def test_sarif_locates_wire_line_after_header(self):
        self.assertEqual(sarif._seq_to_line(str(self.path)), {1: 2})
        trace = from_mcp_session_file(self.path)
        rendered = json.loads(sarif.render_session_sarif(trace, str(self.path)))
        self.assertEqual(len(rendered["runs"][0]["artifacts"]), 1)

    def test_report_omits_header_and_trailer(self):
        from glassport.report import render_html
        page = render_html(from_mcp_session_file(self.path), self.path.name)
        self.assertNotIn("glassport.header", page)
        self.assertNotIn("glassport.metrics", page)


class TestComputedLimits(unittest.TestCase):
    def test_each_known_gap_has_code_and_ranges(self):
        header = {"type": "glassport.header", "transport": "stdio", "strict": True}
        trailer = {"type": "glassport.metrics", "seq_range": [1, 5],
                   "write_failures": 2}
        journal = [{"kind": "profile", "strict": True,
                    "authorization": {"status": "not_evaluated"}},
                   {"kind": "intent", "wire_seq": 4}]
        entries = [{"seq": 1, "dir": "c2s"}, {"seq": 3, "dir": "s2c"},
                   {"seq": 5, "dir": "c2s"}]
        result = compute_limits(header, trailer, journal, entries)
        by_code = {item["code"]: item for item in result}
        self.assertEqual(set(by_code), {
            "stdio_decoded_text_no_raw_bytes", "seq_gap", "write_failures",
            "missing_wire_entry", "strict_profile", "authorization_not_evaluated",
            "no_signature"})
        self.assertEqual(by_code["seq_gap"]["ranges"], [[2, 2], [4, 4]])
        self.assertEqual(by_code["write_failures"]["count"], 2)
        self.assertEqual(by_code["missing_wire_entry"]["sequences"], [4])

    def test_legacy_default_without_journal_names_missing_claims(self):
        codes = {x["code"] for x in compute_limits(
            None, None, None, [{"seq": 1, "dir": "c2s"}])}
        self.assertEqual(codes, {"header_missing", "unknown_transport_raw_bytes",
                                 "trailer_missing", "no_journal_for_path",
                                 "authorization_not_evaluated", "no_signature"})
        codes = {x["code"] for x in compute_limits(
            {"type": "glassport.header", "transport": "http", "strict": False},
            None, [], [{"seq": 1, "dir": "c2s", "wire_b64": "eA=="}])}
        self.assertIn("default_profile", codes)
        self.assertNotIn("stdio_decoded_text_no_raw_bytes", codes)

    def test_huge_claimed_sequence_range_is_bounded_work(self):
        result = compute_limits({"type": "glassport.header"},
                                {"type": "glassport.metrics", "seq_range": [1, 10**12]}, None,
                                [{"seq": 1}, {"seq": 10**12}])
        self.assertEqual(next(x for x in result if x["code"] == "seq_gap")["ranges"],
                         [[2, 10**12 - 1]])

    def test_missing_trailer(self):
        codes = {x["code"] for x in compute_limits(
            {"type": "glassport.header", "transport": "http"}, None, [], [])}
        self.assertIn("trailer_missing", codes)

    def test_journal_truncated(self):
        codes = {x["code"] for x in compute_limits(
            {"type": "glassport.header"}, {"type": "glassport.metrics"},
            [{"kind": "profile"}, {"kind": "truncated"}], [])}
        self.assertIn("journal_truncated", codes)


class TestStableFindingIds(unittest.TestCase):
    def test_ids_stable_across_reanalysis_and_distinguish_duplicates(self):
        lines = handshake() + [call(6, 3, "web_search", {
            "first": "first@example.org", "second": "second@example.org"})]
        first, second = from_mcp_session(lines), from_mcp_session(lines)
        detectors.annotate(first)
        detectors.annotate(second)
        def emails(trace):
            return [a for a in trace.annotations
                    if a.subcategory == "pii_email_address"]
        one, two = emails(first), emails(second)
        self.assertEqual(len(one), 2)
        self.assertNotEqual(one[0].id, two[0].id)
        self.assertEqual([a.metadata["stable_id"] for a in one],
                         [a.metadata["stable_id"] for a in two])
        self.assertEqual(len({a.metadata["stable_id"] for a in one}), 2)
        self.assertEqual(dj.findings_digest(dj.semantic_findings(one)),
                         dj.findings_digest(dj.semantic_findings(two)))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.jsonl"
            path.write_text("\n".join(lines) + "\n")
            doc = json.loads(sarif.render_session_sarif(first, str(path)))
            results = [r for r in doc["runs"][0]["results"]
                       if r["ruleId"] == "glassport/pii_email_address"]
            self.assertEqual([r["partialFingerprints"]["stable_id"] for r in results],
                             [a.metadata["stable_id"] for a in one])
            self.assertEqual(doc["runs"][0]["artifacts"][0]["hashes"]["sha-256"],
                             hashlib.sha256(path.read_bytes()).hexdigest())


class TestJournalIntegrity(JournalCase):
    def _capture(self):
        lease = self.session()
        obs = self.observed(lease, wire(id=4, method="tools/call",
                                        params={"name": "search", "arguments": {}}))
        epoch = lease.context.epoch
        lease.release()
        self.observer.close()
        self.journal.close()
        return obs, self.journal.path_for(epoch), self.wire_path(epoch)

    def test_wire_binding_and_chain_replay_equivalent_then_wire_tamper_diverges(self):
        obs, journal_path, wire_path = self._capture()
        raw_journal = journal_path.read_bytes().splitlines(keepends=True)
        records = [json.loads(line) for line in raw_journal]
        previous = dj.GENESIS_SHA256
        for raw, record in zip(raw_journal, records):
            self.assertEqual(record["prev_sha256"], previous)
            previous = hashlib.sha256(raw).hexdigest()
        wire_lines = wire_path.read_bytes().splitlines(keepends=True)
        wire_entry = next(raw for raw in wire_lines
                          if json.loads(raw).get("seq") == obs.seq)
        intent = next(r for r in records if r["kind"] == "intent"
                      and r["wire_seq"] == obs.seq)
        self.assertEqual(intent["wire_entry_sha256"],
                         hashlib.sha256(wire_entry).hexdigest())
        self.assertEqual(dr.verify_journal(journal_path, wire_path).status,
                         "equivalent")
        wire_path.write_bytes(b"".join(
            raw.replace(b"search", b"searxh", 1) if raw == wire_entry else raw
            for raw in wire_lines))
        result = dr.verify_journal(journal_path, wire_path)
        self.assertEqual(result.status, "divergent")
        self.assertEqual(result.reasons, ["wire_digest_mismatch"])

    def test_middle_journal_record_deletion_breaks_chain(self):
        _, journal_path, wire_path = self._capture()
        self.assertEqual(dr.verify_journal(journal_path, wire_path).status,
                         "equivalent")
        lines = journal_path.read_bytes().splitlines(keepends=True)
        self.assertGreaterEqual(len(lines), 3)
        journal_path.write_bytes(b"".join(lines[:1] + lines[2:]))
        result = dr.verify_journal(journal_path, wire_path)
        self.assertEqual(result.status, "divergent")
        self.assertEqual(result.reasons, ["journal_chain_mismatch"])

    def test_null_wire_digest_is_incomplete(self):
        _, journal_path, wire_path = self._capture()
        records = [json.loads(line) for line in journal_path.read_text().splitlines()]
        intent = next(r for r in records if r["kind"] == "intent"
                      and type(r.get("wire_seq")) is int)
        intent["wire_entry_sha256"] = None
        intent["wire_digest_reason"] = "http_log_failed"
        rewrite_chained(journal_path, records)
        result = dr.verify_journal(journal_path, wire_path)
        self.assertEqual(result.status, "incomplete")
        self.assertIn("wire_digest_missing", result.reasons)

    def test_evicted_epoch_resumes_existing_hash_chain(self):
        journal = dj.DecisionJournal(
            self.root / "bounded", self.observer,
            limits=dj.JournalLimits(max_epochs=1))
        self.addCleanup(journal.close)
        first = self.session("first")
        first_obs = first.record("c2s", wire(id=4, method="tools/call",
                                              params={"name": "search", "arguments": {}}))
        first_intent = journal.record_intent(first.context.epoch, first_obs)
        journal.record_delivery(first_intent, dj.OUTCOME_SENT,
                                code="upstream_response")
        second = self.session("second")
        second_obs = second.record("c2s", wire(id=4, method="tools/call",
                                                params={"name": "search", "arguments": {}}))
        second_intent = journal.record_intent(second.context.epoch, second_obs)
        journal.record_delivery(second_intent, dj.OUTCOME_SENT,
                                code="upstream_response")
        resumed_obs = first.record("c2s", wire(id=5, method="tools/call",
                                                 params={"name": "search", "arguments": {}}))
        resumed_intent = journal.record_intent(first.context.epoch, resumed_obs)
        journal.record_delivery(resumed_intent, dj.OUTCOME_SENT,
                                code="upstream_response")
        first.release()
        second.release()
        self.observer.close()
        journal.close()
        path = journal.path_for(first.context.epoch)
        records = [json.loads(line) for line in path.read_bytes().splitlines()]
        self.assertEqual(sum(r["kind"] == "profile" for r in records), 2)
        previous = dj.GENESIS_SHA256
        for raw in path.read_bytes().splitlines(keepends=True):
            self.assertEqual(json.loads(raw)["prev_sha256"], previous)
            previous = hashlib.sha256(raw).hexdigest()
        self.assertEqual(dr.verify_journal(path, self.wire_path(first.context.epoch)).status,
                         "equivalent")


class TestLiveHttpGateCapture(GateCase):
    def test_new_gate_capture_has_header_trailer_and_bound_replay(self):
        self.proxy(strict=True)
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call("ghost")
        self.assert_blocked(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(delivery["evidence_level"], "blocked_policy")
        epoch = intent["epoch"]
        self.observer.close()
        wire_path = self.observer.log_dir / f"{epoch}.jsonl"
        lines = wire_path.read_bytes().splitlines(keepends=True)
        header, trailer = json.loads(lines[0]), json.loads(lines[-1])
        self.assertEqual((header["type"], header["transport"], header["mode"],
                          header["strict"]), ("glassport.header", "http", "gate", True))
        self.assertEqual(trailer["type"], "glassport.metrics")
        self.assertEqual(trailer["log_sha256"],
                         hashlib.sha256(b"".join(lines[:-1])).hexdigest())
        trace = from_mcp_session_file(wire_path)
        detectors.annotate(trace)
        self.assertTrue(all("stable_id" in a.metadata for a in trace.annotations))
        replay = dr.verify_journal(self.journal.path_for(epoch), wire_path)
        self.assertEqual(replay.status, "equivalent", replay.as_dict())
