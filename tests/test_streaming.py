"""
Tests for adapters/streaming.py — the incremental (opt-in) ingest path.

The invariant that matters: after ANY sequence of polls, the streaming
trace and annotations are exactly what the batch path would produce for
the same bytes on disk. Everything else (partial lines, rotation,
tail-only) is defined relative to that.
Pure stdlib, run with:  python3 -m unittest tests.test_streaming
"""
import json
import re
import time
import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path

from glassport import detectors
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.adapters.streaming import StreamingSession
from tests.test_detectors import L, handshake, call, result


def batch(path):
    trace = from_mcp_session_file(path)
    detectors.annotate(trace)
    return trace


def canon_events(trace):
    """Events reduced to id-free comparable form (uuids differ per run)."""
    idx = {e.id: i for i, e in enumerate(trace.events)}
    actor = {a.id: a.name for a in trace.actors}
    out = []
    for e in trace.events:
        parts = json.dumps([(p.kind.value, p.content) for p in e.parts],
                           sort_keys=True, default=str)
        # generated per-run part ids (tu_<hex>) are not semantic
        parts = re.sub(r"tu_[0-9a-f]+", "tu_X", parts)
        out.append((
            e.kind.value, e.timestamp, actor.get(e.actor_id),
            idx.get(e.parent_event_id, -1),
            parts,
            json.dumps({k: v for k, v in e.metadata.items()},
                       sort_keys=True, default=str),
        ))
    return out


def canon_annotations(trace):
    idx = {e.id: i for i, e in enumerate(trace.events)}
    return sorted((a.subcategory, a.severity, idx.get(a.event_id, -1))
                  for a in trace.annotations)


def canon_actors(trace):
    return sorted(
        (a.name, json.dumps(a.metadata, sort_keys=True, default=str))
        for a in trace.actors)


class StreamingCase(unittest.TestCase):
    def assert_equivalent(self, session: StreamingSession, path: Path):
        ref = batch(path)
        self.assertEqual(canon_events(session.trace), canon_events(ref))
        self.assertEqual(canon_annotations(session.trace),
                         canon_annotations(ref))
        self.assertEqual(canon_actors(session.trace), canon_actors(ref))
        self.assertEqual(session.trace.final_state, ref.final_state)


HOSTILE = handshake() + [
    call(6, 3, "web_search", {"q": "http://evil.example.com",
                              "k": "sk-" + "A" * 40}),
    result(7, 3),
    call(8, 4, "shadow_fetch", {"u": "http://x"}),
    L(9, "s2c", {"jsonrpc": "2.0", "id": 4,
                 "error": {"code": -32000, "message": "nope"}}),
    L(10, "s2c", {"jsonrpc": "2.0", "id": 99,
                  "method": "sampling/createMessage", "params": {}}),
    "this is not json at all",
]


class TestEquivalence(StreamingCase):
    def test_single_poll_of_full_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(HOSTILE) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            self.assertTrue(s.poll())
            self.assert_equivalent(s, p)

    def test_line_by_line_polls_match_batch_at_every_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("", encoding="utf-8")
            s = StreamingSession(p)
            with open(p, "a", encoding="utf-8") as fh:
                for line in HOSTILE:
                    fh.write(line + "\n")
                    fh.flush()
                    s.poll()
                    self.assert_equivalent(s, p)

    def test_trace_identity_stable_and_events_append_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake()) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            s.poll()
            t0 = s.trace
            n0 = len(s.trace.events)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(call(6, 3, "web_search", {"q": "x"}) + "\n")
            s.poll()
            self.assertIs(s.trace, t0)              # same object, updated
            self.assertGreater(len(s.trace.events), n0)

    def test_unknown_surface_never_fabricates_across_polls(self):
        # Issue #76: future declarations cannot prove earlier exclusion.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            pre = [call(1, 1, "web_search", {"q": "x"}), result(2, 1)]
            p.write_text("\n".join(pre) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            s.poll()
            subs = [a.subcategory for a in s.trace.annotations]
            self.assertNotIn("fabricated_tool_call", subs)
            with open(p, "a", encoding="utf-8") as fh:
                fh.write("\n".join(handshake(start_seq=3)) + "\n")
            s.poll()
            subs = [a.subcategory for a in s.trace.annotations]
            self.assertNotIn("fabricated_tool_call", subs)
            self.assert_equivalent(s, p)

    def test_gate_markers_survive_streaming(self):
        entry = json.loads(call(6, 3, "shadow", {}))
        entry["gate"] = {"action": "blocked", "tool": "shadow"}
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake() + [json.dumps(entry)]) + "\n",
                         encoding="utf-8")
            s = StreamingSession(p)
            s.poll()
            gated = [e for e in s.trace.events
                     if isinstance(e.metadata.get("gate"), dict)]
            self.assertEqual(len(gated), 1)
            self.assert_equivalent(s, p)


class TestFileEdgeCases(StreamingCase):
    def test_growing_file_enters_bounded_tail_and_matches_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake()) + "\n")
            cap = p.stat().st_size + 100
            session = StreamingSession(p, tail_cap_bytes=cap)
            session.poll()
            for i in range(20):
                with p.open("a") as fh:
                    fh.write(call(i + 10, i + 10, "web_search", {"query": "x" * 100}) + "\n")
                session.poll()
                ref = from_mcp_session_file(p, tail_cap_bytes=cap)
                detectors.annotate(ref)
                self.assertEqual(canon_events(session.trace), canon_events(ref))
                self.assertEqual(canon_annotations(session.trace), canon_annotations(ref))
                self.assertLessEqual(len(session._buf), cap)
            self.assertTrue(session.tail_only)

    def test_append_does_not_rescan_prior_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake()) + "\n")
            session = StreamingSession(p)
            session.poll()
            with p.open("a") as fh:
                fh.write(call(6, 3, "web_search", {"query": "x"}) + "\n")
            with patch.object(detectors, "annotate", side_effect=AssertionError("batch rescan")):
                self.assertTrue(session.poll())
            self.assert_equivalent(session, p)

    def test_unterminated_input_stays_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            session = StreamingSession(p, tail_cap_bytes=128)
            for _ in range(5):
                with p.open("ab") as fh:
                    fh.write(b"x" * 100)
                session.poll()
                self.assertLessEqual(len(session._buf), 128)
            self.assertTrue(session.trace.metadata["tail_only"])

    def test_batch_extension_registry_stays_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake()) + "\n")
            session = StreamingSession(p)
            session.poll()
            with patch.object(detectors, "DETECTORS", [detectors.context_violations]):
                self.assertTrue(session.poll())
                self.assert_equivalent(session, p)
            self.assertTrue(session.poll())
            self.assert_equivalent(session, p)

    def test_invalid_tail_cap_rejected(self):
        with self.assertRaises(ValueError):
            StreamingSession("unused", tail_cap_bytes=0)

    def test_partial_line_is_buffered_not_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            whole = handshake()
            p.write_text("\n".join(whole[:-1]) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            s.poll()
            n = len(s.trace.events)
            half = whole[-1][: len(whole[-1]) // 2]
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(half)                      # no newline
            s.poll()
            self.assertEqual(len(s.trace.events), n)   # nothing half-eaten
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(whole[-1][len(half):] + "\n")
            s.poll()
            self.assertEqual(len(s.trace.events), n + 1)
            self.assert_equivalent(s, p)

    def test_poll_false_when_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake()) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            self.assertTrue(s.poll())
            self.assertFalse(s.poll())

    def test_vanished_file_poll_false_trace_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(handshake()) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            s.poll()
            n = len(s.trace.events)
            p.unlink()
            self.assertFalse(s.poll())
            self.assertEqual(len(s.trace.events), n)

    def test_truncated_file_rebuilds_from_scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            p.write_text("\n".join(HOSTILE) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            s.poll()
            p.write_text("\n".join(handshake()) + "\n", encoding="utf-8")
            self.assertTrue(s.poll())
            self.assert_equivalent(s, p)

    def test_tail_only_mode_over_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            lines = handshake() + [
                call(6 + i, 3 + i, "web_search", {"q": "x" * 50})
                for i in range(50)]
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            total = len(batch(p).events)
            s = StreamingSession(p, tail_cap_bytes=1000)
            s.poll()
            self.assertTrue(s.tail_only)
            self.assertTrue(s.trace.metadata.get("tail_only"))
            self.assertLess(len(s.trace.events), total)
            # tail parse starts at a line boundary: no unparsed debris
            self.assertFalse(any(e.metadata.get("unparsed")
                                 for e in s.trace.events))


class TestPerf(unittest.TestCase):
    def test_incremental_poll_stays_fast_on_10k_frames(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.jsonl"
            lines = handshake()
            for i in range(5000):
                lines.append(call(6 + 2 * i, 3 + i, "web_search",
                                  {"query": f"query {i}"}))
                lines.append(result(7 + 2 * i, 3 + i))
            p.write_text("\n".join(lines) + "\n", encoding="utf-8")
            s = StreamingSession(p)
            t0 = time.monotonic()
            s.poll()
            initial = time.monotonic() - t0
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(call(99991, 99991, "web_search", {"query": "z"}) + "\n")
            t0 = time.monotonic()
            s.poll()
            incremental = time.monotonic() - t0
            print(f"\n[streaming perf] initial={initial * 1000:.0f}ms "
                  f"incremental={incremental * 1000:.0f}ms "
                  f"({len(s.trace.events)} events)")
            # plan target: <100ms per new frame on 10k. Observed incremental
            # time sits right at ~1.0-1.1s under the coverage job's line-trace
            # instrumentation overhead (flaked 4x across PRs #66/#67/#68 at
            # 1.03-1.07s) - 1.5s keeps real margin under that overhead without
            # masking an actual regression. The printed number is the honest
            # measurement.
            self.assertLess(incremental, 1.5)


if __name__ == "__main__":
    unittest.main()
