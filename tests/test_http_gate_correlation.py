"""A refused request is not part of the wire the server saw.

The HTTP gate must fold a client request before it can decide whether the
server will ever see it, so until this change a refused ``tools/call`` was
already a pending correlation by the time it was refused: it sat in the
session's pending map, it displaced and quarantined any in-flight real
request that shared its id, and nothing in the wire log said it had been
refused, so a reader of that log (and ``replay-decisions``) folded it as if
it had been forwarded. The reply the gate answered with was not logged at
all, unlike the stdio gate's ``gate: injected`` entry.

These tests pin the corrected contract:

* a ``tools/list`` folded for the gate still establishes a complete surface
  (its ``declaration_generation`` is stamped before the session state folds
  the request; only the pending correlation waits for the forward verdict);
* a refused request never becomes a pending correlation and never displaces
  a real one that shares its id;
* the reply the gate injects is logged, pairs to the refused call in the
  trace, and never pops a real pending request;
* a wire log containing refused requests replays to the same correlation
  state and the same decisions the live gate reached (H3);
* a journal recorded under detector engine ``/1`` is unsupported under
  ``/2``, and the replay result names both the recorded and the analyzing
  engine rather than conflating them.

Most tests drive only interfaces that already existed, so they also run
against the previous gate and fail there on behavior, not on a missing name.
"""
from __future__ import annotations

import contextlib
import io
import json
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from glassport import decision_journal as dj
from glassport import decision_replay as dr
from glassport.adapters.mcp_session import MCPTraceBuilder, from_mcp_session, from_mcp_session_file
from glassport.detectors import annotate
from glassport.interaction_trace import EventKind
from glassport.session import SessionLimits
from pathlib import Path
from tests.test_decision_journal import JournalCase, wire
from tests.test_gate import gated_log_lines
from tests.test_http_gate import GateCase, Upstream


def c2s(seq, frame):
    return {"schema_version": "0.1", "seq": seq, "ts": f"t{seq}", "dir": "c2s",
            "frame": dict(jsonrpc="2.0", **frame), "raw": None}


def s2c(seq, frame, **outer):
    return {"schema_version": "0.1", "seq": seq, "ts": f"t{seq}", "dir": "s2c",
            "frame": dict(jsonrpc="2.0", **frame), "raw": None, **outer}


class CorrelationCase(GateCase):
    def builder(self):
        """The one legacy session's live builder (white-box, by design: the
        claim is about the server's view of the wire, which is this map)."""
        with self.observer._lock:
            contexts = [c for c in self.observer._contexts.values() if c.key is not None]
        self.assertEqual(len(contexts), 1, 'expected exactly one bound session')
        return contexts[0].builder

    def wire_log(self):
        logs = sorted((self.root / 'wire').glob('*.jsonl'))
        self.assertEqual(len(logs), 1, logs)
        return logs[0]

    def wire_entries(self):
        return [json.loads(line) for line in self.wire_log().read_text().splitlines()]

    def subcategories(self, trace):
        return [a.subcategory for a in annotate(trace)]


# ── a forwarded tools/list still establishes a complete surface ──────────

class TestForwardedListingStillDeclares(CorrelationCase):
    """Guard against the naive form of deferral: a tools/list whose
    generation were assigned at commit time, after SessionState.observe(),
    would open a pending listing with no generation and its reply could
    never establish anything. The generation must be on the event before
    the state folds it; only the pending correlation waits."""

    def test_gate_mode_handshake_establishes_the_surface(self):
        self.proxy()
        self.handshake()
        builder = self.builder()
        self.assertEqual(builder.state.surface, frozenset({'search'}))
        self.assertFalse(builder.state.listing_in_flight)
        self.assertEqual(len(builder.pending), 0, 'every request was answered')
        before = self.upstream_calls()
        _, body = self.call('nope', rid=7)
        self.assert_blocked(body, before, rid=7)

    def test_deferred_paginated_listing_completes_only_when_admitted(self):
        b = MCPTraceBuilder(retain_events=False)
        first = b.ingest_frame(c2s(1, {"id": 1, "method": "tools/list"}),
                               defer_correlation=True)
        self.assertIsNotNone(first.metadata.get("declaration_generation"))
        self.assertTrue(b.state.listing_in_flight)
        self.assertEqual(len(b.pending), 0, 'not yet admitted')
        self.assertTrue(b.commit_correlation())
        self.assertEqual(len(b.pending), 1)
        b.feed(s2c(2, {"id": 1, "result": {"tools": [{"name": "a"}], "nextCursor": "p2"}}))
        self.assertIsNone(b.state.surface, 'an intermediate page proves nothing yet')
        b.ingest_frame(c2s(3, {"id": 2, "method": "tools/list", "params": {"cursor": "p2"}}),
                       defer_correlation=True)
        b.commit_correlation()
        b.feed(s2c(4, {"id": 2, "result": {"tools": [{"name": "b"}]}}))
        self.assertEqual(b.state.surface, frozenset({"a", "b"}))

        # The same listing, refused instead of admitted: its reply is nobody's.
        b = MCPTraceBuilder(retain_events=False)
        b.ingest_frame(c2s(1, {"id": 1, "method": "tools/list"}), defer_correlation=True)
        self.assertTrue(b.discard_correlation())
        self.assertEqual(len(b.pending), 0)
        reply = b.feed(s2c(2, {"id": 1, "result": {"tools": [{"name": "a"}]}}))
        self.assertTrue(reply.metadata["orphaned"])
        self.assertIsNone(b.state.surface)
        self.assertFalse(b.commit_correlation(), 'nothing left to commit')


# ── a refused request never becomes a pending correlation ────────────────

class TestRefusedRequestIsNotCorrelated(CorrelationCase):
    def test_refused_call_never_enters_pending_and_a_reused_id_correlates(self):
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope', rid=7)
        self.assert_blocked(body, before, rid=7)
        builder = self.builder()
        self.assertEqual([k for k in builder.pending if k[-1] == 7], [],
                         'a refused request must not be a pending correlation')
        self.assertEqual(builder._quarantined['c2s'], set())

        # A later real request may reuse the id (the server never saw 7):
        # it correlates cleanly, its analysis is not limited, and its reply
        # is a tool result, not an orphan.
        since = self.intent_watermark(self._handshake_request_count + 1)
        before = self.upstream_calls()
        _, body = self.call('search', rid=7)
        self.assert_forwarded(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent['action'], 'allow', intent)
        self.assertEqual([f['subcategory'] for f in intent['findings']], [])
        self.assertEqual(delivery['outcome'], 'sent')
        trace = from_mcp_session_file(self.wire_log())
        results = [e for e in trace.events if e.kind == EventKind.TOOL_RESULT
                   and e.metadata.get('jsonrpc_id') == 7]
        # Two replies carried id 7: the one the gate injected for the refused
        # call (marked, paired to it) and the server's real one (paired to
        # the real call). Neither is an orphan and neither limited analysis.
        self.assertEqual([(e.metadata.get('tool_name'), 'gate' in e.metadata) for e in results],
                         [('nope', True), ('search', False)])
        self.assertNotIn('orphaned_response', self.subcategories(trace))
        self.assertNotIn('analysis_limit', self.subcategories(trace))

    def test_refused_request_and_injected_reply_are_marked_in_the_wire_log(self):
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope', rid=7)
        self.assert_blocked(body, before, rid=7)
        entries = self.wire_entries()
        refused = [e for e in entries if e['dir'] == 'c2s'
                   and (e.get('frame') or {}).get('id') == 7]
        self.assertEqual(len(refused), 1, refused)
        self.assertIs(refused[0]['http_observation'].get('admitted'), False)
        self.assertNotIn('gate', refused[0], 'the decision record is the journal')
        injected = [e for e in entries if isinstance(e.get('gate'), dict)]
        self.assertEqual([e['gate'] for e in injected], [{'action': 'injected', 'tool': 'nope'}])
        self.assertEqual(injected[0]['dir'], 's2c')
        self.assertEqual(injected[0]['frame']['id'], 7)
        self.assertEqual(injected[0]['frame']['error']['data']['glassport'], 'http_gate_blocked')
        self.assertGreater(injected[0]['seq'], refused[0]['seq'])
        # A reader shows the same record the stdio gate's log shows.
        trace = from_mcp_session_file(self.wire_log())
        found = self.subcategories(trace)
        self.assertIn('fabricated_tool_call', found)
        self.assertIn('gate_injected_response', found)
        self.assertNotIn('orphaned_response', found)
        reply = next(e for e in trace.events if e.metadata.get('gate'))
        call = next(e for e in trace.events if e.kind == EventKind.TOOL_CALL
                    and e.metadata.get('jsonrpc_id') == 7)
        self.assertEqual(reply.parent_event_id, call.id, 'the injected reply pairs to the refused call')

    def test_an_unpersisted_refusal_forwards_and_still_correlates(self):
        """Doctrine kept from the eager fold: a block is enforced only on
        persisted evidence. When the wire write fails, the admit-time verdict
        is refuse but the final one is forward, and the observer must have
        committed the correlation so the forwarded request's reply pairs."""
        from unittest import mock
        from glassport import tap
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        with mock.patch.object(tap.SessionLog, 'write_entry', return_value=False):
            _, body = self.call('nope', rid=7)
            self.assert_forwarded(body, before)
            intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent['diagnostic'], 'http_log_failed')
        self.assertTrue(intent['candidate_block'])
        self.assertFalse(intent['enforce'])
        self.assertEqual(delivery['outcome'], 'sent')
        builder = self.builder()
        self.assertEqual(len(builder.pending), 0, 'the forwarded call correlated and was answered')
        self.assertEqual(builder._quarantined['c2s'], set())

    def test_observe_mode_marks_nothing_and_injects_nothing(self):
        self.proxy(mode=dj.MODE_OBSERVE)
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope', rid=7)
        self.assert_forwarded(body, before)
        entries = self.wire_entries()
        self.assertFalse(any('gate' in e for e in entries))
        self.assertFalse(any(e.get('http_observation', {}).get('admitted') is False
                             for e in entries))
        self.assertEqual([k[-1] for k in self.builder().pending], [])


# ── the injected reply never pops a real request ─────────────────────────

class SlowUpstream(Upstream):
    """Delays the reply to one named tool so a refusal can race it."""
    slow_tool = None
    delay = 0.6

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0) or 0))
        try:
            frame = json.loads(raw)
        except ValueError:
            frame = {}
        if not isinstance(frame, dict):
            frame = {}
        with Upstream.lock:
            Upstream.calls.append({'method': frame.get('method'),
                                   'id': frame.get('id'), 'raw': raw})
        if (frame.get('method') == 'tools/call'
                and (frame.get('params') or {}).get('name') == type(self).slow_tool):
            time.sleep(type(self).delay)
        if 'id' not in frame:
            self.send_response(202)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        body = json.dumps(self._result(frame)).encode()
        self.send_response(200)
        if frame.get('method') == 'initialize':
            self.send_header('Mcp-Session-Id', 'sess-1')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestInjectedReplyPopsNoRealRequest(CorrelationCase):
    def upstream(self):
        SlowUpstream.slow_tool = None
        srv = ThreadingHTTPServer(('127.0.0.1', 0), SlowUpstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_address[1]}/mcp'

    def test_builder_never_pops_a_real_request_for_an_injected_reply(self):
        b = MCPTraceBuilder()
        b.feed(c2s(1, {"id": 7, "method": "tools/call",
                       "params": {"name": "search", "arguments": {}}}))
        injected = b.feed(s2c(2, {"id": 7, "error": {"code": -32000, "message": "blocked",
                                                     "data": {"glassport": "http_gate_blocked"}}},
                              gate={"action": "injected", "tool": "nope"}))
        self.assertEqual(len(b.pending), 1, 'the real request is still awaiting its reply')
        self.assertFalse(injected.metadata.get('orphaned'), 'glassport\'s own reply is not an orphan')
        self.assertEqual(injected.metadata['gate']['action'], 'injected')
        real = b.feed(s2c(3, {"id": 7, "result": {"content": [], "isError": False}}))
        self.assertEqual(real.kind, EventKind.TOOL_RESULT)
        self.assertEqual(real.metadata['tool_name'], 'search')
        self.assertEqual(len(b.pending), 0)

    def test_live_refusal_racing_a_real_call_with_the_same_id(self):
        self.proxy()
        self.handshake()
        SlowUpstream.slow_tool = 'search'
        outcome = {}

        def slow_call():
            try:
                outcome['body'] = self.call('search', rid=7)[1]
            except Exception as exc:   # pragma: no cover - surfaced by the assertion below
                outcome['error'] = exc
        thread = threading.Thread(target=slow_call)
        thread.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(
                c['method'] == 'tools/call' for c in self.upstream_calls()):
            time.sleep(0.01)
        before = self.upstream_calls()
        self.assertTrue(any(c['method'] == 'tools/call' for c in before), 'real call never left')
        _, body = self.call('nope', rid=7)
        thread.join(10)
        self.assertIn('body', outcome, outcome.get('error'))
        self.quiesce()
        frame = json.loads(body)
        self.assertEqual(frame['error']['data']['glassport'], 'http_gate_blocked')
        self.assertEqual(frame['id'], 7)
        self.assertEqual(len(self.upstream_calls()), len(before), 'the refusal reached upstream')
        self.assertIn('result', json.loads(outcome['body']))

        trace = from_mcp_session_file(self.wire_log())
        results = [e for e in trace.events if e.kind == EventKind.TOOL_RESULT
                   and e.metadata.get('jsonrpc_id') == 7]
        self.assertEqual(sorted(e.metadata.get('tool_name') for e in results), ['nope', 'search'],
                         'the real reply pairs to the real call, the injected one to the refused call')
        anns = annotate(trace)
        found = [a.subcategory for a in anns]
        self.assertNotIn('orphaned_response', found)
        # The refused call reused an in-flight id, so it honestly carries the
        # collision stamp (stamps precede the verdict by design) — and that
        # stamp waived nothing: it was still blocked. The stamp belongs to the
        # refused call alone; the admitted call and its reply are clean.
        refused = next(e for e in trace.events if e.kind == EventKind.TOOL_CALL
                       and e.metadata.get('jsonrpc_id') == 7
                       and e.metadata.get('http_observation', {}) == {}
                       and e.parts[0].content['name'] == 'nope')
        limits = [a for a in anns if a.subcategory == 'analysis_limit']
        self.assertEqual([(a.event_id, a.metadata.get('reason')) for a in limits],
                         [(refused.id, 'request_correlation')])
        builder = self.builder()
        self.assertEqual(len(builder.pending), 0)
        self.assertEqual(builder._quarantined['c2s'], set(),
                         'the refusal quarantined nothing: the server never saw it')


# ── an ambiguous id on the refused request itself waives nothing ──────────

class TestCollidingIdDoesNotWaiveTheBlock(unittest.TestCase):
    """The exclusion a block rests on is the declared surface; whether this
    request's own reply could ever be correlated has no bearing on it. Until
    this change a client could forward one undeclared call per session by
    reusing the id of a request still in flight: the collision stamped
    `correlation_limited`, the engine reported `analysis_limit`, and that
    waived enforcement. Saturation and every other limit stay conservative."""

    def verdict(self, reason):
        from glassport.detectors import AnnotationKind, HallucinationCategory, _ann
        from glassport.interaction_trace import Event
        from glassport.http_sessions import Observation
        event = Event.tool_call('agent', 'nope', {}, metadata={'seq': 1})
        fabricated = _ann(event, AnnotationKind.HALLUCINATION, 'fabricated_tool_call',
                          'outside', severity=3, category=HallucinationCategory.TOOL_USE,
                          no_declaration_seen=False, tool='nope')
        limit = _ann(event, AnnotationKind.ANOMALY, 'analysis_limit', 'limit',
                     severity=1, reason=reason, limits={})
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            journal = dj.DecisionJournal(Path(tmp), observer=None, mode=dj.MODE_GATE)
            try:
                return journal.evaluate(Observation('e', 1, event, (fabricated, limit)))
            finally:
                journal.close()

    def test_request_correlation_limit_does_not_waive_a_proved_exclusion(self):
        self.assertTrue(self.verdict('request_correlation'))

    def test_every_other_limit_still_waives(self):
        for reason in ('request_correlation_saturated', 'tool_declaration', 'session_metadata'):
            with self.subTest(reason=reason):
                self.assertFalse(self.verdict(reason))


# ── H3: a log with refusals replays to the live correlation state ─────────

class TestReplayWithRefusals(CorrelationCase):
    def test_refusals_and_reused_ids_replay_as_equivalent(self):
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        self.assert_blocked(self.call('nope', rid=7)[1], before, rid=7)
        before = self.upstream_calls()
        self.assert_forwarded(self.call('search', rid=7)[1], before)
        before = self.upstream_calls()
        self.assert_blocked(self.call('nope', rid=8)[1], before, rid=8)
        before = self.upstream_calls()
        self.assert_forwarded(self.call('search', rid=9)[1], before)
        self.records(settle=self._handshake_request_count + 4)

        journals = sorted((self.root / 'decisions').glob('*.jsonl'))
        self.assertEqual(len(journals), 1)
        result = dr.verify_journal(journals[0], self.wire_log())
        self.assertEqual(result.status, 'equivalent', result.as_dict())
        self.assertEqual(result.mismatched, [])
        self.assertEqual(result.recorded_engine, dj.DETECTOR_ENGINE_VERSION)
        self.assertEqual(result.analyzer_engine, dj.DETECTOR_ENGINE_VERSION)
        enforced = [r for r in self._read('intent') if r['enforce']]
        self.assertEqual(len(enforced), 2)

        live = self.builder()
        replay = MCPTraceBuilder(retain_events=False)
        for entry in self.wire_entries():
            replay.ingest_frame(entry)
        for b in (live, replay):
            self.assertEqual(dict(b.pending), {})
            self.assertEqual(b._quarantined, {'c2s': set(), 's2c': set()})
            self.assertEqual(dict(b._blocked), {}, 'every injected reply consumed its memo')
            self.assertEqual(b._correlation_saturated, set())
            self.assertEqual(b.state.surface, frozenset({'search'}))
        self.assertEqual(replay.correlation_evictions, live.correlation_evictions)


# ── fold-version provenance ──────────────────────────────────────────────

class TestFoldProvenance(JournalCase):
    def test_a_journal_recorded_under_engine_1_is_unsupported_under_2(self):
        lease = self.session()
        self.observed(lease, wire(id=4, method='tools/call',
                                  params={'name': 'nope', 'arguments': {}}))
        epoch = lease.context.epoch
        self.assertEqual(dj.DETECTOR_ENGINE_VERSION, 'glassport.detectors/2')
        self.assertEqual(self.verify(lease).status, 'equivalent')

        # The same journal, as a /1 writer would have recorded it.
        legacy = self.root / 'legacy.jsonl'
        lines = []
        for record in self.journal_lines(epoch):
            if record['kind'] == 'profile':
                record['detector_engine'] = 'glassport.detectors/1'
            lines.append(json.dumps(record))
        legacy.write_text('\n'.join(lines) + '\n')
        result = dr.verify_journal(legacy, self.wire_path(epoch))
        self.assertEqual(result.status, 'unsupported')
        self.assertEqual(result.reasons, ['profile_mismatch_detector_engine'])
        self.assertEqual(result.recorded_engine, 'glassport.detectors/1')
        self.assertEqual(result.analyzer_engine, 'glassport.detectors/2')
        as_dict = result.as_dict()
        self.assertEqual((as_dict['recorded_engine'], as_dict['analyzer_engine']),
                         ('glassport.detectors/1', 'glassport.detectors/2'))

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = dr.main([str(legacy), '--wire', str(self.wire_path(epoch))])
        self.assertEqual(code, 1)
        self.assertIn('recorded detector engine: glassport.detectors/1; '
                      'this analyzer: glassport.detectors/2', out.getvalue())
        lease.release()

    def test_a_profile_without_an_engine_names_none_not_the_analyzer(self):
        lease = self.session()
        self.observed(lease, wire(id=4, method='ping'))
        epoch = lease.context.epoch
        broken = self.root / 'no-engine.jsonl'
        lines = []
        for record in self.journal_lines(epoch):
            if record['kind'] == 'profile':
                del record['detector_engine']
            lines.append(json.dumps(record))
        broken.write_text('\n'.join(lines) + '\n')
        result = dr.verify_journal(broken, self.wire_path(epoch))
        self.assertEqual(result.status, 'unsupported')
        self.assertIsNone(result.recorded_engine)
        self.assertEqual(result.analyzer_engine, dj.DETECTOR_ENGINE_VERSION)
        lease.release()

    def test_a_fold_fault_under_the_gate_still_writes_the_entry(self):
        lease = self.session()
        context = lease.context
        original = context.builder.feed

        def faulty(entry, **kw):
            if entry.get('dir') == 'c2s':
                raise RuntimeError('analysis fault')
            return original(entry, **kw)
        context.builder.feed = faulty
        asked = []
        payload = wire(id=9, method='tools/call', params={'name': 'nope', 'arguments': {}})
        observation = lease.record('c2s', payload, admit=lambda o: asked.append(o) or True)
        context.builder.feed = original
        self.assertEqual(observation.diagnostic, 'http_analysis_failed')
        self.assertEqual(asked, [], 'no verdict is asked for a fold that faulted')
        entries = [json.loads(l) for l in self.wire_path(context.epoch).read_text().splitlines()]
        kept = [e for e in entries if (e.get('frame') or {}).get('id') == 9]
        self.assertEqual(len(kept), 1, 'evidence first: the faulted entry is on disk')
        self.assertNotIn('admitted', kept[0]['http_observation'])
        self.assertIsNone(context.builder._reservation)
        lease.release()


# ── the stdio gate's log keeps its shape, and gains the same freedom ─────

class TestStdioLogParity(unittest.TestCase):
    def test_injected_reply_pairs_to_the_refused_call_and_frees_its_id(self):
        later = [json.dumps(c2s(8, {"id": 3, "method": "tools/call",
                                    "params": {"name": "web_search", "arguments": {}}})),
                 json.dumps(s2c(9, {"id": 3, "result": {"content": [], "isError": False}}))]
        trace = from_mcp_session(gated_log_lines() + later)
        blocked = next(e for e in trace.events if e.kind == EventKind.TOOL_CALL
                       and e.metadata.get('gate', {}).get('action') == 'blocked')
        results = [e for e in trace.events if e.kind == EventKind.TOOL_RESULT]
        self.assertEqual([e.metadata.get('tool_name') for e in results], ['shadow_tool', 'web_search'])
        self.assertEqual(results[0].parent_event_id, blocked.id)
        self.assertEqual(results[0].metadata['gate']['action'], 'injected')
        found = [a.subcategory for a in annotate(trace)]
        self.assertIn('gate_blocked', found)
        self.assertIn('gate_injected_response', found)
        self.assertNotIn('orphaned_response', found)
        self.assertNotIn('analysis_limit', found)

    def test_a_refused_request_never_displaces_a_real_one_in_a_saved_log(self):
        lines = [json.dumps(c2s(1, {"id": 3, "method": "tools/call",
                                    "params": {"name": "web_search", "arguments": {}}})),
                 json.dumps({**c2s(2, {"id": 3, "method": "tools/call",
                                       "params": {"name": "shadow", "arguments": {}}}),
                             "gate": {"action": "blocked", "tool": "shadow"}}),
                 json.dumps(s2c(3, {"id": 3, "result": {"content": [], "isError": False}}))]
        trace = from_mcp_session(lines)
        result = next(e for e in trace.events if e.kind == EventKind.TOOL_RESULT)
        self.assertEqual(result.metadata['tool_name'], 'web_search')
        self.assertNotIn('orphaned_response', [a.subcategory for a in annotate(trace)])

    def test_bounded_blocked_memo_is_cleared_on_loss_and_exchange_end(self):
        b = MCPTraceBuilder(limits=SessionLimits(max_pending=2))
        for i in range(5):
            b.feed({**c2s(i, {"id": i, "method": "tools/call",
                              "params": {"name": "x", "arguments": {}}}),
                    "gate": {"action": "blocked", "tool": "x"}})
        self.assertEqual(len(b._blocked), 2)
        b.feed({**c2s(9, {"id": 9, "method": "ping"}), "http_observation": {"loss": "http_reset"}})
        self.assertEqual(len(b._blocked), 0)
        b.feed({**c2s(10, {"id": 1, "method": "tools/call", "params": {"name": "x"}}),
                "http_observation": {"exchange": "ex1", "admitted": False}})
        self.assertEqual(list(b._blocked), [("ex1", int, 1)])
        b.feed({"dir": "s2c", "frame": None, "raw": "",
                "http_observation": {"exchange": "ex1", "exchange_end": True, "skip": True}})
        self.assertEqual(len(b._blocked), 0)


if __name__ == '__main__':
    unittest.main()
