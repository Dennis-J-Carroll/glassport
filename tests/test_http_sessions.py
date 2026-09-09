"""Adversarial HTTP identity and replay contracts; no sockets."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from glassport.http_sessions import HTTPObserver, HTTPRegistryLimits
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.incremental import replay
from glassport.session import SessionLimits
from tests.test_incremental_detectors import semantic_findings


def wire(**kw):
    return json.dumps(dict(jsonrpc='2.0', **kw)).encode()


class TestHTTPSessions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.observer = HTTPObserver(Path(self.tmp.name))
        self.addCleanup(self.observer.close)

    def begin(self, token=None, **kw):
        headers = [('Mcp-Session-Id', token)] if token else []
        return self.observer.begin('POST', headers, **kw)

    def initialize(self, token, headers=()):
        lease = self.observer.begin('POST', headers)
        lease.record('c2s', wire(id=1, method='initialize', params={}))
        lease.response(200, [('Mcp-Session-Id', token)])
        lease.record('s2c', wire(id=1, result={'protocolVersion': '2025-11-25',
                     'capabilities': {}, 'serverInfo': {'name': 'test', 'version': '1'}}))
        lease.release()
        return lease.context

    def listing(self, lease, name):
        lease.record('c2s', wire(id=2, method='tools/list'))
        lease.record('s2c', wire(id=2, result={'tools': [{'name': name}]}))

    def test_interleaved_equal_rpc_ids_remain_isolated(self):
        self.initialize('alpha'); self.initialize('beta')
        a, b = self.begin('alpha'), self.begin('beta')
        self.listing(a, 'a'); self.listing(b, 'b')
        self.assertEqual(a.context.builder.state.surface, {'a'})
        self.assertEqual(b.context.builder.state.surface, {'b'})
        self.assertFalse(any(x.subcategory == 'fabricated_tool_call' for x in
            a.record('c2s', wire(id=3, method='tools/call', params={'name':'a'})).annotations))
        self.assertTrue(any(x.subcategory == 'fabricated_tool_call' for x in
            b.record('c2s', wire(id=3, method='tools/call', params={'name':'a'})).annotations))
        a.release(); b.release()

    def test_unknown_missing_malformed_and_credentials_never_reuse(self):
        known = self.initialize('alpha')
        for headers in ([], [('Mcp-Session-Id', 'unknown')],
                        [('Mcp-Session-Id', 'alpha'), ('Mcp-Session-Id', 'alpha')],
                        [('Mcp-Session-Id', 'alpha,beta')],
                        [('Mcp-Session-Id', 'alpha'), ('Authorization', 'other')]):
            lease = self.observer.begin('GET', headers)
            self.assertIsNot(lease.context, known)
            self.assertIsNone(lease.context.builder.state.surface)
            lease.release()

    def test_collision_invalidates_both_and_stale_lease(self):
        self.initialize('alpha')
        old = self.begin('alpha'); self.listing(old, 'old')
        other = self.initialize('alpha')
        self.assertTrue(old.context.retired)
        old.record('s2c', wire(id=2, result={'tools': []}))
        self.assertIsNone(old.context.builder.state.surface)
        fresh = self.begin('alpha')
        self.assertIsNot(fresh.context, old.context)
        self.assertIsNot(fresh.context, other)
        old.release(); fresh.release()

    def test_capacity_counts_active_retired_and_release_idempotent(self):
        obs = HTTPObserver(Path(self.tmp.name)/'small', limits=HTTPRegistryLimits(max_sessions=1))
        self.addCleanup(obs.close)
        a = obs.begin('POST', [])
        obs.reset(a)
        b = obs.begin('GET', [])
        self.assertIsNone(b.context)
        self.assertEqual(b.diagnostic, 'http_capacity')
        a.release(); a.release()
        c = obs.begin('GET', [])
        self.assertIsNotNone(c.context)
        c.release(); b.release()

    def test_sse_duplicate_collision_and_replay(self):
        self.initialize('alpha')
        a = self.begin('alpha')
        a.record('c2s', wire(id=2, method='tools/list'))
        payload = wire(id=2, result={'tools': []})
        first = a.record('s2c', payload, event_id='e1')
        duplicate = a.record('s2c', payload, event_id='e1')
        self.assertIsNotNone(first.event)
        self.assertIsNone(duplicate.event)
        a.record('s2c', wire(id=2, result={'tools':[{'name':'new'}]}), event_id='e1')
        self.assertIsNone(a.context.builder.state.surface)
        result = a.record('c2s', wire(id=3, method='tools/call', params={'name':'new'}))
        self.assertFalse(any(x.subcategory == 'fabricated_tool_call' for x in result.annotations))
        path = a.context.log.path
        a.release()
        trace = from_mcp_session_file(path)
        self.assertFalse(any(x.subcategory == 'fabricated_tool_call' for x in replay(trace)))
        entries = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(sum(e.get('http_observation', {}).get('skip') is True for e in entries), 1)

    def test_only_successful_correlated_initialize_binds(self):
        for response in (wire(id=2, result={}), wire(id=1, result={}),
                         wire(id=1, error={'code':-1,'message':'bad'})):
            a = self.begin()
            a.record('c2s', wire(id=1, method='initialize', params={}))
            a.response(200, [('Mcp-Session-Id', 'alpha')])
            a.record('s2c', response)
            a.release()
            b = self.begin('alpha')
            self.assertIsNot(b.context, a.context)
            b.release()

    def test_loss_callbacks_run_outside_context_lock(self):
        context = self.initialize('alpha')
        acquired = []
        def callback(observation):
            def check():
                ok = context.lock.acquire(blocking=False)
                acquired.append(ok)
                if ok:
                    context.lock.release()
            t = threading.Thread(target=check)
            t.start(); t.join(1)
        self.observer.on_observation = callback
        lease = self.begin('alpha')
        lease.record('s2c', b'{}', event_id='bad\x00id')
        lease.release()
        self.assertTrue(acquired)
        self.assertTrue(all(acquired))

    def test_sse_history_overflow_cannot_reinterpret_old_reply(self):
        self.observer.limits = HTTPRegistryLimits(max_sse_ids=1)
        context = self.initialize('alpha')
        a = self.begin('alpha')
        a.record('c2s', wire(id=2, method='tools/list'))
        a.record('s2c', wire(id=2, result={'tools': []}), event_id='one')
        a.record('s2c', wire(method='notifications/x'), event_id='two')
        a.record('c2s', wire(id=2, method='tools/list'))
        a.record('s2c', wire(id=2, result={'tools': []}), event_id='one')
        self.assertIsNone(context.builder.state.surface)
        self.assertLessEqual(len(context.sse_ids), 1)
        a.release()

    def test_loss_preserves_payload_and_complete_replay_semantics(self):
        observations = []
        self.observer.on_observation = observations.append
        self.initialize('alpha')
        a = self.begin('alpha')
        self.listing(a, 'old')
        a.loss('http_reset')
        payload = wire(id=3, method='tools/call', params={'name': 'survives', 'arguments': {}})
        result = a.record('c2s', payload)
        self.assertIn('survives', result.event.parts[0].content)
        self.assertTrue(result.annotations)
        self.listing(a, 'new')
        self.assertIsNone(a.context.builder.state.surface)
        path = a.context.log.path
        a.release()
        trace = from_mcp_session_file(path)
        events = [o.event for o in observations if o.event]
        findings = [ann for o in observations for ann in o.annotations]
        self.assertEqual(semantic_findings(events, findings), semantic_findings(trace.events, replay(trace)))

    def test_response_cannot_change_existing_identity(self):
        self.initialize('alpha')
        a = self.begin('alpha'); self.listing(a, 'old')
        a.response(200, [('Mcp-Session-Id', 'beta')])
        self.assertIsNone(a.context.builder.state.surface)
        a.release()

    def test_ttl_delete_and_shutdown_keep_active_capacity_bounded(self):
        now = [0.0]
        self.observer.clock = lambda: now[0]
        known = self.initialize('alpha')
        a = self.observer.begin('DELETE', [('Mcp-Session-Id', 'alpha')])
        a.response(405, [])
        self.assertFalse(known.retired)
        a.release()
        now[0] = 301.0
        b = self.begin('alpha')
        self.assertTrue(known.retired)
        self.assertIsNot(b.context, known)
        b.release()
        known = self.initialize('beta')
        active = self.begin('beta')
        d = self.observer.begin('DELETE', [('Mcp-Session-Id', 'beta')])
        d.response(204, []); d.release()
        self.assertTrue(known.retired)
        self.assertIn(known.epoch, self.observer._contexts)
        active.release()
        self.assertNotIn(known.epoch, self.observer._contexts)
        self.observer.close()
        closed = self.begin()
        self.assertIsNone(closed.context)
        closed.release()

    def test_invalid_rpc_shapes_and_log_failure_do_not_break_replay(self):
        for payload in (wire(id=1, method='initialize', params=['bad']),
                        wire(id=1, error=['bad']), b'{"id":1,"result":{"tools":[]}}',
                        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}'):
            with self.subTest(payload=payload):
                a = self.begin()
                result = a.record('c2s', payload)
                self.assertEqual(result.event.kind.value, 'message')
                self.assertTrue(a.context.lost)
                path = a.context.log.path
                a.release()
                self.assertTrue(replay(from_mcp_session_file(path)))
        with mock.patch('glassport.http_sessions.open_session_log', return_value=None):
            a = self.begin()
            result = a.record('c2s', wire(id=1, method='initialize', params={}))
            self.assertFalse(result.persisted)
            self.assertEqual(result.diagnostic, 'http_log_failed')
            a.release()

    def test_interleaved_threads_post_get_replay_and_reconnect(self):
        seen = []
        self.observer.on_observation = seen.append
        contexts = [self.initialize('alpha'), self.initialize('beta')]
        barrier = threading.Barrier(2)
        errors = []
        def run(token, tool):
            try:
                post = self.begin(token)
                get = self.observer.begin('GET', [('Mcp-Session-Id', token)])
                post.record('c2s', wire(id=2, method='tools/list'))
                barrier.wait(2)
                get.record('s2c', wire(id=2, result={'tools': [{'name':tool}]}), event_id='same')
                barrier.wait(2)
                post.record('c2s', wire(id=3, method='tools/call', params={'name':tool}))
                get.release(); post.release()
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=run, args=pair) for pair in [('alpha','a'),('beta','b')]]
        for t in threads: t.start()
        for t in threads: t.join(5)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertFalse(errors)
        for context in contexts:
            events = [o.event for o in seen if o.epoch == context.epoch and o.event]
            annotations = [ann for o in seen if o.epoch == context.epoch for ann in o.annotations]
            trace = from_mcp_session_file(context.log.path)
            self.assertEqual(semantic_findings(events, annotations), semantic_findings(trace.events, replay(trace)))
            self.assertEqual(context.builder.events, [])
        resume = self.observer.begin('GET', [('Mcp-Session-Id','alpha'), ('Last-Event-ID','same')])
        self.assertIs(resume.context, contexts[0])
        resume.release()
        missing = self.observer.begin('GET', [('Mcp-Session-Id','alpha'), ('Last-Event-ID','forgotten')])
        self.assertTrue(missing.context.retired)
        self.assertIsNone(missing.context.builder.state.surface)
        missing.release()
        fresh = self.initialize('alpha')
        self.assertIsNot(fresh, contexts[0])

    def test_invalid_http_method_and_failure_status_cannot_declare(self):
        for method, status in (('GET', 200), ('DELETE', 405), ('POST', 500)):
            context = self.initialize('alpha')
            a = self.observer.begin(method, [('Mcp-Session-Id', 'alpha')])
            a.record('c2s', wire(id=2, method='tools/list'))
            a.response(status, [])
            a.record('s2c', wire(id=2, result={'tools':[]}))
            self.assertIsNone(context.builder.state.surface)
            a.release()

    def test_custom_limits_replay_with_explicit_matching_configuration(self):
        limits = SessionLimits(max_pending=1)
        seen = []
        observer = HTTPObserver(Path(self.tmp.name) / 'limits', session_limits=limits,
                                on_observation=seen.append)
        self.addCleanup(observer.close)
        a = observer.begin('POST', [])
        for rid in range(8):
            a.record('c2s', wire(id=rid, method='ping'))
        trace = from_mcp_session_file(a.context.log.path, limits=limits)
        self.assertEqual(semantic_findings([o.event for o in seen if o.event],
            [ann for o in seen for ann in o.annotations]), semantic_findings(trace.events, replay(trace)))
        a.release()

    def test_404_retirement_and_idle_eviction_do_not_reuse_epochs(self):
        self.observer.limits = HTTPRegistryLimits(max_sessions=1)
        old = self.initialize('alpha')
        a = self.begin('alpha')
        a.response(404, [])
        self.assertTrue(old.retired)
        a.release()
        replacement = self.initialize('alpha')
        self.assertIsNot(replacement, old)
        other = self.initialize('beta')
        self.assertTrue(replacement.retired)
        self.assertIsNot(other, replacement)
        self.assertEqual(len(self.observer._contexts), 1)

    def test_identical_tokens_in_different_credential_partitions_are_independent(self):
        a = self.initialize('shared', [('Authorization', 'first')])
        b = self.initialize('shared', [('Authorization', 'second')])
        self.assertIsNot(a, b)
        for credential, expected in [('first', a), ('second', b)]:
            lease = self.observer.begin('POST', [('Mcp-Session-Id', 'shared'), ('Authorization', credential)])
            self.assertIs(lease.context, expected)
            self.assertFalse(expected.retired)
            lease.release()
