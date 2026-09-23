"""Explicit HTTP enforcement: what it blocks, and everything it must not.

These drive the real proxy over real loopback sockets against a real upstream
HTTP server, because the claim under test is a claim about bytes: a blocked
request must never reach upstream, and every uncertain case must still arrive
there untouched. A mock relay could not tell the difference.

The upstream counts the requests it actually received. Assertions about
blocking are made against THAT counter, not against what the client saw — a
gate that answered the client locally while still forwarding the call upstream
would look identical from the client side and would be worthless.
"""
import json
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from glassport import decision_journal as dj
from glassport import decision_replay as dr
from glassport import detectors, tap
from glassport.adapters.mcp_http import run_http_tap
from glassport.http_sessions import HTTPObserver

BLOCK_MARKER = 'http_gate_blocked'


class Upstream(BaseHTTPRequestHandler):
    """A minimal MCP server that records every request it is handed.

    `calls` holds one entry per received request; the gate's core claim is
    verified by asserting this list does not grow.
    """
    protocol_version = 'HTTP/1.1'
    tools = ['search']
    sse = False
    calls: list = []
    lock = threading.Lock()

    def log_message(self, *a, **k):
        pass

    @classmethod
    def reset(cls, tools=('search',), sse=False):
        with cls.lock:
            cls.calls = []
        cls.tools = list(tools)
        cls.sse = sse

    def _result(self, frame):
        method, rid = frame.get('method'), frame.get('id')
        if method == 'initialize':
            return {'jsonrpc': '2.0', 'id': rid, 'result': {
                'protocolVersion': '2025-11-25', 'capabilities': {},
                'serverInfo': {'name': 'upstream', 'version': '1'}}}
        if method == 'tools/list':
            return {'jsonrpc': '2.0', 'id': rid,
                    'result': {'tools': [{'name': n} for n in type(self).tools]}}
        return {'jsonrpc': '2.0', 'id': rid,
                'result': {'content': [{'type': 'text', 'text': 'ok'}],
                           'isError': False}}

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0) or 0))
        try:
            frame = json.loads(raw)
        except ValueError:
            frame = {}
        with type(self).lock:
            type(self).calls.append({'method': frame.get('method'),
                                     'id': frame.get('id'), 'raw': raw})
        if isinstance(frame, dict) and 'id' not in frame:
            self.send_response(202)          # notification: nothing to answer
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        body = json.dumps(self._result(frame)).encode()
        self.send_response(200)
        if frame.get('method') == 'initialize':
            self.send_header('Mcp-Session-Id', 'sess-1')
        if type(self).sse:
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'data: ' + body + b'\r\n\r\n')
            self.close_connection = True
            return
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ChunkedBodyUpstream(Upstream):
    """A dechunking upstream, for the one scenario where the proxy itself
    must re-frame a request as chunked before forwarding it.

    `_read_client_body` in mcp_http.py caps what it captures for observation
    at `_MAX_LOGGED_BODY`; anything past the cap is still streamed upstream
    via a generator (see module comments there). Content-Length is a hop
    header the proxy always drops, and a generator body has no computable
    length, so `http.client` picks Transfer-Encoding: chunked automatically.
    The plain `Upstream` above only ever reads `Content-Length` bytes, so it
    would see zero body for a chunked request; this subclass dechunks first
    so the test can observe the real, complete bytes the proxy forwarded.
    """

    def _read_chunked(self):
        data = b''
        while True:
            size_line = self.rfile.readline()
            size = int(size_line.split(b';', 1)[0].strip(), 16)
            if size == 0:
                self.rfile.readline()   # trailing CRLF after the last chunk
                break
            data += self.rfile.read(size)
            self.rfile.readline()       # this chunk's trailing CRLF
        return data

    def do_POST(self):
        if 'chunked' not in (self.headers.get('Transfer-Encoding') or '').lower():
            return Upstream.do_POST(self)
        raw = self._read_chunked()
        try:
            frame = json.loads(raw)
        except ValueError:
            frame = {}
        with type(self).lock:
            type(self).calls.append({'method': frame.get('method'),
                                     'id': frame.get('id'), 'raw': raw})
        body = json.dumps(self._result(frame)).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GateCase(unittest.TestCase):
    """One proxy, one upstream, one journal; gate mode unless told otherwise."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        Upstream.reset()

    def upstream(self):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_address[1]}/mcp'

    def proxy(self, mode=dj.MODE_GATE, remote=None):
        remote = remote or self.upstream()
        self.observer = HTTPObserver(self.root / 'wire')
        self.journal = dj.DecisionJournal(self.root / 'decisions', self.observer,
                                          mode=mode)
        ready, box = threading.Event(), []
        threading.Thread(
            target=run_http_tap, args=(remote, self.root / 'wire'),
            kwargs={'ready': ready, 'server_box': box,
                    'observer': self.observer, 'journal': self.journal},
            daemon=True).start()
        self.assertTrue(ready.wait(5), 'proxy did not bind')
        self.addCleanup(self.journal.close)
        self.addCleanup(self.observer.close)
        self.addCleanup(box[0].shutdown)
        self.url = f'http://127.0.0.1:{box[0].server_address[1]}/mcp'
        return self.url

    # -- client -----------------------------------------------------------

    def post(self, frame, session=None, accept='application/json', url=None,
             auth=None):
        headers = {'Content-Type': 'application/json', 'Accept': accept}
        if session:
            headers['Mcp-Session-Id'] = session
        if auth:
            headers['Authorization'] = auth
        request = urllib.request.Request(url or self.url,
                                         data=json.dumps(frame).encode(),
                                         headers=headers)
        with urllib.request.urlopen(request, timeout=10) as resp:
            return resp.status, resp.read()

    def handshake(self, url=None, session='sess-1', declare=True, auth=None):
        """initialize (+ initialized, + tools/list) through the proxy."""
        self.post({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                   'params': {'protocolVersion': '2025-11-25',
                              'capabilities': {},
                              'clientInfo': {'name': 'c', 'version': '1'}}},
                  url=url, auth=auth)
        self.post({'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                  session=session, url=url, auth=auth)
        if declare:
            self.post({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
                      session=session, url=url, auth=auth)
        # Number of requests just issued, i.e. how many intent records this
        # handshake must eventually produce. `intent_watermark` reads this
        # rather than a hardcoded literal, so it can never drift out of sync
        # if a future change adds/removes a request here.
        self._handshake_request_count = 2 + (1 if declare else 0)
        return session

    def call(self, name, rid=7, session='sess-1', args=None, **kw):
        return self.post({'jsonrpc': '2.0', 'id': rid, 'method': 'tools/call',
                          'params': {'name': name, 'arguments': args or {}}},
                         session=session, **kw)

    # -- assertions --------------------------------------------------------

    def upstream_calls(self):
        with Upstream.lock:
            return list(Upstream.calls)

    def quiesce(self, timeout=10):
        """Wait until no observation lease is still held by the relay.

        The relay releases its lease in the same `finally` that closes the
        upstream connection, so "no active lease" is strictly later than any
        upstream exchange the request could have made. Without this anchor the
        "upstream received nothing" assertion is a race a broken gate can win
        just by being slow — verified: a relay mutated to answer locally AND
        forward upstream passes the unsynchronized assertion and fails this one.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.observer._lock:
                busy = any(c.active for c in self.observer._contexts.values())
            if not busy:
                return
            time.sleep(0.01)

    def assert_blocked(self, body, before, rid=7):
        """The client saw glassport's own error and upstream saw nothing."""
        self.quiesce()
        frame = json.loads(body)
        self.assertEqual(frame['error']['code'], -32000, frame)
        self.assertEqual(frame['error']['data']['glassport'], BLOCK_MARKER)
        self.assertEqual(frame['id'], rid)
        self.assertIs(type(frame['id']), type(rid))
        self.assertNotIn('result', frame)
        self.assertEqual(self.upstream_calls(), before,
                         'a blocked request reached upstream')

    def assert_forwarded(self, body, before, method='tools/call'):
        frame = json.loads(body)
        self.assertIn('result', frame, frame)
        received = self.upstream_calls()
        self.assertEqual(len(received), len(before) + 1, received)
        self.assertEqual(received[-1]['method'], method)

    def records(self, kind=None, settle=None):
        """Journal records; `settle` waits for that many deliveries first."""
        if settle is not None:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if len(self._read('delivery')) >= settle:
                    break
                time.sleep(0.02)
        self.journal.close()
        return self._read(kind)

    def _read(self, kind=None):
        out = []
        for path in sorted((self.root / 'decisions').glob('*.jsonl')):
            for line in path.read_text().splitlines():
                record = json.loads(line)
                if kind is None or record['kind'] == kind:
                    out.append(record)
        return out

    def intent_watermark(self, expected):
        """Highest intent `n` written so far, once `expected` intents exist.

        Call this right after setup traffic (handshake(), etc.) and before
        the one decisive request a test cares about, then pass the result to
        `last_call_records(since=...)`. `expected` is the number of setup
        requests already issued (e.g. 3 for a handshake with tools/list
        declared, 2 for `declare=False`) — the number of intent records that
        setup traffic must eventually produce.

        This must WAIT for those records rather than just reading whatever is
        on disk right now: `record_delivery` (and, for the request whose
        response is still being written, even `record_intent`) can still be
        in flight in the relay's own worker thread at the moment a synchronous
        client call like `handshake()` returns to the test — the client sees
        the full response before the server thread's bookkeeping for that
        same request necessarily finishes. Reading a stale, too-low watermark
        just narrows the same race `last_call_records` guards against: the
        decisive call's own record could then land in between the (still
        settling) last setup record and get mistaken for it.
        """
        deadline = time.monotonic() + 15
        ns = []
        while time.monotonic() < deadline:
            ns = [r['n'] for r in self._read('intent')]
            if len(ns) >= expected:
                break
            time.sleep(0.02)
        self.assertGreaterEqual(len(ns), expected,
                                'setup traffic never finished recording')
        return max(ns)

    def last_call_records(self, since=0):
        """(intent, delivery) for the most recent decisive frame.

        Only intents with `n > since` are considered, so a pre-existing,
        already-terminal (intent, delivery) pair from setup traffic (e.g. the
        handshake's own tools/list) can never be mistaken for the record the
        test's actual decisive call produced — see `intent_watermark`.

        The relay's finally block can run after the client has its response —
        and after a disconnect it runs with no client at all — so wait for the
        terminal record rather than racing it.
        """
        deadline = time.monotonic() + 15
        chosen = delivery = None
        while time.monotonic() < deadline:
            intents = [r for r in self._read('intent') if r['n'] > since]
            deliveries = {r['intent']: r for r in self._read('delivery')
                          if r['intent'] > since}
            interesting = [r for r in intents
                           if r['findings'] or r['action'] != 'allow']
            if intents:
                chosen = (interesting or intents)[-1]
                delivery = deliveries.get(chosen['n'])
                if delivery is not None:
                    break
            time.sleep(0.02)
        self.journal.close()
        self.assertIsNotNone(delivery, 'no terminal delivery record was written '
                             'after the watermark')
        return chosen, delivery


# ── matrix 3: the decisive block, and the same evidence in observe mode ──

class TestObservedExclusionBlocks(GateCase):
    def test_excluded_call_is_blocked_and_never_reaches_upstream(self):
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call('nope')
        self.assert_blocked(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent['action'], 'block')
        self.assertTrue(intent['candidate_block'])
        self.assertTrue(intent['enforce'])
        self.assertEqual(delivery['outcome'], 'blocked')
        self.assertEqual(delivery['code'], BLOCK_MARKER)
        self.assertTrue(delivery['enforced'])

    def test_known_empty_surface_is_exclusion_evidence_not_missing_evidence(self):
        """A server that declares zero tools has declared something."""
        Upstream.reset(tools=())
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('search')
        self.assert_blocked(body, before)

    def test_same_evidence_in_observe_mode_forwards_and_records_would_block(self):
        """The two modes differ ONLY in enforcement, never in the verdict."""
        self.proxy(mode=dj.MODE_OBSERVE)
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call('nope')
        self.assert_forwarded(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent['action'], 'block')
        self.assertTrue(intent['candidate_block'])
        self.assertFalse(intent['enforce'])
        self.assertEqual(delivery['outcome'], 'sent')
        self.assertFalse(delivery['enforced'])

    def test_passive_wrap_with_no_journal_cannot_reach_the_gate_branch(self):
        """Byte-for-byte unchanged: no journal, no enforcement, at all."""
        self.observer = HTTPObserver(self.root / 'wire')
        self.addCleanup(self.observer.close)
        ready, box = threading.Event(), []
        threading.Thread(
            target=run_http_tap, args=(self.upstream(), self.root / 'wire'),
            kwargs={'ready': ready, 'server_box': box, 'observer': self.observer},
            daemon=True).start()
        self.assertTrue(ready.wait(5))
        self.addCleanup(box[0].shutdown)
        self.url = f'http://127.0.0.1:{box[0].server_address[1]}/mcp'
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope')
        self.assert_forwarded(body, before)


# ── matrix 1, 2, 4, 5: everything that must forward ───────────────────────

class TestConservativeForwarding(GateCase):
    def test_allowed_declared_tool_forwards(self):
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call('search')
        self.assert_forwarded(body, before)
        intent, delivery = self.last_call_records(since=since)
        self.assertEqual(intent['action'], 'allow')
        self.assertFalse(intent['enforce'])
        self.assertEqual(delivery['outcome'], 'sent')
        self.assertFalse(delivery['enforced'])

    def test_no_declaration_ever_seen_forwards(self):
        """Missing evidence is not exclusion evidence."""
        self.proxy()
        self.handshake(declare=False)
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call('anything')
        self.assert_forwarded(body, before)
        intent, _ = self.last_call_records(since=since)
        self.assertFalse(intent['candidate_block'])

    def test_malformed_declaration_forwards(self):
        """A tools/list result that is not a tool list declares nothing."""
        class Broken(Upstream):
            def _result(self, frame):
                if frame.get('method') == 'tools/list':
                    return {'jsonrpc': '2.0', 'id': frame.get('id'),
                            'result': {'tools': 'not-a-list'}}
                return Upstream._result(self, frame)
        srv = ThreadingHTTPServer(('127.0.0.1', 0), Broken)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.proxy(remote=f'http://127.0.0.1:{srv.server_address[1]}/mcp')
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope')
        self.assert_forwarded(body, before)

    def test_incomplete_paginated_declaration_forwards(self):
        """A surface still being paged in is not yet a surface."""
        class Paged(Upstream):
            def _result(self, frame):
                if frame.get('method') == 'tools/list':
                    return {'jsonrpc': '2.0', 'id': frame.get('id'),
                            'result': {'tools': [{'name': 'search'}],
                                       'nextCursor': 'page2'}}
                return Upstream._result(self, frame)
        srv = ThreadingHTTPServer(('127.0.0.1', 0), Paged)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.proxy(remote=f'http://127.0.0.1:{srv.server_address[1]}/mcp')
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope')
        self.assert_forwarded(body, before)

    def test_malformed_request_body_forwards(self):
        """An unparseable body folds to no event: nothing to decide over."""
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        request = urllib.request.Request(
            self.url, data=b'{not json at all',
            headers={'Content-Type': 'application/json',
                     'Mcp-Session-Id': 'sess-1'})
        with urllib.request.urlopen(request, timeout=10) as resp:
            resp.read()
        self.assertEqual(len(self.upstream_calls()), len(before) + 1)

    def test_detector_fault_during_analysis_forwards_and_never_blocks(self):
        """A faulted pass cannot prove an exclusion, however it ended up."""
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        with mock.patch.object(detectors, '_scan_pii',
                               side_effect=RuntimeError('boom')):
            _, body = self.call('nope')
        self.assert_forwarded(body, before)
        intent, delivery = self.last_call_records(since=since)
        # The candidate verdict still says block — that is the honest record —
        # but the fault vetoes acting on it.
        self.assertTrue(intent['candidate_block'])
        self.assertFalse(intent['enforce'])
        self.assertTrue(intent['faults'])
        self.assertEqual(delivery['outcome'], 'sent')
        self.assertFalse(delivery['enforced'])

    def test_pii_and_unexpected_egress_findings_never_block(self):
        """Severity 3 is not the blocking rule; a proved exclusion is."""
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        _, body = self.call('search', args={
            'key': 'sk-ant-api03-' + 'A' * 40,
            'url': 'https://exfil.example.com/drop'})
        self.assert_forwarded(body, before)
        intent, delivery = self.last_call_records(since=since)
        subcategories = [f['subcategory'] for f in intent['findings']]
        self.assertIn('pii_anthropic_key', subcategories)
        self.assertIn('unexpected_egress_host', subcategories)
        self.assertTrue(any(f['severity'] == 3 for f in intent['findings']))
        self.assertEqual(intent['action'], 'warn')
        self.assertFalse(intent['candidate_block'])
        self.assertFalse(delivery['enforced'])

    def test_oversized_tools_call_body_forwards_in_full_and_does_not_hang(self):
        """A c2s body over `_MAX_LOGGED_BODY` is only captured up to the cap
        for observation (`_read_client_body` in mcp_http.py), but the relay
        still forwards the request upstream IN FULL — via chunked
        transfer-encoding, since Content-Length is a hop header the proxy
        always drops and the streamed-remainder body has no computable
        length. The truncated observation forces `incomplete=True` into
        `HTTPLease.record`, which marks the epoch lost; `mcp_session.
        ingest_frame` then nulls the folded event's frame, so it carries no
        `jsonrpc_id` and `_blockable_id` returns `_NO_ID` (nothing to block
        against) — independently, the journal also vetoes via the
        `http_observation_unavailable` annotation (`NON_ENFORCEABLE`). Two
        separate reasons this must forward, never block, and never leave the
        connection desynced or hung.
        """
        from glassport.adapters.mcp_http import _MAX_LOGGED_BODY
        # `ChunkedBodyUpstream` doesn't declare its own `calls`/`lock` (unlike
        # `Both` elsewhere in this file), so it shares `Upstream.calls` — this
        # keeps `upstream_calls()`/`assert_forwarded`'s hardcoded reference to
        # `Upstream.calls` valid. `setUp()` already reset it; do not call
        # `.reset()` again through the subclass or it would shadow the shared
        # list with a new one of its own and this test would falsely fail.
        srv = ThreadingHTTPServer(('127.0.0.1', 0), ChunkedBodyUpstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.proxy(remote=f'http://127.0.0.1:{srv.server_address[1]}/mcp')
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()

        # A tool the server never declared, so — were the oversized body not
        # forced to forward for its own independent reasons — this would
        # otherwise be exactly the shape a proved exclusion blocks.
        pad = 'A' * (_MAX_LOGGED_BODY + 64_000)
        frame = {'jsonrpc': '2.0', 'id': 42, 'method': 'tools/call',
                 'params': {'name': 'nope', 'arguments': {'padding': pad}}}
        payload = json.dumps(frame).encode()
        self.assertGreater(len(payload), _MAX_LOGGED_BODY,
                           'test body must actually exceed the cap')

        status, body = self.post(frame, session='sess-1')

        # Forwarded, not blocked: an ordinary upstream tools/call result, not
        # glassport's synthesized -32000 error — and it reached upstream
        # complete, byte for byte (the dechunking upstream saw the full
        # padded payload, not a cap-sized prefix).
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertIn('result', result, result)
        received = self.upstream_calls()
        self.assertEqual(len(received), len(before) + 1, received)
        self.assertEqual(received[-1]['method'], 'tools/call')
        self.assertEqual(len(received[-1]['raw']), len(payload))

        # The connection completed cleanly (no hang/timeout above), and the
        # decisive record shows a forward, never a block.
        intent, delivery = self.last_call_records(since=since)
        self.assertFalse(intent['candidate_block'])
        self.assertFalse(intent['enforce'])
        self.assertIn('http_observation_unavailable',
                      [f['subcategory'] for f in intent['findings']])
        self.assertEqual(delivery['outcome'], 'sent')
        self.assertFalse(delivery['enforced'])

        # Pin the OTHER independent reason this forwards, not just the
        # NON_ENFORCEABLE veto above: the wire capture itself, at the exact
        # sequence this intent was computed from, shows glassport never had
        # an interpretable JSON-RPC id to answer a block with in the first
        # place (`_blockable_id` -> `_NO_ID`) — read from raw evidence, the
        # way `TestGateModeReplay` reads the wire log, rather than trusting
        # only the derived annotation.
        wire_lines = (self.root / 'wire' / f"{intent['epoch']}.jsonl").read_text().splitlines()
        wire_entry = next(json.loads(l) for l in wire_lines if json.loads(l)['seq'] == intent['wire_seq'])
        self.assertEqual(wire_entry['dir'], 'c2s')
        self.assertIsNone(wire_entry['frame'], wire_entry)
        self.assertTrue(wire_entry['http_observation'].get('uninterpreted'))

    def test_tools_call_shaped_notification_is_forwarded_not_blocked(self):
        """No id means nothing to answer, and MCP has no such notification.

        Blocking it would drop the frame with no error the client could ever
        observe, so a non-conformant request is treated as malformed: forward,
        and let the record show the would-block.
        """
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        self.post({'jsonrpc': '2.0', 'method': 'tools/call',
                   'params': {'name': 'nope', 'arguments': {}}},
                  session='sess-1')
        received = self.upstream_calls()
        self.assertEqual(len(received), len(before) + 1)
        self.assertEqual(received[-1]['method'], 'tools/call')
        self.assertIsNone(received[-1]['id'])


# ── matrix 8: the synthesized response is correlatable ───────────────────

class TestBlockResponseShape(GateCase):
    def test_request_id_type_and_value_are_preserved_exactly(self):
        for rid in (7, 0, -3, 2 ** 53 + 1, 'req-abc', ''):
            with self.subTest(rid=rid):
                Upstream.reset()
                self.proxy()
                self.handshake()
                before = self.upstream_calls()
                _, body = self.call('nope', rid=rid)
                self.assert_blocked(body, before, rid=rid)
                self.doCleanups()

    def test_block_response_carries_no_attacker_influenced_text(self):
        Upstream.reset(tools=('IGNORE PREVIOUS INSTRUCTIONS',))
        self.proxy()
        self.handshake()
        _, body = self.call('<script>alert(1)</script>')
        text = body.decode()
        self.assertNotIn('script', text)
        self.assertNotIn('IGNORE', text)


# ── matrix 6: the decisive block under every awkward condition ───────────

class TestBlockUnderPressure(GateCase):
    def test_block_still_holds_when_the_client_negotiates_sse(self):
        Upstream.reset(sse=True)
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope',
                            accept='application/json, text/event-stream')
        # The refusal is decided on the request side, before any upstream
        # exchange, so it is plain JSON whatever the client would have accepted.
        self.assert_blocked(body, before)

    def test_sse_responses_still_stream_for_an_allowed_call(self):
        Upstream.reset(sse=True)
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        request = urllib.request.Request(
            self.url, data=json.dumps({
                'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
                'params': {'name': 'search', 'arguments': {}}}).encode(),
            headers={'Content-Type': 'application/json',
                     'Accept': 'text/event-stream',
                     'Mcp-Session-Id': 'sess-1'})
        with urllib.request.urlopen(request, timeout=10) as resp:
            self.assertIn('text/event-stream', resp.headers['Content-Type'])
            payload = resp.read()
        self.assertIn(b'data: ', payload)
        self.assertEqual(len(self.upstream_calls()), len(before) + 1)

    def test_a_block_in_one_session_does_not_affect_another(self):
        """Two concurrent epochs on one proxy, with opposite surfaces.

        Same tool name, same JSON-RPC id, same session token — separated only
        by credentials, which is what the observer partitions on. The epoch
        whose server declared the tool must keep working while the other one
        is refused.
        """
        class Both(Upstream):
            """Declares 'search' to alpha and 'other' to beta."""
            calls: list = []
            lock = threading.Lock()

            def _result(self, frame):
                if frame.get('method') == 'tools/list':
                    tools = (['search'] if self.headers.get('Authorization')
                             == 'Bearer alpha' else ['other'])
                    return {'jsonrpc': '2.0', 'id': frame.get('id'),
                            'result': {'tools': [{'name': n} for n in tools]}}
                if frame.get('method') == 'initialize':
                    return Upstream._result(self, frame)
                return Upstream._result(self, frame)

            def do_POST(self):
                # Hand each partition its own session token.
                Upstream.do_POST(self)

        srv = ThreadingHTTPServer(('127.0.0.1', 0), Both)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.proxy(remote=f'http://127.0.0.1:{srv.server_address[1]}/mcp')

        self.handshake(auth='Bearer alpha')
        self.handshake(auth='Bearer beta')
        with Both.lock:
            before = len([c for c in Both.calls if c['method'] == 'tools/call'])

        _, allowed = self.call('search', auth='Bearer alpha')
        self.assertIn('result', json.loads(allowed))
        _, blocked = self.call('search', auth='Bearer beta')
        frame = json.loads(blocked)
        self.assertEqual(frame['error']['data']['glassport'], BLOCK_MARKER)
        with Both.lock:
            received = [c for c in Both.calls if c['method'] == 'tools/call']
        self.assertEqual(len(received), before + 1,
                         'exactly the allowed call may reach upstream')

    def test_a_surface_update_unblocks_and_blocks_in_the_same_session(self):
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope', rid=10)
        self.assert_blocked(body, before, rid=10)

        # The server re-declares: 'nope' is now offered, 'search' withdrawn.
        Upstream.tools = ['nope']
        self.post({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'},
                  session='sess-1')
        before = self.upstream_calls()
        _, body = self.call('nope', rid=11)
        self.assert_forwarded(body, before)
        before = self.upstream_calls()
        _, body = self.call('search', rid=12)
        self.assert_blocked(body, before, rid=12)

    def test_client_disconnect_around_the_block_still_records_it(self):
        self.proxy()
        self.handshake()
        since = self.intent_watermark(self._handshake_request_count)
        before = self.upstream_calls()
        body = json.dumps({'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
                           'params': {'name': 'nope', 'arguments': {}}}).encode()
        with socket.create_connection(
                ('127.0.0.1', int(self.url.rsplit(':', 1)[1].split('/')[0])),
                timeout=5) as sock:
            sock.sendall(b'POST /mcp HTTP/1.1\r\nHost: x\r\n'
                         b'Mcp-Session-Id: sess-1\r\n'
                         b'Content-Type: application/json\r\n'
                         b'Content-Length: ' + str(len(body)).encode()
                         + b'\r\n\r\n' + body)
            sock.shutdown(socket.SHUT_RDWR)
        self.assertEqual(self.upstream_calls(), before)
        intent, delivery = self.last_call_records(since=since)
        self.assertTrue(intent['enforce'])
        self.assertEqual(delivery['outcome'], 'blocked')
        self.assertTrue(delivery['enforced'])

    def test_cancellation_for_a_blocked_call_forwards_and_changes_nothing(self):
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope', rid=7)
        self.assert_blocked(body, before)
        before = self.upstream_calls()
        self.post({'jsonrpc': '2.0', 'method': 'notifications/cancelled',
                   'params': {'requestId': 7, 'reason': 'user'}},
                  session='sess-1')
        received = self.upstream_calls()
        self.assertEqual(len(received), len(before) + 1)
        self.assertEqual(received[-1]['method'], 'notifications/cancelled')


# ── matrix 6/7: the block must not depend on recording it ────────────────

class TestBlockIsIndependentOfRecording(GateCase):
    """The subtle half of the fail-open contract.

    Recording is fail-open: a journal that cannot write must not disturb the
    relay. The block ACTION is not: once analysis has proved an exclusion, no
    failure in the recording path may downgrade it to a forward. These two
    tests separate "the write failed" from "the recording call itself blew
    up" — only the second proves the verdict is computed independently.
    """

    def test_a_failing_journal_write_does_not_turn_a_block_into_a_forward(self):
        self.proxy()
        self.handshake()
        entry = self.journal._open(sorted(self.journal._epochs)[0]
                                   if self.journal._epochs else 'x')
        before = self.upstream_calls()
        with mock.patch.object(type(entry.log), 'write_json',
                               side_effect=OSError('disk full')):
            _, body = self.call('nope')
        self.assert_blocked(body, before)

    def test_a_raising_record_intent_does_not_turn_a_block_into_a_forward(self):
        """If the verdict were read off record_intent's return value, this
        would forward — which is exactly the bug this test exists to catch."""
        self.proxy()
        self.handshake()
        before = self.upstream_calls()
        with mock.patch.object(type(self.journal), 'record_intent',
                               side_effect=RuntimeError('journal exploded')):
            _, body = self.call('nope')
        self.assert_blocked(body, before)

    def test_an_unwritable_journal_directory_still_blocks(self):
        blocked_dir = self.root / 'blocked'
        blocked_dir.mkdir(mode=0o500)
        self.addCleanup(blocked_dir.chmod, 0o700)
        remote = self.upstream()
        self.observer = HTTPObserver(self.root / 'wire')
        self.addCleanup(self.observer.close)
        self.journal = dj.DecisionJournal(blocked_dir / 'sub', self.observer,
                                          mode=dj.MODE_GATE)
        self.addCleanup(self.journal.close)
        ready, box = threading.Event(), []
        threading.Thread(
            target=run_http_tap, args=(remote, self.root / 'wire'),
            kwargs={'ready': ready, 'server_box': box,
                    'observer': self.observer, 'journal': self.journal},
            daemon=True).start()
        self.assertTrue(ready.wait(5))
        self.addCleanup(box[0].shutdown)
        self.url = f'http://127.0.0.1:{box[0].server_address[1]}/mcp'
        self.handshake()
        before = self.upstream_calls()
        _, body = self.call('nope')
        self.assert_blocked(body, before)


# ── matrix 9: a gate-mode epoch still replays ────────────────────────────

class TestGateModeReplay(GateCase):
    def test_recorded_gate_decisions_replay_as_equivalent(self):
        self.proxy()
        self.handshake()
        self.call('search', rid=5)
        before = self.upstream_calls()
        _, body = self.call('nope', rid=6)
        self.assert_blocked(body, before, rid=6)
        self.records(settle=1)
        journals = sorted((self.root / 'decisions').glob('*.jsonl'))
        self.assertEqual(len(journals), 1)
        epoch = journals[0].stem
        profile = json.loads(journals[0].read_text().splitlines()[0])
        self.assertEqual(profile['mode'], 'gate')
        result = dr.verify_journal(journals[0],
                                   self.root / 'wire' / f'{epoch}.jsonl')
        self.assertIn(result.status, ('equivalent', 'incomplete'),
                      result.as_dict())
        self.assertEqual(result.mismatched, [])
        blocked = [r for r in self._read('intent') if r['enforce']]
        self.assertTrue(blocked, 'no enforced record to replay')


# ── CLI surface ───────────────────────────────────────────────────────────

class TestGateCLISurface(unittest.TestCase):
    def test_gate_over_http_is_wired_and_no_longer_refused(self):
        with mock.patch.object(tap, '_run_http_gate', return_value=0) as run:
            self.assertEqual(
                tap.main(['gate', '--transport', 'http', '--url',
                          'http://127.0.0.1:1/mcp']), 0)
        self.assertEqual(run.call_args.args[0], 'http://127.0.0.1:1/mcp')

    def test_gate_http_builds_a_gate_mode_journal_and_nothing_else(self):
        seen = {}

        def fake_run(remote_url, log_dir, *a, **kw):
            seen['journal'] = kw['journal']
            seen['observer'] = kw['observer']

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('glassport.adapters.mcp_http.run_http_tap', fake_run):
                self.assertEqual(
                    tap._run_http_gate('http://127.0.0.1:1/mcp', Path(tmp)), 0)
        self.assertEqual(seen['journal'].mode, dj.MODE_GATE)
        self.assertIsNotNone(seen['observer'])

    def test_bad_and_ambiguous_gate_http_invocations_are_refused(self):
        import contextlib
        import io
        for args in (['gate', '--transport', 'http'],
                     ['gate', '--controllable', '--transport', 'http',
                      '--url', 'http://127.0.0.1:1/mcp'],
                     ['gate', '--transport', 'http', '--url', 'ftp://nope/']):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tap.main(args), 2, args)

    def test_strict_over_http_is_refused_not_ignored(self):
        """--strict configures the stdio Gate only; the HTTP gate must refuse
        it rather than start without the fail-closed posture it asked for."""
        import contextlib
        import io
        with mock.patch.object(tap, '_run_http_gate', return_value=0) as run:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(tap.main(['gate', '--strict', '--transport', 'http',
                                           '--url', 'http://127.0.0.1:1/mcp']), 2)
        run.assert_not_called()
        self.assertIn('--strict', err.getvalue())

    def test_passive_wrap_over_http_is_unchanged(self):
        """`wrap --transport http` must not acquire a gate by accident."""
        import contextlib
        import io
        with mock.patch('glassport.adapters.mcp_http.run_http_tap') as run:
            self.assertEqual(
                tap.main(['wrap', '--transport', 'http', '--url',
                          'http://127.0.0.1:1/mcp']), 0)
        self.assertEqual(run.call_args.kwargs, {})
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tap.main(['wrap', '--transport', 'http']), 2)


if __name__ == '__main__':
    unittest.main()
