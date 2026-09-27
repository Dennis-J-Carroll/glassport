"""Stateless 2026-07-28 enforcement scopes (plan S2).

A modern server has no sessions: each request is its own POST, and the tool
list may vary with the authorization presented. The gate therefore keys a
declaration scope on the upstream, protocol version, credentials, and any
operator-configured tenant headers. Anonymous callers share one only when
the operator opts in (--public-surface). Different scopes never lend each
other a declaration, and callers reusing JSON-RPC ids never cross-pair.
"""
import http.client
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from glassport import decision_journal as dj
from glassport.adapters.mcp_http import run_http_tap
from glassport.http_sessions import HTTPObserver

MODERN = '2026-07-28'
META = {'io.modelcontextprotocol/protocolVersion': MODERN,
        'io.modelcontextprotocol/clientCapabilities': {}}
BLOCK = b'http_gate_blocked'


class StatelessUpstream(BaseHTTPRequestHandler):
    """A 2026 server: tool list chosen by Authorization and X-Tenant."""
    protocol_version = 'HTTP/1.1'
    lists = {}
    calls = []
    lock = threading.Lock()
    list_delay = 0.0
    session_header = False
    listen_release = None

    def log_message(self, *a, **k):
        pass

    def reply(self, status, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        frame = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        who = (self.headers.get('Authorization'), self.headers.get('X-Tenant'))
        method, rid = frame.get('method'), frame.get('id')
        with type(self).lock:
            type(self).calls.append((method, (frame.get('params') or {}).get('name'), who))
        if method == 'tools/list':
            time.sleep(type(self).list_delay)
            names = type(self).lists.get(who, type(self).lists.get('*', []))
            extra = [('Mcp-Session-Id', 'minted')] if type(self).session_header else []
            return self.reply(200, {'jsonrpc': '2.0', 'id': rid, 'result': {
                'tools': [{'name': n, 'inputSchema': {'type': 'object'}} for n in names]}}, extra)
        if method == 'subscriptions/listen':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'data: {"jsonrpc":"2.0","method":'
                             b'"notifications/subscriptions/acknowledged"}\n\n')
            self.wfile.flush()
            type(self).listen_release.wait(10)
            self.wfile.write(b'data: {"jsonrpc":"2.0","method":'
                             b'"notifications/tools/list_changed"}\n\n')
            self.wfile.flush()
            self.close_connection = True
            return
        if method == 'plain/error':
            body = b'{"detail": "bad request"}'   # a framework error, not JSON-RPC
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == 'unknown/method':
            return self.reply(404, {'jsonrpc': '2.0', 'id': rid,
                                    'error': {'code': -32601, 'message': 'Method not found'}})
        return self.reply(200, {'jsonrpc': '2.0', 'id': rid, 'result': {
            'content': [{'type': 'text', 'text': 'ok'}], 'isError': False}})


class ScopeCase(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        StatelessUpstream.lists = {('Bearer A', None): ['search'],
                                   ('Bearer B', None): ['fetch'],
                                   ('Bearer A', 'alpha'): ['search'],
                                   ('Bearer A', 'beta'): ['fetch'],
                                   (None, None): ['search']}
        StatelessUpstream.calls = []
        StatelessUpstream.list_delay = 0.0
        StatelessUpstream.session_header = False
        StatelessUpstream.listen_release = threading.Event()

    def proxy(self, *, scope_headers=(), public_surface=False, mode=dj.MODE_GATE):
        srv = ThreadingHTTPServer(('127.0.0.1', 0), StatelessUpstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.observer = HTTPObserver(self.root / 'wire', scope_headers=scope_headers,
                                     public_surface=public_surface)
        journal = dj.DecisionJournal(self.root / 'decisions', self.observer, mode=mode)
        ready, box = threading.Event(), []
        threading.Thread(target=run_http_tap,
                         args=(f'http://127.0.0.1:{srv.server_address[1]}/mcp', self.root / 'wire'),
                         kwargs={'ready': ready, 'server_box': box, 'observer': self.observer,
                                 'journal': journal, 'endpoint_era': 'modern'},
                         daemon=True).start()
        self.assertTrue(ready.wait(5))
        self.addCleanup(journal.close)
        self.addCleanup(self.observer.close)
        self.addCleanup(box[0].shutdown)
        self.port = box[0].server_address[1]

    def send(self, method, rid, *, name=None, auth='Bearer A', tenant=None, extra=()):
        params = {'_meta': dict(META)}
        headers = [('Content-Type', 'application/json'),
                   ('Accept', 'application/json, text/event-stream'),
                   ('MCP-Protocol-Version', MODERN), ('Mcp-Method', method)]
        if name is not None:
            params.update(name=name, arguments={})
            headers.append(('Mcp-Name', name))
        if auth is not None:
            headers.append(('Authorization', auth))
        if tenant is not None:
            headers.append(('X-Tenant', tenant))
        headers.extend(extra)
        data = json.dumps({'jsonrpc': '2.0', 'id': rid, 'method': method,
                           'params': params}).encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        conn.putrequest('POST', '/mcp')
        for key, value in headers + [('Content-Length', str(len(data)))]:
            conn.putheader(key, value)
        conn.endheaders(data)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def settle(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with self.observer._lock:
                if not any(c.active for c in self.observer._contexts.values()):
                    return
            time.sleep(0.01)

    def call(self, name, rid, **kw):
        before = len(StatelessUpstream.calls)
        _, body = self.send('tools/call', rid, name=name, **kw)
        self.settle()
        return ('blocked' if BLOCK in body else 'forwarded',
                len(StatelessUpstream.calls) - before)

    def lists(self, rid, **kw):
        self.send('tools/list', rid, **kw)
        self.settle()


class TestStatelessEnforcement(ScopeCase):
    def test_a_listed_scope_blocks_undeclared_calls_across_posts(self):
        self.proxy()
        self.lists(1)
        self.assertEqual(self.call('nope', 2), ('blocked', 0))
        self.assertEqual(self.call('search', 3), ('forwarded', 1))

    def test_credentials_define_separate_scopes(self):
        self.proxy()
        self.lists(1, auth='Bearer A')
        self.lists(1, auth='Bearer B')
        self.assertEqual(self.call('fetch', 2, auth='Bearer A'), ('blocked', 0))
        self.assertEqual(self.call('fetch', 3, auth='Bearer B'), ('forwarded', 1))
        self.assertEqual(self.call('search', 4, auth='Bearer B'), ('blocked', 0))

    def test_an_unlisted_scope_never_borrows_another_declaration(self):
        self.proxy()
        self.lists(1, auth='Bearer A')
        self.assertEqual(self.call('nope', 2, auth='Bearer B'), ('forwarded', 1))

    def test_configured_tenant_header_splits_scopes(self):
        self.proxy(scope_headers=('X-Tenant',))
        self.lists(1, tenant='alpha')
        self.lists(1, tenant='beta')
        self.assertEqual(self.call('fetch', 2, tenant='alpha'), ('blocked', 0))
        self.assertEqual(self.call('fetch', 3, tenant='beta'), ('forwarded', 1))

    def test_duplicate_configured_scope_header_is_refused(self):
        self.proxy(scope_headers=('X-Tenant',))
        self.lists(1, tenant='alpha')
        before = len(StatelessUpstream.calls)
        status, _ = self.send('tools/call', 2, name='search', tenant='alpha',
                              extra=[('X-Tenant', 'beta')])
        self.settle()
        self.assertEqual((status, len(StatelessUpstream.calls) - before), (400, 0))

    def test_anonymous_callers_share_only_with_public_surface(self):
        self.proxy()
        self.lists(1, auth=None)
        self.assertEqual(self.call('nope', 2, auth=None), ('forwarded', 1))

    def test_public_surface_opt_in_enforces_anonymous_callers(self):
        self.proxy(public_surface=True)
        self.lists(1, auth=None)
        self.assertEqual(self.call('nope', 2, auth=None), ('blocked', 0))

    def test_concurrent_callers_reusing_ids_do_not_cross_pair(self):
        self.proxy()
        StatelessUpstream.list_delay = 0.3
        threads = [threading.Thread(target=self.send, args=('tools/list', 1))
                   for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.settle()
        self.assertEqual(self.call('nope', 1), ('blocked', 0))

    def test_list_changed_on_a_listen_stream_retires_the_scope(self):
        self.proxy()
        self.lists(1)
        self.assertEqual(self.call('new_tool', 2), ('blocked', 0))
        listener = threading.Thread(target=self.send, args=('subscriptions/listen', 3))
        listener.start()
        time.sleep(0.3)
        StatelessUpstream.listen_release.set()
        listener.join(10)
        self.settle()
        self.assertEqual(self.call('new_tool', 4), ('forwarded', 1))
        self.lists(5)
        self.assertEqual(self.call('new_tool', 6), ('blocked', 0))

    def test_a_modern_404_does_not_retire_the_scope(self):
        """In 2026 a 404 means method-not-found, not session expiry."""
        self.proxy()
        self.lists(1)
        self.send('unknown/method', 2)
        self.settle()
        self.assertEqual(self.call('nope', 3), ('blocked', 0))

    def test_an_unreadable_reply_does_not_retire_a_shared_scope(self):
        """A caller can provoke a non-JSON-RPC reply (a framework's JSON 400);
        that one exchange is recorded uninterpreted, not treated as a loss
        that would reset the scope for every other caller."""
        self.proxy()
        self.lists(1)
        self.send('plain/error', 2)
        self.settle()
        self.assertEqual(self.call('nope', 3), ('blocked', 0))

    def test_a_minted_session_id_on_a_modern_reply_is_ignored(self):
        self.proxy()
        StatelessUpstream.session_header = True
        self.lists(1)
        self.assertEqual(self.call('nope', 2), ('blocked', 0))

    def test_no_raw_credential_reaches_disk(self):
        self.proxy(scope_headers=('X-Tenant',))
        self.lists(1, tenant='alpha')
        self.call('nope', 2, tenant='alpha')
        for path in self.root.rglob('*'):
            if path.is_file():
                text = path.read_text(errors='replace')
                self.assertNotIn('Bearer A', text, path)
                self.assertNotIn('alpha', text, path)


class TestScopeReplay(ScopeCase):
    def test_each_scope_log_replays_to_the_same_decision(self):
        from glassport.adapters.mcp_session import from_mcp_session_file
        self.proxy()
        self.lists(1)
        self.lists(1, auth='Bearer B')
        self.call('nope', 2)
        logs = sorted((self.root / 'wire').glob('*.jsonl'))
        self.assertEqual(len(logs), 2)
        fabricated = [n for log in logs
                      for _, n in from_mcp_session_file(log).fabricated_tool_calls()]
        self.assertEqual(fabricated, ['nope'])


if __name__ == '__main__':
    unittest.main()


class TestScopeCLI(unittest.TestCase):
    def run_main(self, extra):
        import contextlib
        import io
        from unittest import mock
        from glassport import tap
        seen = {}

        def fake(remote, log_dir, **kw):
            seen.update(kw)
            return 0
        with mock.patch.object(tap, '_run_http_gate', fake), \
                contextlib.redirect_stderr(io.StringIO()):
            code = tap.main(['gate', '--transport', 'http', '--url',
                             'http://127.0.0.1:1/mcp'] + extra)
        return code, seen

    def test_scope_options_reach_the_gate(self):
        code, seen = self.run_main(['--endpoint-era', 'modern', '--scope-header', 'X-Tenant',
                                    '--scope-header', 'X-Org', '--public-surface'])
        self.assertEqual(code, 0)
        self.assertEqual(seen['scope_headers'], ('X-Tenant', 'X-Org'))
        self.assertTrue(seen['public_surface'])

    def test_defaults(self):
        code, seen = self.run_main([])
        self.assertEqual((code, seen['scope_headers'], seen['public_surface']), (0, (), False))

    def test_invalid_scope_options_are_usage_errors(self):
        for extra in (['--scope-header'], ['--scope-header', 'Authorization'],
                      ['--scope-header', 'bad header'], ['--public-surface', 'yes']):
            with self.subTest(extra=extra):
                self.assertEqual(self.run_main(extra), (2, {}))

    def test_cli_gate_builds_an_observer_with_the_scope_options(self):
        from unittest import mock
        from glassport import tap
        seen = {}

        def fake_run(remote, log_dir, **kw):
            seen['observer'] = kw['observer']
        import tempfile
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch('glassport.adapters.mcp_http.run_http_tap', fake_run):
            tap._run_http_gate('http://127.0.0.1:1/mcp', Path(tmp),
                               scope_headers=('X-Tenant',), public_surface=True)
        self.assertEqual(seen['observer'].scope_headers, ('x-tenant',))
        self.assertTrue(seen['observer'].public_surface)
