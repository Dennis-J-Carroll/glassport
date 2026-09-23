"""End to end: the HTTP gate stops treating a stale declaration as authority.

Before, a server that announced notifications/tools/list_changed (or whose
tools/list carried an elapsed ttlMs) could add a tool, and the gate would
block calls to it as fabricated against the outdated list.
"""
import json
import time
import unittest
from unittest import mock

from tests.test_http_gate import BLOCK_MARKER, GateCase, Upstream

LIST_CHANGED = {'jsonrpc': '2.0', 'method': 'notifications/tools/list_changed'}


class ChangingUpstream(Upstream):
    """Declares `search`; a `ping` answers over SSE after first announcing
    tools/list_changed, the way a server streams a notification ahead of a
    response. `ttl` adds ttlMs to tools/list."""
    ttl = None

    def _result(self, frame):
        out = super()._result(frame)
        if frame.get('method') == 'tools/list' and type(self).ttl is not None:
            out['result']['ttlMs'] = type(self).ttl
        return out

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0) or 0))
        frame = json.loads(raw) if raw else {}
        with type(self).lock:
            type(self).calls.append({'method': frame.get('method'),
                                     'id': frame.get('id'), 'raw': raw})
        if 'id' not in frame:
            self.send_response(202)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if frame.get('method') == 'ping':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Connection', 'close')
            self.end_headers()
            for message in (LIST_CHANGED, {'jsonrpc': '2.0', 'id': frame['id'], 'result': {}}):
                self.wfile.write(b'data: ' + json.dumps(message).encode() + b'\n\n')
            self.close_connection = True
            return
        body = json.dumps(self._result(frame)).encode()
        self.send_response(200)
        if frame.get('method') == 'initialize':
            self.send_header('Mcp-Session-Id', 'sess-1')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FreshnessCase(GateCase):
    def upstream(self):
        from http.server import ThreadingHTTPServer
        import threading
        ChangingUpstream.ttl = None
        srv = ThreadingHTTPServer(('127.0.0.1', 0), ChangingUpstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f'http://127.0.0.1:{srv.server_address[1]}/mcp'

    _next_id = 100

    def outcome(self, name):
        # A fresh JSON-RPC id per call: a reused id is quarantined by the
        # correlation layer and forwards for that reason alone, which would
        # mask whether the surface itself went stale.
        FreshnessCase._next_id += 1
        before = len(self.upstream_calls())
        _, body = self.call(name, rid=FreshnessCase._next_id)
        self.quiesce()
        return ('blocked' if BLOCK_MARKER.encode() in body else 'forwarded',
                len(self.upstream_calls()) - before)


class TestHTTPListChanged(FreshnessCase):
    def test_new_tool_forwards_after_list_changed(self):
        self.proxy()
        self.handshake()
        self.assertEqual(self.outcome('new_tool'), ('blocked', 0))
        self.post({'jsonrpc': '2.0', 'id': 30, 'method': 'ping'}, session='sess-1',
                  accept='application/json, text/event-stream')
        self.quiesce()
        self.assertEqual(self.outcome('new_tool'), ('forwarded', 1))

    def test_relisting_restores_enforcement(self):
        self.proxy()
        self.handshake()
        self.post({'jsonrpc': '2.0', 'id': 30, 'method': 'ping'}, session='sess-1',
                  accept='application/json, text/event-stream')
        self.post({'jsonrpc': '2.0', 'id': 31, 'method': 'tools/list'}, session='sess-1')
        self.quiesce()
        self.assertEqual(self.outcome('new_tool'), ('blocked', 0))


class TestHTTPTTL(FreshnessCase):
    def test_new_tool_forwards_once_ttl_elapses(self):
        self.proxy()
        ChangingUpstream.ttl = 300
        self.handshake()
        self.assertEqual(self.outcome('new_tool'), ('blocked', 0))
        time.sleep(0.4)
        self.assertEqual(self.outcome('new_tool'), ('forwarded', 1))

    def test_log_failure_keeps_a_ttl_surface_known(self):
        """A disk failure already stops enforcement (#80: unrecorded evidence
        never blocks), but analysis continues in memory. The observer still
        stamps its wire clock there, so a fresh ttlMs declaration stays known
        instead of collapsing to unknown and hiding fabricated calls."""
        with mock.patch('glassport.tap.SessionLog.record', return_value=None):
            self.proxy()
            ChangingUpstream.ttl = 60_000
            self.handshake()
            self.quiesce()
            with self.observer._lock:
                surfaces = [c.builder.state.surface
                            for c in self.observer._contexts.values()]
        self.assertIn(frozenset({'search'}), surfaces)

if __name__ == '__main__':
    unittest.main()
