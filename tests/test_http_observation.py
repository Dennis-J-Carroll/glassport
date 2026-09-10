"""Opt-in observation preserves HTTP bytes and observes before delivery."""
import base64
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from glassport.adapters.mcp_http import _observe_json_response, _observe_sse, run_http_tap
from glassport.http_sessions import HTTPObserver
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.incremental import replay
from tests.test_http_sessions import wire
from tests.test_incremental_detectors import semantic_findings


class TestObservedFraming(unittest.TestCase):
    def test_empty_sse_event_type_is_a_message(self):
        lease, writer = mock.Mock(), io.BytesIO()
        _observe_sse(io.BytesIO(b'event:\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'),
                     writer, lease, 1024)
        self.assertFalse(lease.record.call_args.kwargs['transport_only'])

    def test_json_fold_precedes_write_and_failed_analysis_still_forwards(self):
        events = []
        lease = mock.Mock()
        lease.record.side_effect = lambda *a, **k: events.append('observed')
        class Writer(io.BytesIO):
            def write(self, data):
                events.append('written')
                return super().write(data)
        writer = Writer()
        payload = wire(id=1, result={'tools': []})
        _observe_json_response(io.BytesIO(payload), writer, lease, 1024, expected=len(payload))
        self.assertEqual(events, ['observed', 'written'])
        self.assertEqual(writer.getvalue(), payload)
        lease.record.side_effect = OSError('analysis failed')
        lease.loss.side_effect = OSError('loss recording failed')
        writer = io.BytesIO()
        _observe_json_response(io.BytesIO(payload), writer, lease, 1024)
        self.assertEqual(writer.getvalue(), payload)

    def test_json_truncation_and_read_failure_preserve_received_prefix(self):
        for source, expected in ((io.BytesIO(b'{}'), 10),
                                 (mock.Mock(read=mock.Mock(side_effect=[b'{', OSError()])), None)):
            lease, writer = mock.Mock(), io.BytesIO()
            try:
                _observe_json_response(source, writer, lease, 1024, expected=expected)
            except OSError:
                pass
            self.assertTrue(writer.getvalue().startswith(b'{'))
            self.assertTrue(lease.record.call_args.kwargs['incomplete'])
        writer, lease = io.BytesIO(), mock.Mock()
        source = mock.Mock(read=mock.Mock(side_effect=http.client.IncompleteRead(b'prefix')))
        with self.assertRaises(http.client.IncompleteRead):
            _observe_json_response(source, writer, lease, 1024)
        self.assertEqual(writer.getvalue(), b'prefix')

    def test_oversized_json_and_sse_stay_byte_exact_and_bounded(self):
        payload = b'x' * 10000
        lease, writer = mock.Mock(), io.BytesIO()
        _observe_json_response(io.BytesIO(payload), writer, lease, 32)
        self.assertEqual(writer.getvalue(), payload)
        self.assertLessEqual(len(lease.record.call_args.args[1]), 32)
        sse = b'data: ' + payload + b'\r\n\r\n' + b'data: {}\r\n\r\n'
        lease, writer = mock.Mock(), io.BytesIO()
        _observe_sse(io.BytesIO(sse), writer, lease, 32)
        self.assertEqual(writer.getvalue(), sse)
        self.assertTrue(any(c.kwargs.get('incomplete') for c in lease.record.call_args_list))
        self.assertTrue(all(len(c.args[1]) <= 32 for c in lease.record.call_args_list))

    def test_sse_split_terminators_bom_and_comments_preserve_raw_bytes(self):
        payload = b'\xef\xbb\xbf: hello\r\n\r\nid: one\rdata: {"jsonrpc":"2.0","method":"x"}\r\r'
        chunks = [payload[i:i+1] for i in range(len(payload))] + [b'']
        resp, writer, lease = mock.Mock(), io.BytesIO(), mock.Mock()
        resp.read1.side_effect = chunks
        _observe_sse(resp, writer, lease, 1024)
        self.assertEqual(writer.getvalue(), payload)
        raw = b''.join(c.kwargs['wire_bytes'] for c in lease.record.call_args_list)
        self.assertEqual(raw, payload)
        self.assertTrue(lease.record.call_args_list[0].kwargs['transport_only'])
        self.assertEqual(lease.record.call_args.kwargs['event_id'], 'one')


class TestObservedHTTP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.seen = []
        self.observer = HTTPObserver(Path(self.tmp.name), on_observation=self.seen.append)
        self.addCleanup(self.observer.close)
        self.finish_stream = threading.Event()
        self.addCleanup(self.finish_stream.set)
        finish_stream = self.finish_stream
        class Remote(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args): pass
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                method = request['method']
                rid = request.get('id')
                sid = self.headers.get('Mcp-Session-Id')
                if method == 'initialize':
                    sid = request['params']['clientInfo']['name']
                    result = {'protocolVersion':'2025-11-25', 'capabilities':{},
                              'serverInfo':{'name':'fixture','version':'1'}}
                elif method == 'tools/list':
                    result = {'tools':[{'name':'tool_' + sid}]}
                else:
                    result = {'content':[]}
                payload = wire(id=rid, result=result)
                sse = self.headers.get('X-Test-SSE') == '1'
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream' if sse else 'application/json')
                if method == 'initialize': self.send_header('Mcp-Session-Id', sid)
                if sse:
                    self.send_header('Connection', 'close'); self.close_connection = True
                else:
                    self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(b'id: list\ndata: ' + payload + b'\n\n' if sse else payload)
                self.wfile.flush()
                if sse: finish_stream.wait(5)
        self.remote = ThreadingHTTPServer(('127.0.0.1', 0), Remote)
        self.remote_thread = threading.Thread(target=self.remote.serve_forever, daemon=True)
        self.remote_thread.start()
        self.addCleanup(self.remote.server_close)
        self.addCleanup(self.remote.shutdown)
        ready, box = threading.Event(), []
        self.proxy_thread = threading.Thread(target=run_http_tap,
            args=(f'http://127.0.0.1:{self.remote.server_port}/mcp', Path(self.tmp.name)),
            kwargs={'ready':ready, 'server_box':box, 'observer':self.observer}, daemon=True)
        self.proxy_thread.start()
        self.assertTrue(ready.wait(5))
        self.proxy = box[0]
        self.addCleanup(self.stop_proxy)

    def stop_proxy(self):
        self.finish_stream.set()
        self.proxy.shutdown()
        self.proxy_thread.join(5)
        self.assertFalse(self.proxy_thread.is_alive())
        self.assertEqual(self.proxy.socket.fileno(), -1)

    def request(self, frame, token=None, *, sse=False):
        conn = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port, timeout=2)
        headers = {'Content-Type':'application/json', 'Accept':'application/json, text/event-stream'}
        if token: headers['Mcp-Session-Id'] = token
        if sse: headers['X-Test-SSE'] = '1'
        conn.request('POST', '/mcp', body=frame, headers=headers)
        return conn, conn.getresponse()

    def initialize(self, name):
        conn, resp = self.request(wire(id=1, method='initialize', params={'clientInfo':{'name':name}}))
        self.assertEqual(resp.getheader('Mcp-Session-Id'), name)
        resp.read(); conn.close()

    def test_two_sessions_reused_ids_and_complete_wire_replay(self):
        for name in ('alpha', 'beta'): self.initialize(name)
        for name in ('alpha', 'beta'):
            conn, resp = self.request(wire(id=2, method='tools/list'), name)
            self.assertEqual(json.loads(resp.read())['result']['tools'], [{'name':'tool_' + name}])
            conn.close()
        for name in ('alpha', 'beta'):
            conn, resp = self.request(wire(id=3, method='tools/call', params={'name':'tool_alpha'}), name)
            self.assertEqual(resp.status, 200); resp.read(); conn.close()
        findings = [ann for o in self.seen for ann in o.annotations if ann.subcategory == 'fabricated_tool_call']
        self.assertEqual(len(findings), 1)
        captures = list(Path(self.tmp.name).glob('*.jsonl'))
        self.assertEqual(len(captures), 2)
        for path in captures:
            trace = from_mcp_session_file(path)
            live = [o for o in self.seen if o.epoch == path.stem]
            self.assertEqual(semantic_findings([o.event for o in live if o.event],
                [a for o in live for a in o.annotations]), semantic_findings(trace.events, replay(trace)))
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertTrue(all('wire_b64' in row for row in rows))
            self.assertTrue(all(base64.b64decode(row['wire_b64']) for row in rows))

    def test_open_sse_delivers_promptly_with_declaration_already_folded(self):
        self.initialize('alpha')
        conn, resp = self.request(wire(id=2, method='tools/list'), 'alpha', sse=True)
        try:
            self.assertEqual(resp.readline(), b'id: list\n')
            data = resp.readline()
            self.assertTrue(data.startswith(b'data: '))
            self.assertTrue(any(c.builder.state.surface == {'tool_alpha'}
                                for c in self.observer._contexts.values()))
        finally:
            self.finish_stream.set(); resp.read(); conn.close()
