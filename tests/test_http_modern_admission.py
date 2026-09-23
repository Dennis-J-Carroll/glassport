"""Gate-mode admission for 2026-07-28 Streamable HTTP requests (plan S1).

A modern POST mirrors body fields into headers. Anything that routes or
decides on one copy while upstream executes the other is a parser
differential, so gate mode refuses any disagreement before connecting
upstream. The operator declares the endpoint's era, so an agent cannot
dodge modern checks by labelling a request as legacy.
"""
import base64
import contextlib
import io
import json
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

from glassport import decision_journal as dj
from glassport import tap
from glassport.adapters.mcp_http import run_http_tap
from glassport.http_sessions import HTTPObserver
from tests.test_http_gate import GateCase

MODERN = '2026-07-28'
META_KEY = 'io.modelcontextprotocol/protocolVersion'


def b64(value):
    return '=?base64?' + base64.b64encode(value.encode()).decode() + '?='


class ModernCase(GateCase):
    def proxy(self, mode=dj.MODE_GATE, remote=None, limits=None, era='auto'):
        remote = remote or self.upstream()
        self.observer = HTTPObserver(self.root / 'wire', limits=limits)
        self.journal = dj.DecisionJournal(self.root / 'decisions', self.observer, mode=mode)
        ready, box = threading.Event(), []
        threading.Thread(
            target=run_http_tap, args=(remote, self.root / 'wire'),
            kwargs={'ready': ready, 'server_box': box, 'observer': self.observer,
                    'journal': self.journal, 'endpoint_era': era},
            daemon=True).start()
        self.assertTrue(ready.wait(5), 'proxy did not bind')
        self.addCleanup(self.journal.close)
        self.addCleanup(self.observer.close)
        self.addCleanup(box[0].shutdown)
        self.url = f'http://127.0.0.1:{box[0].server_address[1]}/mcp'
        return self.url

    def frame(self, method='tools/call', name='search', rid=5, meta=MODERN):
        params = {'name': name, 'arguments': {}} if method == 'tools/call' else {}
        if meta is not None:
            params['_meta'] = {META_KEY: meta,
                               'io.modelcontextprotocol/clientCapabilities': {}}
        frame = {'jsonrpc': '2.0', 'method': method, 'params': params}
        if rid is not None:
            frame['id'] = rid
        return frame

    def headers(self, version=MODERN, method='tools/call', name='search'):
        out = []
        if version is not None:
            out.append(('MCP-Protocol-Version', version))
        if method is not None:
            out.append(('Mcp-Method', method))
        if name is not None:
            out.append(('Mcp-Name', name))
        return out

    def send(self, frame, headers):
        # http.client, not urllib: urllib keeps headers in a dict and would
        # silently collapse a duplicated header the test means to send.
        import http.client
        data = json.dumps(frame).encode()
        host, port = self.url.split('/')[2].rsplit(':', 1)
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        conn.putrequest('POST', '/mcp')
        for key, value in [('Content-Type', 'application/json'),
                           ('Accept', 'application/json, text/event-stream'),
                           ('Content-Length', str(len(data)))] + list(headers):
            conn.putheader(key, value)
        conn.endheaders(data)
        before = len(self.upstream_calls())
        resp = conn.getresponse()
        status, body = resp.status, resp.read()
        conn.close()
        self.quiesce()
        return status, body, len(self.upstream_calls()) - before

    def assert_refused(self, frame, headers, code):
        status, body, reached = self.send(frame, headers)
        self.assertEqual((status, reached), (400, 0), body)
        error = json.loads(body)['error']
        self.assertEqual(error['code'], code)
        return json.loads(body), error


class TestModernHeaderBodyAgreement(ModernCase):
    def setUp(self):
        super().setUp()
        self.proxy()

    def test_consistent_modern_call_is_forwarded(self):
        status, _, reached = self.send(self.frame(), self.headers())
        self.assertEqual((status, reached), (200, 1))

    def test_mcp_name_must_match_the_body(self):
        self.assert_refused(self.frame(name='nope'), self.headers(name='search'), -32020)

    def test_mcp_name_is_required_for_tools_call(self):
        self.assert_refused(self.frame(), self.headers(name=None), -32020)

    def test_base64_mcp_name_is_decoded_before_comparing(self):
        status, _, reached = self.send(self.frame(name='search'),
                                       self.headers(name=b64('search')))
        self.assertEqual((status, reached), (200, 1))
        self.assert_refused(self.frame(name='nope'), self.headers(name=b64('search')), -32020)

    def test_invalid_base64_or_utf8_is_refused(self):
        for bad in ('=?base64?not base64!?=', '=?base64?' +
                    base64.b64encode(b'\xff\xfe').decode() + '?='):
            with self.subTest(value=bad):
                self.assert_refused(self.frame(), self.headers(name=bad), -32020)

    def test_sentinel_markers_are_case_sensitive(self):
        # "=?BASE64?...?=" is not the sentinel: compared literally, it
        # cannot match the body name.
        upper = '=?BASE64?' + base64.b64encode(b'search').decode() + '?='
        self.assert_refused(self.frame(), self.headers(name=upper), -32020)

    def test_mcp_method_must_be_present_and_match(self):
        self.assert_refused(self.frame(), self.headers(method=None), -32020)
        self.assert_refused(self.frame(), self.headers(method='tools/list'), -32020)

    def test_meta_version_must_match_the_header(self):
        self.assert_refused(self.frame(meta='2025-11-25'), self.headers(), -32020)
        self.assert_refused(self.frame(meta=None), self.headers(), -32020)

    def test_duplicate_mirrored_headers_are_refused(self):
        headers = self.headers() + [('Mcp-Name', 'search')]
        self.assert_refused(self.frame(), headers, -32020)

    def test_refusal_echoes_a_valid_id_and_no_request_text(self):
        body, error = self.assert_refused(self.frame(name='secret_name', rid='r-1'),
                                          self.headers(name='search'), -32020)
        self.assertEqual(body['id'], 'r-1')
        self.assertNotIn('secret_name', json.dumps(body))

    def test_notifications_are_exempt_from_mirrored_headers(self):
        status, _, reached = self.send(
            self.frame(method='notifications/progress', rid=None),
            self.headers(method=None, name=None))
        self.assertEqual((status, reached), (202, 1))


class TestVersionClaims(ModernCase):
    def test_unknown_version_is_refused_in_every_era(self):
        for era in ('auto', 'legacy', 'modern'):
            with self.subTest(era=era):
                self.setUp()
                self.proxy(era=era)
                body, error = self.assert_refused(
                    self.frame(meta='2099-01-01'), self.headers(version='2099-01-01'), -32022)
                self.assertEqual(MODERN in error['data']['supported'], era != 'legacy')
                self.assertEqual(error['data']['requested'], '2099-01-01')

    def test_unsafe_requested_version_is_not_echoed(self):
        self.proxy()
        hostile = 'x<script>' + 'a' * 80
        _, error = self.assert_refused(self.frame(meta=hostile),
                                       self.headers(version=hostile), -32022)
        self.assertNotIn('script', error['data']['requested'])

    def test_body_version_claim_with_legacy_or_absent_header_is_refused(self):
        """Mixed era claims are the header/body differential again."""
        self.proxy()
        self.assert_refused(self.frame(), self.headers(version=None), -32020)
        self.assert_refused(self.frame(), self.headers(version='2025-11-25'), -32020)

    def test_modern_era_refuses_legacy_or_missing_version(self):
        self.proxy(era='modern')
        legacy = self.frame(meta=None)
        self.assert_refused(legacy, self.headers(version=None), -32022)
        self.assert_refused(legacy, self.headers(version='2025-11-25'), -32022)

    def test_legacy_era_refuses_modern_requests(self):
        self.proxy(era='legacy')
        self.assert_refused(self.frame(), self.headers(), -32022)

    def test_auto_era_keeps_legacy_traffic_on_the_legacy_path(self):
        self.proxy()
        status, _, reached = self.send(self.frame(meta=None),
                                       self.headers(version='2025-11-25', method=None, name=None))
        self.assertEqual((status, reached), (200, 1))
        status, _, reached = self.send(self.frame(meta=None), [])
        self.assertEqual((status, reached), (200, 1))

    def test_observe_mode_checks_nothing(self):
        self.proxy(mode=dj.MODE_OBSERVE, era='modern')
        status, _, reached = self.send(self.frame(name='nope'), self.headers(name='search'))
        self.assertEqual((status, reached), (200, 1))


class TestEndpointEraCLI(unittest.TestCase):
    def run_main(self, args):
        seen = {}

        def fake(remote, log_dir, **kw):
            seen.update(kw)
            return 0
        with mock.patch.object(tap, '_run_http_gate', fake), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = tap.main(args)
        return code, seen, err.getvalue()

    def test_gate_accepts_each_era(self):
        for era in ('auto', 'legacy', 'modern'):
            with self.subTest(era=era):
                code, seen, _ = self.run_main(
                    ['gate', '--transport', 'http', '--url', 'http://127.0.0.1:1/mcp',
                     '--endpoint-era', era])
                self.assertEqual((code, seen.get('endpoint_era')), (0, era))

    def test_default_era_is_auto(self):
        code, seen, _ = self.run_main(
            ['gate', '--transport', 'http', '--url', 'http://127.0.0.1:1/mcp'])
        self.assertEqual((code, seen.get('endpoint_era')), (0, 'auto'))

    def test_bad_era_and_stray_arguments_are_usage_errors(self):
        for args in (['--endpoint-era', 'future'], ['--endpoint-era'],
                     ['--endpont-era', 'modern']):
            with self.subTest(args=args):
                code, seen, err = self.run_main(
                    ['gate', '--transport', 'http', '--url', 'http://127.0.0.1:1/mcp'] + args)
                self.assertEqual(code, 2)
                self.assertEqual(seen, {})

    def test_era_is_gate_only(self):
        with mock.patch('glassport.adapters.mcp_http.run_http_tap') as run, \
                contextlib.redirect_stderr(io.StringIO()):
            code = tap.main(['wrap', '--transport', 'http', '--url',
                             'http://127.0.0.1:1/mcp', '--endpoint-era', 'modern'])
        self.assertEqual(code, 2)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
