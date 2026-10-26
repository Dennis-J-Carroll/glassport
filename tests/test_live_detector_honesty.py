"""Live findings must not change stdio or HTTP forwarding decisions."""
from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest

from glassport import detectors, tap
from glassport.adapters.mcp_session import from_mcp_session_file
from tests.test_http_stateless_scopes import ScopeCase, StatelessUpstream
from tests.test_public_gate import _Sink, _line


class TestStdioSurfaceMutation(unittest.TestCase):
    def test_description_change_is_finding_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'stdio.jsonl'
            log = tap.open_session_log(path, transport='stdio', mode='gate')
            gate, upstream, downstream = tap.Gate(), _Sink(), _Sink()

            def send(direction, frame):
                tap.pump(io.BytesIO(_line(frame)),
                         upstream if direction == 'c2s' else downstream,
                         log, direction, gate=gate, client_write=downstream.write)

            for rid, description in ((1, 'first'), (2, 'second')):
                send('c2s', {'jsonrpc': '2.0', 'id': rid, 'method': 'tools/list'})
                send('s2c', {'jsonrpc': '2.0', 'id': rid, 'result': {
                    'tools': [{'name': 'search', 'description': description}]}})
            send('c2s', {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                         'params': {'name': 'search', 'arguments': {}}})
            log.close()
            calls = [json.loads(line) for line in upstream.getvalue().splitlines()
                     if json.loads(line).get('method') == 'tools/call']
            self.assertEqual(len(calls), 1)
            trace = from_mcp_session_file(path)
            findings = detectors.annotate(trace)
            self.assertEqual(len([a for a in findings
                                  if a.subcategory == 'surface_mutation']), 1)
            self.assertNotIn('detector_error', [a.subcategory for a in findings])


class TestHTTPStatelessSurfaceMutation(ScopeCase):
    def _exercise(self, strict: bool):
        self.proxy(strict=strict)
        StatelessUpstream.lists[('Bearer A', None)] = [
            {'name': 'search', 'description': 'first',
             'inputSchema': {'type': 'object'}}]
        self.lists(1)
        StatelessUpstream.lists[('Bearer A', None)][0]['description'] = 'second'
        self.lists(2)
        self.assertEqual(self.call('search', 3), ('forwarded', 1))
        self.assertEqual(self.call('ghost', 4), ('blocked', 0))
        self.observer.close()
        findings = []
        for path in (self.root / 'wire').glob('*.jsonl'):
            trace = from_mcp_session_file(path)
            findings.extend(detectors.annotate(trace))
        mutations = [a for a in findings if a.subcategory == 'surface_mutation']
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0].metadata['fields_changed'], ['description'])
        self.assertEqual(mutations[0].severity, 2)

    def test_default_gate_forwards_after_same_name_change(self):
        self._exercise(False)

    def test_strict_gate_forwards_after_same_name_change(self):
        self._exercise(True)


if __name__ == '__main__':
    unittest.main()
