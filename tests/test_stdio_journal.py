"""Stdio write receipts, observer ordering, and transport-independent evidence."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from glassport import bundle, tap


class Sink(io.BytesIO):
    def close(self):
        pass


def line(frame):
    return (json.dumps(frame) + '\n').encode()


class TestStdioReceipts(unittest.TestCase):
    def test_header_epoch_is_unique_opaque_and_stdio_only(self):
        one = tap.build_session_header(transport='stdio', mode='wrap')
        two = tap.build_session_header(transport='stdio', mode='wrap')
        self.assertRegex(one['epoch'], r'^[0-9a-f]{32}$')
        self.assertNotEqual(one['epoch'], two['epoch'])
        self.assertNotIn('epoch', tap.build_session_header(transport='http', mode='gate'))

    def test_exact_legacy_serialization_and_digest(self):
        frames = [b'\n', b'bad\xff\r\n', line({'id': 1, 'method': 'tools/list'}),
                  b'{"id":2,"result":"\\ud800"}\n', b'[1,2]\n']
        with tempfile.TemporaryDirectory() as tmp, patch('glassport.tap._now_iso', return_value='fixed'):
            path = Path(tmp) / 'wire.jsonl'
            log = tap.SessionLog(path)
            expected = b''
            for seq, raw in enumerate(frames, 1):
                entry, text = tap.build_session_entry('c2s', raw, seq=seq)
                receipt = log.record_with_digest('c2s', raw)
                self.assertEqual(receipt[0], entry)
                self.assertEqual(receipt[1], hashlib.sha256((text+'\n').encode()).hexdigest())
                expected += (text+'\n').encode()
            log.close()
            self.assertEqual(path.read_bytes(), expected)

    def test_two_sessions_bundle_and_old_no_epoch_still_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = []
            for index in range(2):
                path = root / f'{index}.jsonl'
                log = tap.open_session_log(path)
                log.record('c2s', line({'id': 1, 'method': 'tools/list'}))
                log.write_metrics()
                log.close()
                paths.append(path)
            manifest = bundle.build_bundle(paths, None, None, root / 'new')
            self.assertEqual(len({e['epoch'] for e in manifest['evidence']['epochs']}), 2)
            header = tap.build_session_header(transport='stdio', mode='wrap')
            header.pop('epoch')
            old = root / 'old.jsonl'
            log = tap.SessionLog(old, header)
            log.record('c2s', line({'id': 1, 'method': 'tools/list'}))
            log.write_metrics()
            log.close()
            manifest = bundle.build_bundle([old], None, None, root / 'old-bundle')
            self.assertEqual(manifest['evidence']['epochs'][0]['epoch'], 'stdio')
            self.assertEqual(bundle.verify_exit_code(bundle.verify_bundle(root / 'old-bundle')), 2)
