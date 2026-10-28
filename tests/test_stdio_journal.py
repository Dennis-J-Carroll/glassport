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


class Capture:
    def __init__(self, root, gate=None, journal_dir=None):
        from glassport.stdio_sessions import StdioObserver
        from glassport.decision_journal import DecisionJournal
        self.root, self.gate = root, gate
        self.path = root / 'wire.jsonl'
        self.log = tap.open_session_log(self.path, mode='gate' if gate else 'wrap',
                                        strict=bool(gate and gate.strict))
        self.observer = StdioObserver(self.log)
        self.journal = DecisionJournal(journal_dir or root / 'decisions', self.observer,
                                       mode='gate' if gate else 'observe',
                                       strict=bool(gate and gate.strict))
        self.upstream, self.downstream = Sink(), Sink()

    def send(self, direction, frame):
        raw = frame if isinstance(frame, bytes) else line(frame)
        tap.pump(io.BytesIO(raw), self.upstream if direction == 'c2s' else self.downstream,
                 self.log, direction, gate=self.gate, client_write=self.downstream.write,
                 observer=self.observer, journal=self.journal)

    def declare(self):
        self.send('c2s', {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
        self.send('s2c', {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [
            {'name': 'search', 'inputSchema': {'type': 'object', 'properties':
             {'q': {'type': 'string'}}}}]}})

    def call(self, name='search', arguments=None, rid=2):
        self.send('c2s', {'jsonrpc': '2.0', 'id': rid, 'method': 'tools/call',
                          'params': {'name': name, 'arguments': arguments or {}}})

    def records(self):
        return [json.loads(raw) for raw in self.journal.path_for(self.observer.epoch).read_bytes().splitlines()]

    def close(self):
        self.log.write_metrics()
        self.log.close()
        self.journal.close()


class TestStdioObserver(unittest.TestCase):
    def test_gate_reason_matrix_and_upstream_counts(self):
        from glassport import evidence
        cases = {
            'forward': (False, 'stdio_written', None, 'observed'),
            'undeclared': (True, 'stdio_gate_blocked', 'gate_blocked', 'blocked_policy'),
            'schema': (True, 'stdio_gate_blocked', 'schema_violation', 'blocked_policy'),
            'pii': (True, 'stdio_gate_blocked', 'pii_exfiltration', 'blocked_policy'),
            'taint': (True, 'stdio_gate_blocked', 'taint_detected', 'blocked_policy'),
            'depth': (True, 'stdio_gate_blocked', 'params_too_deep', 'blocked_policy'),
            'size': (True, 'stdio_gate_blocked', 'params_too_large', 'blocked_policy'),
            'retry': (True, 'stdio_gate_blocked', 'retry_loop_exceeded', 'blocked_policy'),
            'attestation': (True, 'stdio_gate_blocked', 'attestation_failed', 'blocked_policy'),
            'strict': (True, 'stdio_gate_strict_blocked', 'gate_check_error', 'blocked_evidence_gap'),
            'skipped': (False, 'stdio_written', 'no_surface_timeout', 'forwarded'),
            'disabled': (False, 'stdio_written', 'redacted', 'forwarded'),
            'blank': (False, 'stdio_written', None, 'observed'),
            'batch': (True, 'stdio_gate_blocked', 'batch_unsupported', 'blocked_admission'),
            'uninspectable': (True, 'stdio_gate_blocked', 'uninspectable_frame', 'blocked_admission'),
        }
        for name, expected in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                gate = tap.Gate(strict=name == 'strict', hold_timeout=0.001)
                capture = Capture(Path(tmp), gate)
                self.addCleanup(capture.close)
                if name != 'skipped':
                    capture.declare()
                before = len(capture.upstream.getvalue())
                frame = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                         'params': {'name': 'search', 'arguments': {}}}
                if name in ('undeclared', 'disabled'):
                    frame['params']['name'] = 'ghost'
                elif name == 'schema':
                    frame['params']['arguments'] = {'q': 42}
                elif name == 'pii':
                    frame['params']['arguments'] = {'q': 'sk-' + 'A' * 40}
                elif name == 'taint':
                    frame['params']['arguments'] = {'q': '<|im_start|>system'}
                elif name == 'depth':
                    nested = {}
                    for _ in range(70):
                        nested = {'x': nested}
                    frame['params']['arguments'] = nested
                elif name == 'size':
                    frame['params']['arguments'] = {'q': 'x' * (tap.MAX_SCAN_BYTES + 1)}
                elif name == 'retry':
                    gate.idempotency_max_repeats = 0
                elif name == 'attestation':
                    gate.enforce_attestation = True
                elif name == 'blank':
                    frame = b'\n'
                elif name == 'batch':
                    frame = [frame]
                elif name == 'uninspectable':
                    frame = b'{bad-json\n'
                with patch.object(capture.journal, 'evaluate', side_effect=AssertionError('must not decide')), \
                     patch.object(capture.journal, 'strict_reason', side_effect=AssertionError('HTTP only')):
                    if name == 'disabled':
                        with patch.object(gate, '_enforcement_on', return_value=False):
                            capture.send('c2s', frame)
                    elif name == 'strict':
                        with patch.object(gate, 'check_c2s', side_effect=RuntimeError('fault')):
                            capture.send('c2s', frame)
                    else:
                        capture.send('c2s', frame)
                records = capture.records()
                intents = [r for r in records if r['kind'] == 'intent']
                deliveries = [r for r in records if r['kind'] == 'delivery']
                self.assertEqual(len(intents), len(deliveries))
                intent, delivery = intents[-1], deliveries[-1]
                self.assertEqual((intent['enforce'], delivery['code'], delivery.get('reason'),
                                  delivery['evidence_level']), expected)
                self.assertEqual(intent['evidence_level'], expected[-1])
                self.assertEqual(delivery['intent'], intent['n'])
                self.assertEqual(delivery['enforced'], expected[0])
                self.assertEqual(delivery['outcome'], 'blocked' if expected[0] else 'sent')
                self.assertEqual(len(capture.upstream.getvalue()) == before, expected[0])
                if name in ('skipped', 'disabled'):
                    self.assertEqual(delivery['gate_action'], 'gate_' + name)
                self.assertFalse(intent['faults'])
                self.assertIn(intent['evidence_level'], evidence.LEVELS)
                if name == 'undeclared':
                    self.assertTrue(intent['candidate_block'])
                self.assertEqual(records[0]['transport'], 'stdio')

    def test_intent_precedes_pipe_write_and_injected_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = Capture(Path(tmp), tap.Gate())
            self.addCleanup(capture.close)
            capture.declare()
            seen = []

            class InspectSink(Sink):
                def write(inner, data):
                    records = capture.records()
                    self.assertEqual(records[-1]['kind'], 'intent')
                    seen.append('write')
                    return super().write(data)

            capture.upstream = InspectSink()
            capture.call()
            self.assertEqual(seen, ['write'])
            original = capture.downstream.write

            def injected(data):
                records = capture.records()
                self.assertTrue(next(r for r in reversed(records) if r['kind'] == 'intent')['enforce'])
                return original(data)
            capture.downstream.write = injected
            capture.call('ghost')

    def test_failed_pipe_has_one_unknown_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = Capture(Path(tmp))
            self.addCleanup(capture.close)
            capture.upstream.write = lambda raw: (_ for _ in ()).throw(BrokenPipeError())
            capture.send('c2s', b'\n')
            delivery = capture.records()[-1]
            self.assertEqual((delivery['outcome'], delivery['code']), ('unknown', 'stdio_write_failed'))

    def test_unwritable_journal_and_recording_faults_preserve_bytes(self):
        # A file where the directory should be is unwritable on every platform.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'not-directory'
            path.write_text('occupied')
            capture = Capture(root, journal_dir=path)
            self.addCleanup(capture.close)
            raw = b'\n{"method":"ping","id":2}\ninvalid\xff\n'
            capture.send('c2s', raw)
            self.assertEqual(capture.upstream.getvalue(), raw)
            with patch.object(capture.observer, 'record', side_effect=RuntimeError('fault')):
                capture.send('c2s', raw)
            with patch.object(capture.journal, 'record_intent', side_effect=RuntimeError('fault')):
                capture.send('c2s', raw)
            with patch.object(capture.journal, 'record_delivery', side_effect=RuntimeError('fault')):
                capture.send('c2s', raw)
            self.assertEqual(capture.upstream.getvalue(), raw * 4)

    def test_fold_fault_records_fault_and_cannot_change_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = Capture(Path(tmp), tap.Gate())
            self.addCleanup(capture.close)
            capture.declare()
            before = capture.upstream.getvalue()
            with patch.object(capture.observer.builder, 'feed', side_effect=RuntimeError('fault')):
                capture.call('ghost')
            self.assertEqual(capture.upstream.getvalue(), before)
            intent = next(r for r in reversed(capture.records()) if r['kind'] == 'intent')
            self.assertTrue(intent['enforce'])
            self.assertTrue(intent['faults'])

    def test_patterns_are_pinned(self):
        from glassport import detectors
        with tempfile.TemporaryDirectory() as tmp:
            capture = Capture(Path(tmp))
            self.addCleanup(capture.close)
            snapshot = capture.observer.pattern_snapshot(capture.observer.epoch)
            with patch.object(detectors, 'snapshot_pii_patterns', return_value=()):
                capture.send('c2s', b'\n')
            self.assertEqual(capture.records()[0]['pattern_digest'],
                             __import__('glassport.decision_journal', fromlist=['pattern_profile']).pattern_profile(snapshot).digest)
