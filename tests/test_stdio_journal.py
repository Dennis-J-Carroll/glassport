"""Stdio write receipts, observer ordering, and transport-independent evidence."""
from __future__ import annotations

from contextlib import ExitStack
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
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
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
        self.observer.start(self.journal)
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
        self.observer.worker.wait_idle()
        return [json.loads(raw) for raw in self.journal.path_for(self.observer.epoch).read_bytes().splitlines()]

    def close(self):
        self.observer.finish()
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
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
                gate = tap.Gate(strict=name == 'strict', hold_timeout=0.001)
                capture = Capture(Path(tmp), gate)
                cleanup.callback(capture.close)
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
                    self.assertTrue(capture.observer.worker.wait_idle())
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

    def test_wire_precedes_pipe_write_and_injected_reply(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            capture = Capture(Path(tmp), tap.Gate())
            cleanup.callback(capture.close)
            capture.declare()
            seen = []

            class InspectSink(Sink):
                def write(inner, data):
                    records = [json.loads(raw) for raw in capture.path.read_bytes().splitlines()]
                    self.assertEqual(records[-1]['dir'], 'c2s')
                    seen.append('write')
                    return super().write(data)

            capture.upstream = InspectSink()
            capture.call()
            self.assertEqual(seen, ['write'])
            original = capture.downstream.write

            def injected(data):
                records = [json.loads(raw) for raw in capture.path.read_bytes().splitlines()]
                self.assertEqual(records[-1]['gate']['action'], 'blocked')
                return original(data)
            capture.downstream.write = injected
            capture.call('ghost')
            records = capture.records()
            intents = {r['n']: r for r in records if r['kind'] == 'intent'}
            for record in records:
                if record['kind'] == 'delivery':
                    self.assertIn(record['intent'], intents)
                    self.assertLess(record['intent'], record['n'])

    def test_failed_pipe_has_one_unknown_delivery(self):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            capture = Capture(Path(tmp))
            cleanup.callback(capture.close)
            capture.upstream.write = lambda raw: (_ for _ in ()).throw(BrokenPipeError())
            capture.send('c2s', b'\n')
            delivery = capture.records()[-1]
            self.assertEqual((delivery['outcome'], delivery['code']), ('unknown', 'stdio_write_failed'))

    def test_unwritable_journal_and_recording_faults_preserve_bytes(self):
        # A file where the directory should be is unwritable on every platform.
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            root = Path(tmp)
            path = root / 'not-directory'
            path.write_text('occupied')
            capture = Capture(root, journal_dir=path)
            cleanup.callback(capture.close)
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
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            capture = Capture(Path(tmp), tap.Gate())
            cleanup.callback(capture.close)
            capture.declare()
            before = capture.upstream.getvalue()
            with patch.object(capture.observer.builder, 'feed', side_effect=RuntimeError('fault')):
                capture.call('ghost')
                self.assertTrue(capture.observer.worker.wait_idle())
            self.assertEqual(capture.upstream.getvalue(), before)
            intent = next(r for r in reversed(capture.records()) if r['kind'] == 'intent')
            self.assertTrue(intent['enforce'])
            self.assertTrue(intent['faults'])

    def test_patterns_are_pinned(self):
        from glassport import detectors
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            capture = Capture(Path(tmp))
            cleanup.callback(capture.close)
            snapshot = capture.observer.pattern_snapshot(capture.observer.epoch)
            with patch.object(detectors, 'snapshot_pii_patterns', return_value=()):
                capture.send('c2s', b'\n')
            self.assertEqual(capture.records()[0]['pattern_digest'],
                             __import__('glassport.decision_journal', fromlist=['pattern_profile']).pattern_profile(snapshot).digest)


class TestStdioReplay(unittest.TestCase):
    def capture(self, root, *, pii=False, undeclared=False):
        capture = Capture(root, tap.Gate())
        capture.declare()
        capture.call('ghost' if undeclared else 'search',
                     {'q': 'sk-' + 'A' * 40} if pii else {})
        capture.close()
        return capture

    def test_clean_pii_and_undeclared_bundles(self):
        from glassport.decision_replay import verify_journal
        from tests.test_public_gate import assert_public_strings
        for scenario in ('clean', 'pii', 'undeclared'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
                root = Path(tmp)
                capture = self.capture(root, pii=scenario == 'pii', undeclared=scenario == 'undeclared')
                replay = verify_journal(capture.journal.path_for(capture.observer.epoch), capture.path)
                self.assertEqual(replay.status, 'equivalent', replay.as_dict())
                manifest = bundle.build_bundle([capture.path], None, None, root / 'bundle', redact=True)
                verdict = bundle.verify_bundle(root / 'bundle')
                self.assertEqual(bundle.verify_exit_code(verdict), 0, verdict)
                limits = [item for item in manifest['limits'] if item['code'] == 'stdio_gate_reasons_not_replayed']
                self.assertEqual(limits, [{'code': 'stdio_gate_reasons_not_replayed',
                                           'reasons': ['pii_exfiltration']}] if scenario == 'pii' else [])
                assert_public_strings(self, root / 'bundle/public')
                self.assertEqual(bundle.verify_exit_code(bundle.verify_bundle(root / 'bundle/public', public=True)), 2)

    def declaration_race(self, root, marker_kind='honest'):
        capture = Capture(root, tap.Gate())
        try:
            capture.declare()  # completed old surface: search only
            capture.send('c2s', {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'})
            check = capture.gate.check_c2s

            def decide_then_publish(raw):
                verdict = check(raw)
                self.assertEqual(verdict[0], 'block')
                self.assertEqual(verdict[2]['declared'], ['search'])
                # Deterministic interleaving: gate already decided, but the call
                # has not reached StdioObserver.record. No sleeps or scheduling bets.
                capture.send('s2c', {'jsonrpc': '2.0', 'id': 3, 'result': {
                    'tools': [{'name': 'search'}, {'name': 'ghost'}]}})
                action, response, marker = verdict
                if marker_kind == 'forged':
                    marker = {**marker, 'declared': ['never-declared']}
                elif marker_kind == 'self-contradicting':
                    marker = {**marker, 'declared': ['search', 'ghost']}
                return action, response, marker

            with patch.object(capture.gate, 'check_c2s', side_effect=decide_then_publish):
                capture.call('ghost', rid=4)
            last_intent = next(r for r in reversed(capture.records()) if r['kind'] == 'intent')
            self.assertTrue(last_intent['enforce'])
            self.assertFalse(last_intent['candidate_block'])
            self.assertEqual(capture.upstream.getvalue().count(b'"tools/call"'), 0)
        finally:
            capture.close()
        bundle.build_bundle([capture.path], None, None, root / 'bundle')
        return bundle.verify_bundle(root / 'bundle')

    def test_declaration_race_verifies_honest_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            verdict = self.declaration_race(Path(tmp))
            self.assertEqual(bundle.verify_exit_code(verdict), 0, verdict)
            self.assertEqual(verdict['analysis_reproduced']['status'], 'equivalent')

    def test_declaration_race_rejects_forged_and_self_contradicting_markers(self):
        for kind in ('forged', 'self-contradicting'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                verdict = self.declaration_race(Path(tmp), kind)
                self.assertEqual(bundle.verify_exit_code(verdict), 1, verdict)
                self.assertIn('stdio_undeclared_block_unproven', verdict['integrity']['reasons'])

    def test_historical_exclusion_requires_completed_prior_declaration(self):
        from dataclasses import asdict
        from glassport.session import SessionLimits
        profile = {'session_limits': asdict(SessionLimits())}
        request = {'id': 1, 'method': 'tools/list'}
        reply = {'id': 1, 'result': {'tools': [{'name': 'search'}]}}
        block = {'id': 4, 'method': 'tools/call', 'params': {'name': 'ghost'}}
        marker = {'action': 'blocked', 'tool': 'ghost', 'declared': ['search']}
        for scenario in ('complete', 'empty', 'partial', 'orphan', 'future',
                         'paginated', 'malformed', 'non-list', 'non-string'):
            with self.subTest(scenario=scenario):
                frames = [('c2s', request, None), ('s2c', reply, None)]
                gate_marker = marker
                if scenario == 'empty':
                    frames[1] = ('s2c', {'id': 1, 'result': {'tools': []}}, None)
                    gate_marker = {**marker, 'declared': []}
                elif scenario in ('partial', 'paginated'):
                    frames[1] = ('s2c', {'id': 1, 'result': {
                        'tools': [{'name': 'search'}], 'nextCursor': 'more'}}, None)
                    if scenario == 'paginated':
                        frames += [('c2s', {'id': 2, 'method': 'tools/list',
                                            'params': {'cursor': 'more'}}, None),
                                   ('s2c', {'id': 2, 'result': {'tools': []}}, None)]
                elif scenario == 'orphan':
                    frames[1] = ('s2c', {**reply, 'id': 99}, None)
                elif scenario == 'malformed':
                    frames[1] = ('s2c', {'id': 1, 'result': {'tools': 'search'}}, None)
                elif scenario == 'non-list':
                    gate_marker = {**marker, 'declared': 'search'}
                elif scenario == 'non-string':
                    gate_marker = {**marker, 'declared': [['search']]}
                blocked = ('c2s', block, gate_marker)
                frames = [blocked] + frames if scenario == 'future' else frames + [blocked]
                entries = [tap.build_session_entry(direction, line(frame), gate=gate, seq=i)[0]
                           for i, (direction, frame, gate) in enumerate(frames, 1)]
                proven = bundle._stdio_historical_exclusions(entries, profile)
                expected = {len(entries)} if scenario in ('complete', 'empty', 'paginated') else set()
                self.assertEqual(proven, expected)

    def test_quarantine_limit_covers_server_actions_without_intents(self):
        from glassport.limits import stdio_gate_reasons
        entries = [{'gate': {'action': action, 'reason': 'quarantine_scan_error'}}
                   for action in ('quarantined', 'quarantine_replacement', 'quarantine_withheld',
                                  'quarantine_dropped', 'quarantine_scan_error')]
        self.assertEqual(stdio_gate_reasons(entries), sorted({
            'quarantined', 'quarantine_replacement', 'quarantine_withheld',
            'quarantine_dropped', 'quarantine_scan_error'}))
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            root = Path(tmp)
            capture = Capture(root, tap.Gate(strict=True))
            capture.declare()
            before = len([r for r in capture.records() if r['kind'] == 'intent'])
            with patch.object(capture.gate, 'check_s2c', side_effect=RuntimeError('fault')):
                capture.send('s2c', {'id': 9, 'result': {}})
            self.assertEqual(len([r for r in capture.records() if r['kind'] == 'intent']), before)
            capture.close()
            manifest = bundle.build_bundle([capture.path], None, None, root / 'bundle')
            self.assertIn({'code': 'stdio_gate_reasons_not_replayed',
                           'reasons': ['quarantine_dropped', 'quarantine_scan_error']}, manifest['limits'])
            self.assertEqual(bundle.verify_exit_code(bundle.verify_bundle(root / 'bundle')), 0)

    def test_missing_intent_and_analysis_fault_cannot_certify_prefix(self):
        from glassport.decision_replay import verify_journal
        for scenario in ('missing', 'fault'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
                root = Path(tmp)
                capture = Capture(root)
                capture.declare()
                self.assertTrue(capture.observer.worker.wait_idle())
                if scenario == 'missing':
                    with patch.object(capture.journal, 'record_intent', return_value=None):
                        capture.call()
                        self.assertTrue(capture.observer.worker.wait_idle())
                else:
                    with patch.object(capture.observer.builder, 'feed', side_effect=RuntimeError('fault')):
                        capture.call()
                        self.assertTrue(capture.observer.worker.wait_idle())
                capture.close()
                result = verify_journal(capture.journal.path_for(capture.observer.epoch), capture.path)
                self.assertEqual(result.status, 'incomplete', result.as_dict())
                self.assertIn('stdio_intent_missing' if scenario == 'missing' else
                              'recorded_fault_not_re_executed', result.reasons)

    def test_tampering_and_undeclared_consistency(self):
        from glassport.decision_replay import verify_journal
        from glassport.decision_journal import GENESIS_SHA256
        for scenario in ('chain', 'wire', 'swapped', 'deleted-final', 'unproven', 'missing-limit'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
                root = Path(tmp)
                capture = self.capture(root, undeclared=True)
                journal = capture.journal.path_for(capture.observer.epoch)
                if scenario == 'unproven':
                    records = capture.records()
                    for record in records:
                        if record['kind'] == 'intent' and record['candidate_block']:
                            record['candidate_block'] = False
                    previous = GENESIS_SHA256
                    data = b''
                    for record in records:
                        record['prev_sha256'] = previous
                        raw = line(record)
                        previous = hashlib.sha256(raw).hexdigest()
                        data += raw
                    journal.write_bytes(data)
                out = root / 'bundle'
                manifest = bundle.build_bundle([capture.path], None, None, out)
                copied_journal = out / manifest['evidence']['epochs'][0]['journal']['path']
                copied_wire = out / manifest['evidence']['epochs'][0]['wire']['path']
                raw_lines = copied_journal.read_bytes().splitlines(keepends=True)
                if scenario == 'chain':
                    record = json.loads(raw_lines[1]); record['prev_sha256'] = '1' * 64
                    raw_lines[1] = line(record)
                    copied_journal.write_bytes(b''.join(raw_lines))
                elif scenario == 'swapped':
                    positions = [i for i, raw in enumerate(raw_lines) if json.loads(raw)['kind'] == 'intent']
                    a, b = positions[:2]
                    raw_lines[a], raw_lines[b] = raw_lines[b], raw_lines[a]
                    copied_journal.write_bytes(b''.join(raw_lines))
                elif scenario == 'wire':
                    copied_wire.write_bytes(copied_wire.read_bytes().replace(b'ghost', b'other'))
                elif scenario == 'deleted-final':
                    copied_journal.write_bytes(b''.join(raw_lines[:-1]))
                elif scenario == 'missing-limit':
                    manifest['limits'].append({'code': 'stdio_gate_reasons_not_replayed', 'reasons': ['redacted']})
                    (out / 'manifest.json').write_bytes(bundle.canonical_bytes(manifest))
                result = bundle.verify_bundle(out)
                self.assertEqual(bundle.verify_exit_code(result), 1, result)
                if scenario == 'unproven':
                    # The historical marker is honest, but rewriting the
                    # policy candidate still contradicts detector replay.
                    self.assertEqual(result['analysis_reproduced']['status'], 'divergent')
                if scenario == 'missing-limit':
                    self.assertIn('stdio_gate_limit_mismatch', result['integrity']['reasons'])
                if scenario in ('chain', 'swapped', 'wire'):
                    replay = verify_journal(copied_journal, copied_wire)
                    self.assertEqual(replay.status, 'divergent')
                    self.assertIn('wire_digest_mismatch' if scenario == 'wire' else
                                  'journal_chain_mismatch', replay.reasons)

    def test_concurrent_pumps_replay_in_wire_order(self):
        import threading
        from glassport.decision_replay import verify_journal
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            root = Path(tmp)
            capture = Capture(root, tap.Gate(idempotency_max_repeats=10000))
            capture.declare()
            start = threading.Barrier(2)

            def client():
                start.wait()
                for index in range(100):
                    capture.call('ghost' if index % 2 else 'search', {'q': str(index)}, index + 10)

            def server():
                start.wait()
                for index in range(100):
                    capture.send('s2c', {'jsonrpc': '2.0', 'method': 'notifications/message',
                                         'params': {'data': str(index)}})

            workers = [threading.Thread(target=client), threading.Thread(target=server)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(10)
                self.assertFalse(worker.is_alive())
            capture.close()
            result = verify_journal(capture.journal.path_for(capture.observer.epoch), capture.path)
            self.assertEqual(result.status, 'equivalent', result.as_dict())
            self.assertEqual(capture.upstream.getvalue().count(b'"tools/call"'), 50)
            bundle.build_bundle([capture.path], None, None, root / 'bundle')
            self.assertEqual(bundle.verify_exit_code(bundle.verify_bundle(root / 'bundle')), 0)

    def test_hostile_frames_are_total_and_cannot_veto_gate(self):
        hostile = [b'\xff\n', b'{"id":1,"method":[],"params":[]}\n',
                   b'{"id":[],"method":"tools/call","params":{"name":[]}}\n',
                   b'{"id":true,"method":"tools/call","params":null}\n',
                   b'{"id":3,"method":"tools/call","params":{"name":"\\ud800"}}\n',
                   b'[' * 1500 + b'0' + b']' * 1500 + b'\n']
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as cleanup:
            capture = Capture(Path(tmp), tap.Gate())
            capture.declare()
            for raw in hostile:
                capture.send('c2s', raw)
            capture.close()
            intents = [r for r in capture.records() if r['kind'] == 'intent']
            self.assertEqual(len(intents), len(hostile) + 1)
            for record in intents:
                if record['faults']:
                    self.assertTrue(record['enforce'], record)
            self.assertEqual(capture.upstream.getvalue().count(b'"tools/call"'), 0)


class TestStdioRunTap(unittest.TestCase):
    def test_wrap_passive_probe_passive_and_explicit_journal(self):
        import os
        import subprocess
        import sys
        for mode in ('wrap', 'probe', 'wrap-journal', 'gate'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                payload = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n\n'
                code = """
from pathlib import Path
import sys
from unittest.mock import patch
from glassport import tap
from glassport.incremental import DetectorEngine
mode, directory = sys.argv[1:]
argv = ['gate' if mode == 'gate' else 'wrap', '--log-dir', directory]
if mode == 'wrap-journal':
    argv += ['--journal']
argv += ['--', sys.executable, '-c',
         'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.stdout.buffer.flush()']
with patch.object(DetectorEngine, 'on_event', autospec=True,
                  side_effect=DetectorEngine.on_event) as detector:
    original_exit = tap.os._exit
    def checked_exit(rc):
        assert (detector.call_count > 0) == (mode in ('gate', 'wrap-journal')), detector.call_count
        original_exit(rc)
    with patch.object(tap.os, '_exit', side_effect=checked_exit):
        rc = tap.main(argv)
sys.exit(rc)
"""
                env = dict(os.environ, PYTHONPATH=str(Path(tap.__file__).parents[1]))
                env.pop('GLASSPORT_INTERNAL_PROBE', None)
                if mode == 'probe':
                    env['GLASSPORT_INTERNAL_PROBE'] = '1'
                result = subprocess.run([sys.executable, '-c', code, mode, str(root)],
                                        input=payload, capture_output=True, timeout=15, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, payload)
                enabled = mode in ('gate', 'wrap-journal')
                self.assertEqual(len(list((root / 'decisions').glob('*.jsonl'))), int(enabled))
                if not enabled:
                    self.assertFalse((root / 'decisions').exists())
                bundle.build_bundle(list(root.glob('*.jsonl')), None, None, root / 'bundle')
                verdict = bundle.verify_bundle(root / 'bundle')
                self.assertEqual(bundle.verify_exit_code(verdict), 0 if enabled else 2, verdict)
                if not enabled:
                    self.assertIn('no_journal_for_path', verdict['analysis_reproduced']['epochs'][0]['reasons'])

    def test_passive_wrap_logs_only_after_successful_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = tap.open_session_log(Path(tmp) / 'wire.jsonl')
            try:
                for direction in ('c2s', 's2c'):
                    sink = Sink()
                    sink.write = lambda raw: (_ for _ in ()).throw(BrokenPipeError())
                    with patch.object(log, 'record', wraps=log.record) as record:
                        tap.pump(io.BytesIO(b'hello\n'), sink, log, direction)
                        record.assert_not_called()
            finally:
                log.close()

    def test_journal_flag_parsing(self):
        for flags in (['--journal', '--log-dir', 'capture'],
                      ['--log-dir', 'capture', '--journal']):
            with patch.object(tap, 'run_tap', return_value=0) as run, \
                 patch.object(tap.shutil, 'which', return_value='/server'):
                self.assertEqual(tap.main(['wrap'] + flags + ['--', 'server']), 0)
                self.assertTrue(run.call_args.kwargs['journal_enabled'])
        for argv in (['wrap', '--journal', '--journal', '--', 'server'],
                     ['gate', '--journal', '--', 'server'],
                     ['wrap', '--journal', '--transport', 'http', '--url', 'https://example.test']):
            with patch.object(tap, 'run_tap') as run:
                self.assertEqual(tap.main(argv), 2)
                run.assert_not_called()
