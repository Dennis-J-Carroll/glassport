"""Ordered background analysis, bounded loss and shutdown evidence."""
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from glassport import bundle, stdio_sessions, tap
from glassport.decision_journal import DecisionJournal
from tests.test_stdio_journal import line


class WorkerCapture:
    """Exercise the worker independently of production pump wiring."""
    def __init__(self, root):
        self.root = root
        self.path = root / 'wire.jsonl'
        self.log = tap.open_session_log(self.path)
        self.observer = stdio_sessions.StdioObserver(self.log)
        self.journal = DecisionJournal(root / 'decisions', self.observer)
        self.worker = stdio_sessions.StdioAnalysisWorker(self.observer, self.journal)

    def send(self, direction='c2s', raw=None):
        raw = raw or line({'id': 1, 'method': 'ping'})
        entry, digest = self.log.record_with_digest(direction, raw)
        self.worker.entry(entry, digest, None, direction, len(raw))
        if direction == 'c2s':
            self.worker.delivery(entry['seq'], 'sent', 'stdio_written', None)

    def close(self):
        self.worker.finish()
        self.journal.close()
        self.log.write_metrics()
        self.log.close()

    def verify(self):
        bundle.build_bundle([self.path], None, None, self.root / 'bundle')
        return bundle.verify_bundle(self.root / 'bundle')


class TestStdioWorker(unittest.TestCase):
    def test_normal_drain_and_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            for rid in range(30):
                capture.send(raw=line({'id': rid, 'method': 'ping'}))
            capture.close()
            self.assertEqual(bundle.verify_exit_code(capture.verify()), 0)
            import json
            records = [json.loads(raw) for raw in capture.journal.path_for(capture.observer.epoch).read_bytes().splitlines()]
            intents = [r for r in records if r['kind'] == 'intent']
            deliveries = [r for r in records if r['kind'] == 'delivery']
            self.assertEqual([r['wire_seq'] for r in intents], list(range(1, 31)))
            self.assertEqual([r['intent'] for r in deliveries], [r['n'] for r in intents])
            self.assertTrue(all(i['n'] < d['n'] for i, d in zip(intents, deliveries)))

    def test_overflow_preserves_real_links_and_records_sticky_fault(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            with patch.object(stdio_sessions, 'MAX_QUEUED_LINE_BYTES', 1):
                capture.send()
            capture.send(raw=line({'id': 2, 'method': 'ping'}))
            capture.close()
            result = capture.verify()
            self.assertEqual(bundle.verify_exit_code(result), 2, result)
            self.assertEqual(result['delivery_evidence_present']['status'], 'present')
            import json
            records = [json.loads(raw) for raw in capture.journal.path_for(capture.observer.epoch).read_bytes().splitlines()]
            intents = [r for r in records if r['kind'] == 'intent']
            self.assertEqual(len(intents), 2)
            self.assertTrue(all(r['faults'][0]['error_type'] == 'queue_overflow' for r in intents))
            self.assertTrue(all(r['wire_entry_sha256'] for r in intents))

    def test_final_server_overflow_cannot_certify_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            capture.send()
            with patch.object(stdio_sessions, 'MAX_QUEUED_LINE_BYTES', 1):
                capture.send('s2c', line({'id': 1, 'result': {}}))
            capture.close()
            result = capture.verify()
            self.assertEqual(bundle.verify_exit_code(result), 2, result)
            self.assertIn('journal_truncated', result['analysis_reproduced']['epochs'][0]['reasons'])

    def test_drain_timeout_prevents_late_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            entered, release = threading.Event(), threading.Event()

            def stalled(*args):
                entered.set()
                release.wait(5)
                return None

            with patch.object(capture.worker.builder, 'feed', side_effect=stalled):
                capture.send()
                self.assertTrue(entered.wait(2))
                self.assertFalse(capture.worker.finish(timeout=.01))
                path = capture.journal.path_for(capture.observer.epoch)
                before = path.read_bytes()
                release.set()
                capture.worker.thread.join(2)
                self.assertEqual(path.read_bytes(), before)
            capture.close()
            result = capture.verify()
            self.assertEqual(bundle.verify_exit_code(result), 2, result)
            self.assertIn('journal_truncated', result['analysis_reproduced']['epochs'][0]['reasons'])

    def test_worker_death_and_later_enqueue(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            with patch.object(capture.worker, '_process', side_effect=SystemExit):
                capture.send()
                capture.worker.thread.join(2)
            self.assertTrue(capture.worker.dead.is_set())
            capture.send(raw=line({'id': 2, 'method': 'ping'}))
            self.assertFalse(capture.worker._queue)
            capture.close()
            self.assertEqual(bundle.verify_exit_code(capture.verify()), 2)

    def test_exception_does_not_kill_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            with patch.object(capture.worker.builder, 'feed', side_effect=RuntimeError):
                capture.send()
                self.assertTrue(capture.worker.wait_idle())
            self.assertFalse(capture.worker.dead.is_set())
            capture.send(raw=line({'id': 2, 'method': 'ping'}))
            capture.close()
            self.assertEqual(bundle.verify_exit_code(capture.verify()), 2)

    def test_timeout_after_intent_is_incomplete_not_contradicted(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            entered, release = threading.Event(), threading.Event()
            process = capture.worker._process

            def stall_delivery(item):
                if item[0] == 'delivery':
                    entered.set()
                    release.wait(5)
                process(item)

            with patch.object(capture.worker, '_process', side_effect=stall_delivery):
                capture.send()
                self.assertTrue(entered.wait(2))
                self.assertFalse(capture.worker.finish(timeout=.01))
                release.set()
                capture.worker.thread.join(2)
            capture.close()
            result = capture.verify()
            self.assertEqual(bundle.verify_exit_code(result), 2, result)
            self.assertIn('delivery_missing_truncated', result['delivery_evidence_present']['epochs'][0]['reasons'])

    def test_control_backlog_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = WorkerCapture(Path(tmp))
            self.addCleanup(capture.close)
            entered, release = threading.Event(), threading.Event()
            with patch.object(capture.worker.builder, 'feed',
                              side_effect=lambda *_: (entered.set(), release.wait(5), None)[-1]):
                capture.send()
                self.assertTrue(entered.wait(2))
                with patch.object(capture.journal, 'limits',
                                  type(capture.journal.limits)(max_records=2)):
                    for rid in range(10):
                        capture.send(raw=line({'id': rid, 'method': 'ping'}))
                self.assertTrue(capture.worker._abandoned.is_set())
                self.assertEqual(capture.worker.queued_bytes, 0)
                self.assertFalse(capture.worker._queue)
                release.set()
                capture.worker.thread.join(2)
            capture.close()
            self.assertEqual(bundle.verify_exit_code(capture.verify()), 2)
