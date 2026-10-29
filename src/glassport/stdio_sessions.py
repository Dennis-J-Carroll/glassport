"""Best-effort stdio evidence observer. Never owns a transport verdict."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import threading

from glassport import detectors
from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.http_sessions import Observation
from glassport.incremental import DetectorEngine, default_detectors
from glassport.session import SessionLimits
from glassport.tap import build_session_entry


@dataclass(frozen=True)
class StdioObservation(Observation):
    gate: object = None
    analysis_fault: str | None = None


MAX_QUEUED_LINE_BYTES = 64 * 1024 * 1024
DRAIN_TIMEOUT_SECONDS = 10.0


def _delivery_marker(gate):
    """Retain only fixed-size facts consumed by journal evidence classification."""
    if not isinstance(gate, dict):
        return None
    from glassport import evidence
    action, reason = gate.get('action'), gate.get('reason')
    marker = {'action': action if action in evidence.GATE_ACTIONS else 'redacted'}
    if isinstance(reason, str) and reason in evidence.GATE_REASONS:
        marker['reason'] = reason
    elif reason is not None:
        marker['reason'] = 'redacted'
    if 'declared' in gate:
        marker['declared'] = []  # presence alone selects the gate_blocked code
    return marker


class StdioAnalysisWorker:
    """FIFO analysis and journal writer. Never holds a producer lock to analyze.

    Payload bytes are bounded separately from small control records. On payload
    overflow keep only real sequence/digest/gate facts, never a synthetic frame.
    The record cap also bounds control backlog and outstanding intent handles.
    """

    def __init__(self, observer, journal):
        self.epoch, self.journal = observer.epoch, journal
        self.patterns = observer.patterns
        self.builder = MCPTraceBuilder(retain_events=False, limits=observer.session_limits)
        self.engine = DetectorEngine(default_detectors(self.patterns))
        self._fault = None
        self._fault_recorded = False
        self._intents = {}
        self._condition = threading.Condition()
        self._queue = deque()
        self.queued_bytes = 0
        self._closing = False
        self.dead = threading.Event()
        self._abandoned = threading.Event()
        self.thread = threading.Thread(target=self._run, name='glassport-stdio-analysis', daemon=True)
        self.thread.start()

    def _append(self, item, size=0):
        # Caller holds _condition. No producer ever waits for queue capacity.
        if self.dead.is_set() or self._closing or self._abandoned.is_set():
            return
        if len(self._queue) >= self.journal.limits.max_records * 2:
            # Even lightweight overflow/delivery records cannot grow forever.
            self._abandoned.set()
            self._queue.clear()
            self.queued_bytes = 0
        else:
            self._queue.append((item, size))
            self.queued_bytes += size
        self._condition.notify()

    def entry(self, entry, digest, gate, direction, line_bytes):
        marker = _delivery_marker(gate)
        with self._condition:
            if self.queued_bytes + line_bytes > MAX_QUEUED_LINE_BYTES:
                self._append(('overflow', entry['seq'], digest, marker, direction))
            else:
                self._append(('entry', entry, digest, marker, direction), line_bytes)

    def delivery(self, seq, outcome, code, gate):
        with self._condition:
            self._append(('delivery', seq, outcome, code, _delivery_marker(gate)))

    def fault(self):
        with self._condition:
            self._append(('fault',))

    def wait_idle(self, timeout=DRAIN_TIMEOUT_SECONDS):
        """Test/tool barrier only; the relay never calls this method."""
        done = threading.Event()
        with self._condition:
            if self.dead.is_set() or self._abandoned.is_set():
                return False
            if self._closing:
                return not self.thread.is_alive() and not self._abandoned.is_set()
            self._append(('barrier', done))
        return done.wait(timeout)

    def finish(self, timeout=None):
        """Stop accepting work and drain. Timeout explicitly truncates evidence."""
        with self._condition:
            self._closing = True
            self._condition.notify()
        self.thread.join(DRAIN_TIMEOUT_SECONDS if timeout is None else timeout)
        complete = not self.thread.is_alive() and not self.dead.is_set() and not self._abandoned.is_set()
        if not complete:
            self._abandoned.set()
            self._truncate()
        return complete

    def _truncate(self):
        try:
            self.journal.truncate(self.epoch)
        except Exception:
            pass  # unavailable journal never changes the transport

    def _run(self):
        try:
            while True:
                with self._condition:
                    self._condition.wait_for(lambda: self._queue or self._closing or self._abandoned.is_set())
                    if self._abandoned.is_set():
                        break
                    if not self._queue:
                        break
                    item, size = self._queue.popleft()
                    self.queued_bytes -= size
                try:
                    self._process(item)
                except Exception as exc:
                    self._fault = type(exc).__name__
                    # An item may have lost an intent or delivery; a surviving
                    # prefix must never certify the whole capture.
                    self._truncate()
                finally:
                    item = None  # do not retain a large idle frame
        except BaseException:
            self.dead.set()
        finally:
            if self.dead.is_set() or self._abandoned.is_set() or (self._fault and not self._fault_recorded):
                self._truncate()
            with self._condition:
                self._queue.clear()
                self.queued_bytes = 0
            self._intents.clear()

    def _process(self, item):
        kind = item[0]
        if kind == 'barrier':
            item[1].set()
            return
        if kind == 'fault':
            self._fault = 'record_failed'
            return
        if kind == 'delivery':
            _, seq, outcome, code, marker = item
            handle = self._intents.pop(seq, None)
            if not self._abandoned.is_set():
                self.journal.record_delivery(handle, outcome, code=code, gate=marker)
            return
        event, annotations = None, ()
        if kind == 'overflow':
            _, seq, digest, marker, direction = item
            self._fault = 'queue_overflow'
        else:
            _, entry, digest, marker, direction = item
            seq = entry['seq']
            if self._fault is None:
                try:
                    event = self.builder.feed(entry)
                    if event is not None:
                        annotations = tuple(self.engine.on_event(event, self.builder.state))
                except Exception as exc:
                    self._fault = type(exc).__name__
        if direction != 'c2s' or self._abandoned.is_set():
            return
        observation = StdioObservation(
            self.epoch, seq, event, annotations, bool(digest),
            'stdio_analysis_failed' if self._fault else None,
            digest, None if digest else 'stdio_log_failed', marker, self._fault)
        handle = self.journal.record_intent(
            self.epoch, observation, enforce=bool(marker and marker.get('action') == 'blocked'))
        if handle is not None and handle.written:
            self._intents[seq] = handle
            if self._fault:
                self._fault_recorded = True


class StdioObserver:
    """One ordered write/fold stream shared by both pumps, with frozen patterns.

    A failed fold poisons subsequent analysis, never the relay. Recording that
    fault prevents a later successful prefix from masquerading as equivalence.
    The lock never spans a pipe write or the gate's declaration wait.
    """
    transport = 'stdio'
    limits = None

    def __init__(self, log):
        self.log = log
        self.epoch = log.header['epoch']
        self.lock = threading.RLock()
        self.session_limits = SessionLimits()
        self.patterns = detectors.snapshot_pii_patterns()
        self.builder = MCPTraceBuilder(retain_events=False, limits=self.session_limits)
        self.engine = DetectorEngine(default_detectors(self.patterns))
        self.seq = log._seq
        self._fault = None

    def pattern_snapshot(self, epoch):
        return self.patterns if epoch == self.epoch else None

    def record(self, direction, line, gate=None):
        try:
            with self.lock:
                self.seq += 1
                entry, text = build_session_entry(direction, line, gate=gate, seq=self.seq)
                digest = self.log.write_entry(entry, text)
                event, annotations = None, ()
                if self._fault is None:
                    try:
                        event = self.builder.feed(entry)
                        if event is not None:
                            annotations = tuple(self.engine.on_event(event, self.builder.state))
                    except Exception as exc:
                        self._fault = type(exc).__name__
                return StdioObservation(
                    self.epoch, self.seq, event, annotations, bool(digest),
                    'stdio_analysis_failed' if self._fault else None,
                    digest, None if digest else 'stdio_log_failed',
                    gate, self._fault)
        except Exception:
            # Includes construction/serialization and injected recorder faults.
            # No intent is preferable to inventing linkage for unwritten bytes.
            self._fault = 'record_failed'
            return None
