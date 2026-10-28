"""Best-effort stdio evidence observer. Never owns a transport verdict."""
from __future__ import annotations

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
