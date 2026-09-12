"""
adapters/streaming.py — incremental (opt-in) ingest of a live tap log.

The batch path (from_mcp_session_file) re-reads and re-parses the whole
file on every change; fine for a curses tick, wrong for a web console
holding many long sessions. StreamingSession keeps the adapter's fold
state (_TraceBuilder) alive between polls and feeds it only the bytes
appended since last time, so parsing is O(new data) per poll.

Built-in detectors consume each event immediately using the builder's session
state. Batch analysis replays the same lifecycle. Explicitly installed batch
passes still use full re-annotation; changing the registry rebuilds the view.

File lifecycle:
  * partial trailing line -> buffered, parsed only once its newline lands
  * file shrank (rotation/truncation) -> full rebuild from scratch
  * file vanished -> poll() returns False, last good trace kept
  * file larger than tail_cap_bytes -> bounded tail-only view:
    parse only the last tail_cap_bytes, starting at a line boundary;
    trace.metadata["tail_only"] = True so consumers can say so.
    Further changes replay that bounded tail, matching batch file ingestion.
    Continuous no-history analysis uses MCPTraceBuilder(retain_events=False)
    and DetectorEngine directly; it does not discard session facts at a tail.

Zero dependencies. Pure stdlib.
"""
from __future__ import annotations

from pathlib import Path

from glassport import detectors
from glassport.adapters.mcp_session import (TAIL_CAP_BYTES, _iter_entries,
                                            _TraceBuilder)
from glassport.interaction_trace import InteractionTrace
from glassport.incremental import DetectorEngine

# TAIL_CAP_BYTES lives in mcp_session so batch and streaming share one
# definition of "too big to replay in full" (plan 3.3); re-exported here
# for existing importers.


class StreamingSession:
    def __init__(self, path: str | Path,
                 tail_cap_bytes: int = TAIL_CAP_BYTES, **adapter_kw) -> None:
        self.path = Path(path)
        if type(tail_cap_bytes) is not int or tail_cap_bytes < 1:
            raise ValueError("tail_cap_bytes must be a positive integer")
        self.tail_cap_bytes = tail_cap_bytes
        self.tail_only = False
        self._adapter_kw = adapter_kw
        self._offset = 0               # bytes of the file already consumed
        self._buf = b""                # trailing partial line
        self._started = False          # first successful read happened
        self._builder = _TraceBuilder(**adapter_kw)
        self._engine = DetectorEngine()
        self._registry = tuple(detectors.DETECTORS)
        self.trace: InteractionTrace = self._builder.snapshot()

    def _reset(self) -> None:
        """Rotation/truncation: derived state is disposable, rebuild.
        The trace object is replaced — a rotated file is a new session."""
        self._offset = 0
        self._buf = b""
        self._started = False
        self.tail_only = False
        self._builder = _TraceBuilder(**self._adapter_kw)
        self._engine = DetectorEngine()
        self._registry = tuple(detectors.DETECTORS)
        self.trace = self._builder.snapshot()

    def poll(self) -> bool:
        """Consume newly appended bytes. Returns True when the visible
        trace changed (new events and re-annotation happened)."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return False               # vanished; keep the last good trace

        if tuple(detectors.DETECTORS) != self._registry:
            self._reset()
        if size == self._offset:
            return False
        if size < self._offset or size > self.tail_cap_bytes:
            self._reset()
        if size == self._offset:
            return False

        with open(self.path, "rb") as fh:
            start = self._offset
            if not self._started and size > self.tail_cap_bytes:
                # too big to replay in full: parse only the tail,
                # aligned to the next line boundary
                start = size - self.tail_cap_bytes
                fh.seek(start)
                skipped = fh.readline(size - start)  # bounded cut-off line
                start += len(skipped)
                self.tail_only = True
                data = fh.read(size - start)
            else:
                fh.seek(start)
                data = fh.read(size - start)
        self._started = True
        if self.tail_only:
            self.trace.metadata["tail_only"] = True
        self._offset = start + len(data) if start != self._offset \
            else self._offset + len(data)

        self._buf += data
        if b"\n" not in self._buf:
            return False               # only a partial line so far
        chunk, self._buf = self._buf.rsplit(b"\n", 1)

        fed = 0
        lines = (raw.decode("utf-8", errors="replace")
                 for raw in chunk.split(b"\n"))
        for entry in _iter_entries(lines):
            event = self._builder.feed(entry)
            if event is not None and self._registry == detectors._DEFAULT_DETECTORS:
                self.trace.annotations.extend(self._engine.on_event(event, self._builder.state))
            fed += 1
        if not fed:
            return False

        self._builder.snapshot()
        if self.tail_only:
            self.trace.metadata["tail_only"] = True
        if self._registry != detectors._DEFAULT_DETECTORS:
            self.trace.annotations.clear()
            detectors.annotate(self.trace)
        return True
