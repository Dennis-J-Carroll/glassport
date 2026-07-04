"""
adapters/streaming.py — incremental (opt-in) ingest of a live tap log.

The batch path (from_mcp_session_file) re-reads and re-parses the whole
file on every change; fine for a curses tick, wrong for a web console
holding many long sessions. StreamingSession keeps the adapter's fold
state (_TraceBuilder) alive between polls and feeds it only the bytes
appended since last time, so parsing is O(new data) per poll.

Annotation is deliberately NOT incremental: detectors may revise earlier
conclusions when later frames arrive (a tools/list retroactively
un-fabricates prior calls), so annotations are recomputed over the full
trace each time anything new lands. That keeps one invariant absolute,
and test-locked: after any sequence of polls, trace + annotations are
byte-for-byte what the batch path would say about the same file.
Detectors are linear passes; recomputation is well inside the frame
budget (see tests.test_streaming.TestPerf for the measured number).

File lifecycle:
  * partial trailing line -> buffered, parsed only once its newline lands
  * file shrank (rotation/truncation) -> full rebuild from scratch
  * file vanished -> poll() returns False, last good trace kept
  * file larger than tail_cap_bytes at first read -> tail-only mode:
    parse only the last tail_cap_bytes, starting at a line boundary;
    trace.metadata["tail_only"] = True so consumers can say so.

Zero dependencies. Pure stdlib.
"""
from __future__ import annotations

from pathlib import Path

from glassport import detectors
from glassport.adapters.mcp_session import (TAIL_CAP_BYTES, _iter_entries,
                                            _TraceBuilder)
from glassport.interaction_trace import InteractionTrace

# TAIL_CAP_BYTES lives in mcp_session so batch and streaming share one
# definition of "too big to replay in full" (plan 3.3); re-exported here
# for existing importers.


class StreamingSession:
    def __init__(self, path: str | Path,
                 tail_cap_bytes: int = TAIL_CAP_BYTES, **adapter_kw) -> None:
        self.path = Path(path)
        self.tail_cap_bytes = tail_cap_bytes
        self.tail_only = False
        self._adapter_kw = adapter_kw
        self._offset = 0               # bytes of the file already consumed
        self._buf = b""                # trailing partial line
        self._started = False          # first successful read happened
        self._builder = _TraceBuilder(**adapter_kw)
        self.trace: InteractionTrace = self._builder.snapshot()

    def _reset(self) -> None:
        """Rotation/truncation: derived state is disposable, rebuild.
        The trace object is replaced — a rotated file is a new session."""
        self._offset = 0
        self._buf = b""
        self._started = False
        self.tail_only = False
        self._builder = _TraceBuilder(**self._adapter_kw)
        self.trace = self._builder.snapshot()

    def poll(self) -> bool:
        """Consume newly appended bytes. Returns True when the visible
        trace changed (new events and re-annotation happened)."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return False               # vanished; keep the last good trace

        if size < self._offset:
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
                skipped = fh.readline()          # drop the cut-off line
                start += len(skipped)
                self.tail_only = True
                data = fh.read()
            else:
                fh.seek(start)
                data = fh.read()
        self._started = True
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
            self._builder.feed(entry)
            fed += 1
        if not fed:
            return False

        self._builder.snapshot()
        if self.tail_only:
            self.trace.metadata["tail_only"] = True
        # full re-annotation: exact agreement with the batch path beats
        # incremental cleverness (see module docstring)
        self.trace.annotations.clear()
        detectors.annotate(self.trace)
        return True
