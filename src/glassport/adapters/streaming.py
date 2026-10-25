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

PLAY-BY-PLAY
------------
`from_mcp_session_file` answers "what happened in this log?" by reading
the whole file. `StreamingSession` answers "what changed since I last
looked?" by reading only the new bytes. Same fold, same adapter, same
findings -- different cost per poll.

State is five things:

  _offset    bytes already consumed
  _buf       the trailing partial line, waiting for its newline
  _started   whether a successful read has happened yet
  _builder   the live fold, shared with the batch adapter
  _engine    the incremental detector engine

`poll()` then does, in order: notice a rotated or vanished file, return
early when nothing changed, seek to the offset, cut the new bytes on a
line boundary, feed each complete line, and only then re-annotate.

Two paths deliberately diverge at the end. With the default detector
registry, each event is detected as it is fed and the annotations
accumulate. With any explicitly installed batch pass, the view is
rebuilt from scratch, because a batch pass needs the whole trace and an
accumulated view would quietly mix the two.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not decide when to poll, does not own a thread, and does not
hide a bounded view. If the file is too large to replay from the start,
`tail_only` is set so the caller can say the head was never analyzed.
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
    # PLAY: One object per file, holding the fold across polls. `trace` is
    # a snapshot that is refreshed in place, so a UI can hold a reference
    # to it and simply repaint after a True return from poll().
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
        # PLAY: Everything derived is thrown away together. Reusing a fold
        # across a rotation would attribute one session's declarations to
        # the next one's calls, which is the worst kind of quiet error.
        # Note the trace is REPLACED, not cleared, so a caller holding the
        # old object sees a frozen past rather than a mutating present.
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

        # PLAY: The registry is compared on every poll. Installing a batch
        # pass changes how findings are produced, and a view built by the
        # old method cannot be trusted under the new one -- so the answer
        # is to rebuild rather than to patch.
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
                # PLAY: The seek lands mid-line, so the first readline()
                # throws away the truncated remainder of whatever line it
                # landed in. That discarded line is real evidence, which is
                # exactly why tail_only is set: the view is truthful about
                # what it skipped instead of parsing a half frame.
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
        # PLAY: rsplit keeps everything after the LAST newline in _buf. A
        # writer that is mid-frame leaves a fragment here, and parsing it
        # now would produce a truncated JSON line that reads as a malformed
        # frame. It waits for its newline instead.
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
        # PLAY: The two endings. Default registry: findings were produced
        # event by event above and are left alone. Anything else: the
        # accumulated list is cleared and the batch pass runs over the
        # whole trace, so there is exactly one source of findings.
        if self._registry != detectors._DEFAULT_DETECTORS:
            self.trace.annotations.clear()
            detectors.annotate(self.trace)
        return True
