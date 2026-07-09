"""Regression locks for the Kimi red-team round on `adapters/mcp_http.py`.

These drive `_stream_sse` directly with a fake upstream response so the framing
edge cases are deterministic (no sockets, no timing). Two invariants:

  1. log/client parity — a frame the client received verbatim must not be
     silently rewritten in the log (mid-stream BOM must NOT be stripped).
  2. bounded disk — a hostile upstream that never sends a terminator cannot
     make the tap write its stream to disk without limit.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from glassport.adapters.mcp_http import _stream_sse
from glassport.tap import SessionLog


class _FakeResp:
    """Hands out pre-canned chunks the way http.client's response.read(n) does:
    each call returns the next chunk, then b'' at end of stream."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


def _drain(chunks: list[bytes]):
    """Run _stream_sse over `chunks`; return (bytes forwarded, [log entries])."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "s.jsonl"
        log = SessionLog(path)
        out = io.BytesIO()
        _stream_sse(_FakeResp(chunks), out, log)
        log.close()
        entries = [json.loads(ln) for ln in path.read_text("utf-8").splitlines()]
        return out.getvalue(), entries


class TestMidStreamBom(unittest.TestCase):
    def test_bom_bytes_after_stream_start_are_not_stripped_from_log(self):
        # First event carries no BOM, so the leading-BOM strip must arm-and-fire
        # only at true stream start. A later chunk that happens to begin with the
        # BOM byte sequence is real payload the client received verbatim — the
        # log must match the client, not silently drop three bytes.
        forwarded, entries = _drain(
            [b"data: a\n\n", b"\xef\xbb\xbfdata: x\n\n"])

        # forwarding is always byte-for-byte
        self.assertEqual(forwarded, b"data: a\n\n\xef\xbb\xbfdata: x\n\n")

        payloads = [e["frame"] if e["frame"] is not None else e["raw"]
                    for e in entries if e["dir"] == "s2c"]
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0], "a")
        # BOM preserved (U+FEFF). A mid-stream BOM makes "﻿data:" an invalid
        # SSE data line, so the honest log keeps the whole raw event verbatim
        # rather than silently dropping three bytes to fake a clean payload.
        self.assertEqual(payloads[1], "﻿data: x")

    def test_true_leading_bom_is_stripped_once(self):
        # Regression guard the other way: a genuine leading BOM is still removed
        # from the first framed event (Kimi's H5 fix must keep working).
        forwarded, entries = _drain([b"\xef\xbb\xbfdata: hello\n\n"])
        self.assertEqual(forwarded, b"\xef\xbb\xbfdata: hello\n\n")
        s2c = [e for e in entries if e["dir"] == "s2c"]
        self.assertEqual(len(s2c), 1)
        self.assertEqual(s2c[0]["raw"] or s2c[0]["frame"], "hello")


class TestUnterminatedStreamDoesNotFloodDisk(unittest.TestCase):
    def test_unterminated_flood_logs_one_note_not_the_whole_stream(self):
        # ~4 MiB of SSE bytes that never contain an event terminator.
        chunks = [b"A" * 4096 for _ in range(1024)]
        forwarded, entries = _drain(chunks)

        # every byte still reaches the client (relay is sacred)
        self.assertEqual(len(forwarded), 1024 * 4096)

        s2c = [e for e in entries if e["dir"] == "s2c"]
        # exactly one bounded note, not one partial-flush per 256 KiB
        self.assertEqual(len(s2c), 1)
        note = s2c[0]["frame"] if s2c[0]["frame"] is not None else s2c[0]["raw"]
        self.assertEqual(note, {"glassport": "sse_frame_dropped_oversize"})

    def test_real_events_after_a_runaway_still_frame(self):
        # A terminator re-syncs framing: the oversize note fires once, then a
        # normal event that follows is logged as its own frame.
        chunks = [b"A" * 4096 for _ in range(80)]        # ~320 KiB, no terminator
        chunks.append(b"\n\ndata: real\n\n")             # resync + one real event
        _forwarded, entries = _drain(chunks)

        s2c = [e for e in entries if e["dir"] == "s2c"]
        payloads = [e["frame"] if e["frame"] is not None else e["raw"]
                    for e in s2c]
        self.assertIn({"glassport": "sse_frame_dropped_oversize"}, payloads)
        self.assertIn("real", payloads)


if __name__ == "__main__":
    unittest.main()
