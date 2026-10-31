"""The s2c pump reads server output in buffered chunks, never byte by byte."""
from __future__ import annotations

import io
import os
import threading
import unittest

from glassport import tap


class _CountingPipe(io.RawIOBase):
    """Raw reader over a pipe fd that counts read syscalls."""

    def __init__(self, fd):
        self.fd = fd
        self.calls = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        self.calls += 1
        data = os.read(self.fd, len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        if not self.closed:
            os.close(self.fd)
        super().close()


class _Sink(io.BytesIO):
    """Downstream that survives pump's final close and signals each write."""

    def __init__(self):
        super().__init__()
        self.wrote = threading.Event()

    def write(self, data):
        written = super().write(data)
        self.wrote.set()
        return written

    def close(self):
        pass


def _relay(payload: bytes, *, keep_open: bool = False):
    r, w = os.pipe()
    raw = _CountingPipe(r)
    sink = _Sink()
    pump = threading.Thread(target=tap.pump,
                            args=(tap.line_reader(raw), sink, None, "s2c"),
                            daemon=True)
    pump.start()
    os.write(w, payload)
    if not keep_open:
        os.close(w)
        pump.join(10)
        return raw, sink, None
    return raw, sink, (w, pump)


class TestServerOutputReader(unittest.TestCase):
    def test_megabyte_line_takes_few_reads(self):
        line = b'{"jsonrpc":"2.0","id":1,"result":{"text":"' + b"x" * 1_000_000 + b'"}}\n'
        raw, sink, _ = _relay(line)
        self.assertEqual(sink.getvalue(), line)
        # An unbuffered readline makes one read() per byte (~1,000,000 here).
        self.assertLess(raw.calls, 200)

    def test_small_frame_is_relayed_without_waiting_for_more(self):
        frame = b'{"jsonrpc":"2.0","id":1,"result":{}}\n'
        raw, sink, (w, pump) = _relay(frame, keep_open=True)
        try:
            self.assertTrue(sink.wrote.wait(5), "frame held back by the reader")
            self.assertEqual(sink.getvalue(), frame)
        finally:
            os.close(w)
            pump.join(10)

    def test_bytes_are_preserved_exactly(self):
        payload = (b'{"a":1}\r\n' + b'\xff\xfe not utf-8\n' + b'{"tail":true}')
        raw, sink, _ = _relay(payload)
        # CRLF, invalid UTF-8 and a final line without newline all pass through.
        self.assertEqual(sink.getvalue(), payload)


if __name__ == "__main__":
    unittest.main()
