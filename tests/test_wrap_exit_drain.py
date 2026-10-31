"""A passive capture relays the server's last output before it exits."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from glassport import tap

_RUN = """
import sys
from glassport import tap
sys.exit(tap.main(['wrap', '--log-dir', sys.argv[1], '--', sys.executable, '-c', sys.argv[2]]))
"""


def _wrap(server_code: str, log_dir: str) -> subprocess.Popen:
    env = dict(os.environ, PYTHONPATH=str(Path(tap.__file__).parents[1]))
    env.pop("GLASSPORT_INTERNAL_PROBE", None)
    return subprocess.Popen([sys.executable, "-c", _RUN, log_dir, server_code],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env)


class TestPassiveWrapExitDrain(unittest.TestCase):
    def test_slow_client_receives_final_large_line(self):
        line = b'{"jsonrpc":"2.0","id":1,"result":{"text":"' + b"x" * 1_000_000 + b'"}}\n'
        server = ("import sys; sys.stdout.buffer.write(b'{\"jsonrpc\":\"2.0\",\"id\":1,"
                  "\"result\":{\"text\":\"' + b'x' * 1000000 + b'\"}}\\n'); "
                  "sys.stdout.buffer.flush()")
        with tempfile.TemporaryDirectory() as tmp:
            proc = _wrap(server, tmp)
            # The client reads late: the relay is still writing when the server
            # has already exited. Exiting without draining would drop the tail.
            time.sleep(0.5)
            out, _ = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(out), len(line))
        self.assertEqual(out, line)

    @unittest.skipUnless(os.name == "posix", "inherited pipe handles are POSIX-specific")
    def test_exit_is_bounded_when_server_output_never_reaches_eof(self):
        # A grandchild inherits the server's stdout and keeps it open, so the
        # relay never sees EOF. Exit must still happen within the drain bound.
        server = ("import subprocess, sys; "
                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(15)']); "
                  "sys.stdout.buffer.write(b'{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'); "
                  "sys.stdout.buffer.flush()")
        with tempfile.TemporaryDirectory() as tmp:
            start = time.monotonic()
            proc = _wrap(server, tmp)
            out, _ = proc.communicate(timeout=30)
            elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(out, b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
        self.assertLess(elapsed, tap.PUMP_DRAIN_SECONDS + 8)


if __name__ == "__main__":
    unittest.main()
