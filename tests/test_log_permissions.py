"""S1 — SessionLog must create its dir/file with private permissions.

Glassport logs full MCP traffic (credentials, PII), so the session log and its
directory must be owner-only regardless of the caller's umask. POSIX only; on
other OSes st_mode is advisory and these tests are skipped.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from glassport.tap import SessionLog


@unittest.skipUnless(os.name == "posix", "log permissions are POSIX-only")
class TestLogPermissions(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def _mode(self, p: Path) -> int:
        return stat.S_IMODE(os.stat(p).st_mode)

    def test_new_log_and_dir_are_private(self):
        # A permissive umask must not leak into the created log.
        old = os.umask(0o000)
        try:
            path = self.root / "sessions" / "s.jsonl"
            log = SessionLog(path)
            log.close()
            self.assertEqual(self._mode(path), 0o600,
                             "log file is not 0o600")
            self.assertEqual(self._mode(path.parent), 0o700,
                             "session dir is not 0o700")
        finally:
            os.umask(old)

    def test_preexisting_loose_dir_and_file_are_tightened(self):
        d = self.root / "loose"
        d.mkdir(mode=0o755)
        os.chmod(d, 0o755)   # mkdir mode is umask-masked; force it loose
        path = d / "s.jsonl"
        path.touch(mode=0o644)
        os.chmod(path, 0o644)
        log = SessionLog(path)
        log.close()
        self.assertEqual(self._mode(path), 0o600,
                         "pre-existing loose file was not tightened")
        self.assertEqual(self._mode(d), 0o700,
                         "pre-existing loose dir was not tightened")

    def test_frame_still_round_trips(self):
        # The os.open + wrap must not break append/buffering.
        path = self.root / "rt.jsonl"
        log = SessionLog(path)
        log.record("c2s", b'{"jsonrpc":"2.0","id":1,"method":"ping"}')
        log.close()
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn('"method": "ping"', lines[0])


@unittest.skipUnless(os.name == "posix", "POSIX modes only")
class TestFileMode(unittest.TestCase):
    def test_reports_owner_only_mode(self):
        with tempfile.TemporaryDirectory() as d:
            log = SessionLog(Path(d) / "s.jsonl")
            self.assertEqual(log.file_mode(), 0o600)
            log.close()


class TestOpenSessionLog(unittest.TestCase):
    def test_unwritable_dir_returns_none_not_raise(self):
        from glassport.tap import open_session_log
        # Cross-platform unwritable/uncreatable target: the log's parent
        # directory component is an existing REGULAR FILE, not a directory.
        # mkdir(parents=True) then raises OSError (FileExistsError /
        # NotADirectoryError, both OSError subclasses) identically on POSIX
        # and Windows -- no chmod, no /proc, no platform-specific path.
        with tempfile.TemporaryDirectory() as d:
            blocker = Path(d) / "blocker"
            blocker.write_text("not a directory")
            bad = blocker / "nested" / "s.jsonl"
            self.assertIsNone(open_session_log(bad))

    @unittest.skipUnless(os.name == "posix", "POSIX modes only")
    def test_non_private_mode_degrades_to_none(self):
        from glassport.tap import open_session_log, SessionLog
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(SessionLog, "file_mode", return_value=0o644):
                self.assertIsNone(open_session_log(Path(d) / "s.jsonl"))

    def test_valid_dir_returns_a_working_log(self):
        from glassport.tap import open_session_log
        with tempfile.TemporaryDirectory() as d:
            log = open_session_log(Path(d) / "s.jsonl")
            self.assertIsNotNone(log)
            log.record("c2s", b'{"jsonrpc":"2.0"}')
            log.close()


if __name__ == "__main__":
    unittest.main()
