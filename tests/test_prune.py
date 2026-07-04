"""
Tests for `glassport prune` — retention for the session log dir
(roadmap H1.10). Logs grow forever in ~/.glassport/sessions/; prune
deletes old ones, dry-run by default, and refuses to delete a log whose
analysis crashed a detector (that log is evidence) without --force.

Pure stdlib, run with:  python3 -m unittest tests.test_prune
"""
import contextlib
import io
import os
import tempfile
import time
import unittest
from pathlib import Path

from glassport import prune as prune_mod
from tests.test_detectors import handshake


def write_session(tmp, name, lines, age_days=0.0) -> Path:
    p = Path(tmp) / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if age_days:
        old = time.time() - age_days * 86400
        os.utime(p, (old, old))
    return p


class TestParseAge(unittest.TestCase):
    def test_days_hours(self):
        self.assertEqual(prune_mod.parse_age("30d"), 30 * 86400)
        self.assertEqual(prune_mod.parse_age("12h"), 12 * 3600)

    def test_bad_values_raise(self):
        for bad in ("", "30", "d30", "-3d", "3w"):
            with self.assertRaises(ValueError):
                prune_mod.parse_age(bad)


class TestPrune(unittest.TestCase):
    def test_dry_run_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = write_session(tmp, "a.jsonl", handshake(), age_days=40)
            res = prune_mod.prune(Path(tmp), 30 * 86400, apply=False)
            self.assertEqual(res.candidates, [old])
            self.assertTrue(old.exists())

    def test_apply_deletes_old_keeps_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = write_session(tmp, "a.jsonl", handshake(), age_days=40)
            new = write_session(tmp, "b.jsonl", handshake(), age_days=1)
            res = prune_mod.prune(Path(tmp), 30 * 86400, apply=True)
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())
            self.assertEqual(res.deleted, [old])

    def test_detector_error_log_is_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = write_session(tmp, "err.jsonl", handshake(),
                                      age_days=40)
            orig = prune_mod._has_detector_error
            prune_mod._has_detector_error = lambda p: True
            try:
                res = prune_mod.prune(Path(tmp), 30 * 86400, apply=True)
            finally:
                prune_mod._has_detector_error = orig
            self.assertTrue(protected.exists())
            self.assertEqual(res.skipped, [protected])

    def test_force_overrides_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            protected = write_session(tmp, "err.jsonl", handshake(),
                                      age_days=40)
            orig = prune_mod._has_detector_error
            prune_mod._has_detector_error = lambda p: True
            try:
                prune_mod.prune(Path(tmp), 30 * 86400, apply=True,
                                force=True)
            finally:
                prune_mod._has_detector_error = orig
            self.assertFalse(protected.exists())

    def test_non_jsonl_files_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            stray = Path(tmp) / "notes.txt"
            stray.write_text("keep me", encoding="utf-8")
            old_stat = os.stat(stray)
            os.utime(stray, (old_stat.st_atime - 90 * 86400,
                             old_stat.st_mtime - 90 * 86400))
            res = prune_mod.prune(Path(tmp), 30 * 86400, apply=True)
            self.assertTrue(stray.exists())
            self.assertEqual(res.candidates, [])


class TestPruneCLI(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = prune_mod.main(argv)
        return rc, out.getvalue()

    def test_default_is_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = write_session(tmp, "a.jsonl", handshake(), age_days=40)
            rc, out = self.run_main(["--older-than", "30d",
                                     "--log-dir", tmp])
            self.assertEqual(rc, 0)
            self.assertTrue(old.exists())
            self.assertIn("dry-run", out)

    def test_threshold_exit_code_for_cron(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(3):
                write_session(tmp, f"s{i}.jsonl", handshake(), age_days=40)
            rc, _ = self.run_main(["--older-than", "30d", "--log-dir", tmp,
                                   "--threshold", "2"])
            self.assertEqual(rc, 1)

    def test_apply_deletes(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = write_session(tmp, "a.jsonl", handshake(), age_days=40)
            rc, _ = self.run_main(["--older-than", "30d", "--log-dir", tmp,
                                   "--apply"])
            self.assertEqual(rc, 0)
            self.assertFalse(old.exists())

    def test_missing_older_than_is_usage_error(self):
        rc, _ = self.run_main([])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
