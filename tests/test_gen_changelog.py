"""Changelog generation reads only release tags and full history."""
from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gen_changelog.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("gen_changelog", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load changelog generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestGenChangelog(unittest.TestCase):
    def test_non_release_tags_do_not_start_sections(self):
        generator = load_generator()
        tags = "backup/security-round4-prerebase v0.1.0 v0.2.0-rc1 v0.2.0 scratch\n"

        def git(*args):
            if args[0] == "tag":
                return tags
            if args[0] == "log":
                return "2026-01-01\n"
            raise AssertionError(args)

        with mock.patch.object(generator, "_git", side_effect=git):
            self.assertEqual(generator.tags_in_order(),
                             [("v0.1.0", "2026-01-01"), ("v0.2.0", "2026-01-01")])

    def test_write_refuses_shallow_clone(self):
        generator = load_generator()
        with tempfile.TemporaryDirectory() as tmp:
            generator.REPO = Path(tmp)
            calls = []

            def git(*args):
                calls.append(args)
                if args == ("rev-parse", "--is-shallow-repository"):
                    return "true\n"
                raise AssertionError(args)

            stderr = io.StringIO()
            with mock.patch.object(generator, "_git", side_effect=git), \
                    redirect_stderr(stderr):
                self.assertEqual(generator.main(["--write"]), 1)
            self.assertEqual(calls, [("rev-parse", "--is-shallow-repository")])
            self.assertFalse((Path(tmp) / "CHANGELOG.md").exists())
            self.assertIn("git fetch --unshallow", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
