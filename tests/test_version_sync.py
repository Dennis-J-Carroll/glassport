"""
Version-sync lock (roadmap P0.2).

`serve` reports __version__ in serverInfo; pyproject.toml is what PyPI
installs. A skew means a user who pins glassport==X sees the serve tool
report Y — the kind of thing a security-conscious adopter files an issue
about. The literal in __init__.py stays (explicit over clever, and a bare
clone with no installed dist metadata must still import); this test is the
real fix because it prevents recurrence.

Pure stdlib, run with:  python3 -m unittest tests.test_version_sync
"""
import re
import unittest
from pathlib import Path

import glassport

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


class TestVersionSync(unittest.TestCase):
    def test_dunder_version_matches_pyproject(self):
        text = PYPROJECT.read_text(encoding="utf-8")
        m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert m, "pyproject.toml has no version field"
        self.assertEqual(glassport.__version__, m.group(1))


if __name__ == "__main__":
    unittest.main()
