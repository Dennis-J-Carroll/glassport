"""
Token-presence tests for the CI distribution templates. The suite is
stdlib-only (no YAML parser), so we assert the load-bearing tokens are
present — a cheap contract lock against deletion or a typo in a critical
field. The real end-to-end behavior is exercised by the GitHub Actions
`pre-commit-hook` job (pre-commit try-repo against a tool-poisoning fixture).
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestPreCommitHook(unittest.TestCase):
    def test_manifest_exists_with_required_extension(self):
        # pre-commit requires `.pre-commit-hooks.yaml` (NOT .yml)
        self.assertTrue((ROOT / ".pre-commit-hooks.yaml").is_file())

    def test_manifest_has_load_bearing_tokens(self):
        text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        for token in ("id: glassport-audit", "entry: glassport audit",
                      "language: python", "pass_filenames: false"):
            self.assertIn(token, text)


class TestGitlabTemplate(unittest.TestCase):
    def test_template_exists(self):
        self.assertTrue((ROOT / "examples" / "gitlab-ci.yml").is_file())

    def test_template_has_load_bearing_tokens(self):
        text = (ROOT / "examples" / "gitlab-ci.yml").read_text(encoding="utf-8")
        for token in ("glassport audit", "--sarif", "allow_failure: true",
                      "when: always", "set false to gate"):
            self.assertIn(token, text)
