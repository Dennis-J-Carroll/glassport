"""Action metadata and input guards; CI exercises the composite action itself."""

from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
HELPER = ROOT / "scripts" / "action_helper.py"


class TestActionMetadata(unittest.TestCase):
    def test_no_input_expression_inside_run_script(self):
        lines = ACTION.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if not re.match(r"^      run: \|$", line):
                continue
            body = []
            for following in lines[index + 1:]:
                if following and not following.startswith("        "):
                    break
                body.append(following)
            self.assertNotIn("${{ inputs.", "\n".join(body))

    def test_third_party_actions_use_full_sha_pins(self):
        uses = re.findall(r"^\s+-?\s*uses: ([^\s]+)(.*)$",
                          ACTION.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual(len(uses), 2)
        for ref, comment in uses:
            self.assertRegex(ref, r"^[\w-]+/[\w-]+(?:/[\w-]+)?@[0-9a-f]{40}$")
            self.assertRegex(comment, r"# v\d")


class TestActionValidation(unittest.TestCase):
    def run_validation(self, workspace: Path, audit: str = "", bundle: str = ""):
        env = dict(os.environ, GITHUB_WORKSPACE=str(workspace), AUDIT_PATH=audit,
                   BUNDLE_PATHS=bundle, BUNDLE_PUBLIC="false", FAIL_ON_FINDINGS="none",
                   FAIL_ON_BUNDLE="contradicted", UPLOAD_SARIF="true",
                   SETUP_PYTHON="true")
        return subprocess.run([sys.executable, "-I", str(HELPER), "validate"],
                              env=env, capture_output=True, text=True, check=False)

    def test_usage_message_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "src").mkdir()
            self.assertEqual(self.run_validation(workspace, audit="src").returncode, 0)
            empty = self.run_validation(workspace)
            self.assertEqual(empty.returncode, 1)
            self.assertIn("Set audit-path or bundle", empty.stderr)
            absolute = self.run_validation(workspace, audit=str(workspace / "src"))
            self.assertEqual(absolute.returncode, 1)
            self.assertIn("SARIF", absolute.stderr)
            self.assertEqual(self.run_validation(workspace, audit="../src").returncode, 1)
            self.assertEqual(self.run_validation(workspace, bundle="missing").returncode, 1)

    def test_shell_metacharacters_remain_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "src").mkdir()
            marker = workspace / "injected"
            for payload in (f'src"; touch {marker}; #', f'src$(touch {marker})',
                            f'src`touch {marker}`'):
                with self.subTest(payload=payload):
                    result = self.run_validation(workspace, audit=payload)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
