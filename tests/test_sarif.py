"""
Tests for sarif.render_sarif() — SARIF 2.1.0 export of static audit
findings for the GitHub Security tab. Pure stdlib / unittest.

The contract that matters for GitHub code scanning: every result points
at a REPO-RELATIVE path and line (so it annotates the diff), and the one
severity vocabulary maps cleanly whether a finding carries a string
severity (audit) or an int one (runtime detectors).
"""
import json
import unittest

from glassport.audit import Finding, Report
from glassport import sarif


def report(findings, score=50, grade="F"):
    return Report(profile={"name": "demo"}, findings=findings,
                  deductions=[], score=score, grade=grade)


class TestSeverityVocab(unittest.TestCase):
    def test_string_severities(self):
        self.assertEqual(sarif._sarif_level("critical"), "error")
        self.assertEqual(sarif._sarif_level("high"), "error")
        self.assertEqual(sarif._sarif_level("medium"), "warning")
        self.assertEqual(sarif._sarif_level("low"), "note")
        self.assertEqual(sarif._sarif_level("info"), "note")

    def test_int_severities_unify_to_same_levels(self):
        self.assertEqual(sarif._sarif_level(3), "error")
        self.assertEqual(sarif._sarif_level(2), "warning")
        self.assertEqual(sarif._sarif_level(1), "note")

    def test_capability_note_tier_maps_to_sarif_note(self):
        self.assertEqual(sarif._sarif_level("note"), "note")


class TestSarifStructure(unittest.TestCase):
    def doc(self, findings, **kw):
        return json.loads(sarif.render_sarif(report(findings, **kw)))

    def test_minimal_valid_envelope(self):
        d = self.doc([])
        self.assertEqual(d["version"], "2.1.0")
        self.assertIn("$schema", d)
        self.assertEqual(len(d["runs"]), 1)
        self.assertEqual(d["runs"][0]["tool"]["driver"]["name"], "glassport")
        self.assertEqual(d["runs"][0]["results"], [])

    def test_result_uses_repo_relative_path_and_line(self):
        f = Finding("secret-hardcoded", "critical",
                    "mcp-servers/srv/app.py", 42, "leaked key")
        d = self.doc([f])
        res = d["runs"][0]["results"][0]
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"],
                         "mcp-servers/srv/app.py")
        self.assertEqual(loc["region"]["startLine"], 42)
        self.assertEqual(res["ruleId"], "glassport/secret-hardcoded")
        self.assertEqual(res["level"], "error")

    def test_base_prefixes_paths_to_repo_root(self):
        # audited root is a subdir of the repo; SARIF must point at the
        # repo-root-relative path so GitHub annotates the right file
        f = Finding("secret-hardcoded", "critical", "app.py", 9, "k")
        d = json.loads(sarif.render_sarif(report([f]), base="mcp-servers/srv"))
        uri = (d["runs"][0]["results"][0]["locations"][0]
               ["physicalLocation"]["artifactLocation"]["uri"])
        self.assertEqual(uri, "mcp-servers/srv/app.py")

    def test_base_does_not_double_prefix_absolute(self):
        f = Finding("secret-hardcoded", "critical", "/abs/app.py", 9, "k")
        d = json.loads(sarif.render_sarif(report([f]), base="repo/sub"))
        uri = (d["runs"][0]["results"][0]["locations"][0]
               ["physicalLocation"]["artifactLocation"]["uri"])
        self.assertEqual(uri, "/abs/app.py")

    def test_no_home_or_absolute_uris(self):
        f = Finding("net-egress", "low", "src/x.py", 3, "talks to network")
        d = self.doc([f])
        uri = (d["runs"][0]["results"][0]["locations"][0]
               ["physicalLocation"]["artifactLocation"]["uri"])
        self.assertFalse(uri.startswith(("~", "/", "file:")))
        # no uriBaseId pointing at $HOME sessions dir
        self.assertNotIn("uriBaseId",
                         d["runs"][0]["results"][0]["locations"][0]
                         ["physicalLocation"]["artifactLocation"])

    def test_rules_deduped_and_carry_metadata(self):
        fs = [Finding("net-egress", "low", "a.py", 1, "x"),
              Finding("net-egress", "low", "b.py", 2, "y"),
              Finding("exec-dynamic", "high", "c.py", 3, "z")]
        d = self.doc(fs)
        rules = d["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertCountEqual(ids, ["glassport/net-egress",
                                    "glassport/exec-dynamic"])
        eg = next(r for r in rules if r["id"] == "glassport/net-egress")
        self.assertEqual(eg["defaultConfiguration"]["level"], "note")
        self.assertIn("fullDescription", eg)
        self.assertEqual(len(d["runs"][0]["results"]), 3)

    def test_low_severity_is_note_critical_is_error(self):
        d = self.doc([Finding("secret-hardcoded", "critical", "a.py", 1, "x"),
                      Finding("fs-write", "low", "b.py", 2, "y")])
        levels = {r["ruleId"]: r["level"] for r in d["runs"][0]["results"]}
        self.assertEqual(levels["glassport/secret-hardcoded"], "error")
        self.assertEqual(levels["glassport/fs-write"], "note")

    def test_message_carries_detail(self):
        d = self.doc([Finding("tool-poisoning", "critical",
                              "evil.py", 7, "ignore previous instructions")])
        msg = d["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("ignore previous instructions", msg)


class TestAuditCliSarif(unittest.TestCase):
    def test_audit_sarif_flag_emits_sarif(self):
        import io
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path
        from glassport import audit

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "server.py").write_text(
                'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n')
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = audit.main([d, "--sarif"])
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "glassport")
        # hardcoded secret present and non-zero exit (CI gate fires)
        self.assertTrue(doc["runs"][0]["results"])
        self.assertEqual(rc, 1)


class TestSecretRedaction(unittest.TestCase):
    """A hostile server can name a file or directory like a credential; that
    path flows into the SARIF URI, fingerprint and (via a matched snippet) the
    message. None may reach the committed/uploaded document verbatim."""

    _TOKEN = "ghp_123456789012345678901234567890123456"  # 40-char token shape

    def test_secret_in_path_redacted_everywhere(self):
        f = Finding("tool-poisoning", "critical",
                    f"src/{self._TOKEN}/planted.py", 3, "directive text found")
        doc = sarif.render_sarif(report([f]), base="srv")
        self.assertNotIn(self._TOKEN, doc)          # not in uri, fp, or anywhere
        res = json.loads(doc)["runs"][0]["results"][0]
        self.assertIn("redacted",
                      res["locations"][0]["physicalLocation"]
                      ["artifactLocation"]["uri"])
        self.assertNotIn(self._TOKEN, res["partialFingerprints"]["glassportRulePath"])

    def test_secret_in_detail_redacted(self):
        f = Finding("secret-hardcoded", "critical", "app.py", 1,
                    f"leaked: {self._TOKEN}")
        doc = sarif.render_sarif(report([f]), base="")
        self.assertNotIn(self._TOKEN, doc)

    def test_directive_snippet_not_a_secret_is_preserved(self):
        # a quoted poisoning directive is the audit faithfully reporting a
        # finding, not a credential — it must survive redaction
        f = Finding("tool-poisoning", "critical", "app.py", 1,
                    "directive text: 'ignore previous instructions'")
        doc = sarif.render_sarif(report([f]), base="")
        self.assertIn("ignore previous instructions", doc)


if __name__ == "__main__":
    unittest.main()
