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
from unittest import mock

from glassport.audit import Finding, Report
from glassport import sarif
from glassport import detectors


def report(findings, score=50, grade="F"):
    return Report(profile={"name": "demo"}, findings=findings,
                  deductions=[], score=score, grade=grade)


class TestRedactionFailsClosed(unittest.TestCase):
    """S2 — if the PII scan raises, the SARIF artifact must withhold the field,
    never emit the unscanned (possibly-live) secret."""

    def test_scan_failure_withholds_the_secret_in_the_message(self):
        secret = "sk_live_" + "Z" * 24
        f = Finding("secret-hardcoded", "critical", "app.py", 9,
                    "leaked " + secret)
        with mock.patch.object(detectors, "_scan_pii",
                               side_effect=RuntimeError("boom")):
            out = sarif.render_sarif(report([f]))
        self.assertNotIn(secret, out)
        self.assertIn("content withheld", out)


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


class TestBounding(unittest.TestCase):
    """A hostile finding detail must not inflate the SARIF without limit."""

    def test_huge_detail_is_clamped(self):
        f = Finding("tool-poisoning", "critical", "app.py", 1, "X" * 2_000_000)
        doc = sarif.render_sarif(report([f]), base="")
        self.assertLess(len(doc.encode("utf-8")), 500_000)
        msg = json.loads(doc)["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("chars truncated", msg)


_OBF_SECRET = "sk-ant-api03-" + "aB" * 20 + "1234567890"
_OBFS = {
    "zwj":       lambda s: s[:6] + "‍" + s[6:],
    "fullwidth": lambda s: s.translate(
        {ord(c): ord(c) + 0xFEE0 for c in s if "!" <= c <= "~"}),
    "cyrillic":  lambda s: s.replace("a", "а"),
    "multi":     lambda s: (s[:4] + "‍" + s[4:8].replace("a", "а")
                            + "​" + s[8:]),
}


class TestSarifRedactsObfuscated(unittest.TestCase):
    def test_no_reconstructable_secret_in_sarif(self):
        for name, obf in _OBFS.items():
            f = Finding("secret-hardcoded", "critical", "app.py", 9,
                        obf(_OBF_SECRET))
            doc = sarif.render_sarif(report([f]))
            self.assertNotIn(_OBF_SECRET, detectors._normalize_for_scan(doc), name)

    def test_redaction_alone_defeats_obfuscation_in_sarif(self):
        with mock.patch.object(sarif, "neutralize_text", side_effect=lambda t: t):
            for name, obf in _OBFS.items():
                f = Finding("secret-hardcoded", "critical", "app.py", 9,
                            obf(_OBF_SECRET))
                doc = sarif.render_sarif(report([f]))
                self.assertNotIn(_OBF_SECRET, detectors._normalize_for_scan(doc), name)


class TestProvenanceRedaction(unittest.TestCase):
    """P0 evidence-safety: provenance findings come from the audited (possibly
    hostile) manifest, so no field may reach the SARIF artifact raw. Kimi
    confirmed pf.package leaked to message.text + properties.package because
    sarif.py neutralized but never strict-redacted it. These lock the fix and
    the adjacent structural/display fields."""

    from glassport.provenance import ProvenanceFinding as _PF

    def _prov_report(self, pf):
        return Report(profile={"name": "demo"}, findings=[], deductions=[],
                      score=50, grade="F", provenance=[pf])

    def _doc(self, pf):
        return sarif.render_sarif(self._prov_report(pf))

    def _pf(self, **kw):
        base = dict(rule="prov-not-in-registry", severity="high",
                    ecosystem="npm", package="left-pad",
                    manifest="package.json", detail="not found in registry")
        base.update(kw)
        return self._PF(**base)

    def test_plain_credential_in_package_absent_everywhere(self):
        secret = "sk-ant-api03-" + "A" * 40 + "1234567890"
        doc = self._doc(self._pf(package=secret))
        # gone from the whole normalized artifact...
        self.assertNotIn(secret, detectors._normalize_for_scan(doc))
        # ...and specifically from both confirmed sinks
        run = json.loads(doc)["runs"][0]
        res = run["results"][0]
        self.assertNotIn(secret, res["message"]["text"])
        self.assertNotIn(secret, res["properties"]["package"])

    def test_obfuscated_credential_in_package_absent(self):
        for name, obf in _OBFS.items():
            doc = self._doc(self._pf(package=obf(_OBF_SECRET)))
            self.assertNotIn(_OBF_SECRET, detectors._normalize_for_scan(doc), name)

    def test_secret_in_detail_absent(self):
        secret = "sk-ant-api03-" + "B" * 40 + "1234567890"
        doc = self._doc(self._pf(detail=f"resolved from {secret} upstream"))
        self.assertNotIn(secret, detectors._normalize_for_scan(doc))

    def test_secret_in_ecosystem_or_rule_does_not_leak(self):
        secret = "sk-ant-api03-" + "C" * 40 + "1234567890"
        for field in ("ecosystem", "rule"):
            doc = self._doc(self._pf(**{field: secret}))
            self.assertNotIn(secret, detectors._normalize_for_scan(doc), field)

    def test_fail_closed_withhold_when_scan_raises(self):
        secret = "sk-ant-api03-" + "D" * 40 + "1234567890"
        with mock.patch.object(detectors, "_spanned_original_redactions",
                               side_effect=RuntimeError("boom")):
            doc = self._doc(self._pf(package=secret))
        self.assertNotIn(secret, doc)
        self.assertIn(detectors._WITHHELD,
                      json.loads(doc)["runs"][0]["results"][0]["message"]["text"])

    def test_structural_fields_validate_and_stay_consistent(self):
        # a hostile rule/ecosystem collapses to safe sentinels, and every
        # emitted ruleId still resolves to an entry in the driver rules table.
        doc = json.loads(self._doc(self._pf(rule="attacker-rule",
                                            ecosystem="evil-registry")))
        run = doc["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        res = run["results"][0]
        self.assertEqual(res["ruleId"], "provenance/prov-unknown")
        self.assertIn(res["ruleId"], rule_ids)          # ruleId ↔ rules table
        self.assertEqual(res["properties"]["ecosystem"], "unknown")
        # the collapsed rule renders catalog text, not the raw hostile value
        unknown = next(r for r in run["tool"]["driver"]["rules"]
                       if r["id"] == "provenance/prov-unknown")
        self.assertNotIn("attacker-rule", json.dumps(run))
        self.assertEqual(unknown["name"], "prov-unknown")

    def test_ordinary_provenance_output_unchanged(self):
        # a benign npm finding renders exactly as before the hardening
        run = json.loads(self._doc(self._pf()))["runs"][0]
        res = run["results"][0]
        self.assertEqual(res["message"]["text"],
                         "npm:left-pad — not found in registry")
        self.assertEqual(res["properties"]["package"], "left-pad")
        self.assertEqual(res["properties"]["ecosystem"], "npm")
        self.assertEqual(res["ruleId"], "provenance/prov-not-in-registry")


class TestProvenanceRendererBoundaryDefensiveGaps(unittest.TestCase):
    """Kimi pass-3 renderer-boundary findings: severity was emitted raw
    (SARIF's own defaultConfiguration.level is fine — _sarif_level maps it —
    but a hostile/secret-shaped severity must never appear verbatim anywhere),
    and non-string rule/ecosystem crashed all three renderers because they went
    through the free-text scrub (which assumes a string) instead of a
    closed-set structural validator. None of these fields are attacker-reachable
    through the real evaluate() pipeline today (see
    tests/test_provenance.py::TestProvenanceFieldReachability) — these are
    defense-in-depth locks against a future/buggy provenance source, not live
    exploits, and are reported as such."""

    from glassport.provenance import ProvenanceFinding as _PF

    def _doc(self, pf):
        report = Report(profile={"name": "demo"}, findings=[], deductions=[],
                        score=50, grade="F", provenance=[pf])
        return sarif.render_sarif(report)

    def _pf(self, **kw):
        base = dict(rule="prov-not-in-registry", severity="high",
                    ecosystem="npm", package="left-pad",
                    manifest="package.json", detail="not found in registry")
        base.update(kw)
        return self._PF(**base)

    def test_secret_shaped_severity_never_emitted_raw(self):
        secret = "sk-ant-api03-" + "A" * 40 + "1234567890"
        doc = self._doc(self._pf(severity=secret))
        self.assertNotIn(secret, doc)
        run = json.loads(doc)["runs"][0]
        self.assertEqual(run["results"][0]["level"], "note")  # safe default

    def test_non_string_rule_does_not_crash_and_collapses_safely(self):
        for bad_rule in (["a", "b"], 12345, None, {"x": 1}):
            doc = self._doc(self._pf(rule=bad_rule))     # must not raise
            run = json.loads(doc)["runs"][0]
            res = run["results"][0]
            rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            self.assertEqual(res["ruleId"], "provenance/prov-unknown")
            self.assertIn(res["ruleId"], rule_ids)

    def test_non_string_ecosystem_does_not_crash_and_collapses_safely(self):
        for bad_eco in (["a", "b"], 12345, None, {"x": 1}):
            doc = self._doc(self._pf(ecosystem=bad_eco))  # must not raise
            res = json.loads(doc)["runs"][0]["results"][0]
            self.assertEqual(res["properties"]["ecosystem"], "unknown")

    def test_hostile_object_never_has_str_or_bool_invoked(self):
        class Hostile:
            def __str__(self):
                raise RuntimeError("str() must never be called")

            def __bool__(self):
                raise RuntimeError("bool() must never be called")

            def __eq__(self, other):
                raise RuntimeError("eq must never be called")

            def __hash__(self):
                return 0

        for field in ("rule", "ecosystem", "package", "manifest"):
            doc = self._doc(self._pf(**{field: Hostile()}))  # must not raise
            self.assertIsInstance(doc, str)

    def test_all_existing_green_locks_retained(self):
        # a minimal spot-check that the earlier obfuscation/backstop/structural
        # tests in TestProvenanceRedaction still hold after these fixes — the
        # full suite is the authoritative regression, this guards against an
        # accidental import-time or wiring break in this class specifically.
        secret = "sk-ant-api03-" + "A" * 40 + "1234567890"
        doc = self._doc(self._pf(package=secret))
        self.assertNotIn(secret, doc)


if __name__ == "__main__":
    unittest.main()
