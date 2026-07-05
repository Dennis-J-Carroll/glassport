"""H2.03 network-enriched audit — unit tests.

Every test here is offline: registry access goes through an injected fetcher
or a mocked urlopen, so the suite never opens a socket.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from glassport import audit as audit_mod
from glassport import sarif as sarif_mod
from glassport.audit import Report
from glassport.provenance import (
    Dep,
    Fetched,
    ProvenanceFinding,
    _cache_get,
    _cache_put,
    discover_deps,
    enrich,
    evaluate,
    fetch_registry,
)

NOW = datetime(2026, 7, 5, tzinfo=timezone.utc)


def _npm(name="foo", modified=None, maintainers=1, deprecated=False,
         signed=False):
    latest = {"version": "1.0.0"}
    if deprecated:
        latest["deprecated"] = "do not use"
    if signed:
        latest["dist"] = {"attestations": {"url": "x"}}
    return {
        "name": name,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": latest},
        "time": {"modified": (modified or NOW).isoformat()},
        "maintainers": [{"name": f"m{i}"} for i in range(maintainers)],
    }


class TestDataModel(unittest.TestCase):
    def test_dep_is_frozen(self):
        d = Dep(ecosystem="npm", name="left-pad", spec="^1.0.0",
                manifest="package.json")
        with self.assertRaises(FrozenInstanceError):
            d.name = "x"  # type: ignore[misc]

    def test_finding_fields(self):
        f = ProvenanceFinding(rule="prov-stale", severity="low",
                              ecosystem="pypi", package="foo",
                              manifest="requirements.txt", detail="old")
        self.assertEqual(f.severity, "low")

    def test_fetched_defaults_not_from_cache(self):
        self.assertFalse(Fetched(status="ok", payload={}).from_cache)

    def test_report_provenance_defaults_empty(self):
        r = Report(profile={}, findings=[], deductions=[], score=100,
                   grade="A")
        self.assertEqual(r.provenance, [])


class TestDiscoverDeps(unittest.TestCase):
    def _root(self, files: dict) -> Path:
        d = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (d / name).write_text(text, encoding="utf-8")
        self.addCleanup(lambda: shutil.rmtree(d))
        return d

    def test_package_json_deps_and_devdeps(self):
        root = self._root({"package.json": json.dumps({
            "dependencies": {"left-pad": "^1.0.0"},
            "devDependencies": {"jest": "29.0.0"}})})
        got = {(d.ecosystem, d.name) for d in discover_deps(root)}
        self.assertEqual(got, {("npm", "left-pad"), ("npm", "jest")})

    def test_requirements_txt_strips_specifiers_markers_comments(self):
        root = self._root({"requirements.txt":
            "requests==2.31.0\n"
            "# a comment\n"
            "\n"
            "Flask>=2.0 ; python_version >= '3.8'\n"
            "-e ./local\n"
            "-r other.txt\n"
            "urllib3[secure]~=1.26\n"})
        deps = discover_deps(root)
        self.assertEqual({d.name for d in deps},
                         {"requests", "flask", "urllib3"})
        self.assertTrue(all(d.ecosystem == "pypi" for d in deps))

    def test_pyproject_pep621_and_optional(self):
        root = self._root({"pyproject.toml":
            '[project]\n'
            'dependencies = ["httpx>=0.27", "rich"]\n'
            '[project.optional-dependencies]\n'
            'dev = ["pytest", "coverage>=7"]\n'})
        names = {d.name for d in discover_deps(root)}
        self.assertEqual(names, {"httpx", "rich", "pytest", "coverage"})

    def test_pyproject_poetry(self):
        root = self._root({"pyproject.toml":
            '[tool.poetry.dependencies]\n'
            'python = "^3.10"\n'
            'click = "^8.1"\n'})
        names = {d.name for d in discover_deps(root)}
        self.assertEqual(names, {"click"})

    def test_dedup_across_manifests(self):
        root = self._root({
            "requirements.txt": "requests==2.31.0\n",
            "pyproject.toml": '[project]\ndependencies = ["requests"]\n'})
        pypi = [d for d in discover_deps(root) if d.name == "requests"]
        self.assertEqual(len(pypi), 1)


class TestFetchRegistry(unittest.TestCase):
    def test_404_is_not_found(self):
        import urllib.error
        err = urllib.error.HTTPError("u", 404, "nf", {}, None)  # type: ignore[arg-type]
        with mock.patch("glassport.provenance.urllib.request.urlopen",
                        side_effect=err):
            got = fetch_registry("pypi", "definitely-not-real-xyz")
        self.assertEqual(got.status, "not_found")

    def test_network_error_is_error_not_raise(self):
        import urllib.error
        with mock.patch("glassport.provenance.urllib.request.urlopen",
                        side_effect=urllib.error.URLError("boom")):
            got = fetch_registry("npm", "left-pad")
        self.assertEqual(got.status, "error")
        self.assertEqual(got.payload, {})

    def test_ok_returns_parsed_json(self):
        body = b'{"name": "left-pad", "maintainers": [{"name": "a"}]}'
        resp = mock.MagicMock()
        resp.read.return_value = body
        resp.__enter__.return_value = resp
        with mock.patch("glassport.provenance.urllib.request.urlopen",
                        return_value=resp):
            got = fetch_registry("npm", "left-pad")
        self.assertEqual(got.status, "ok")
        self.assertEqual(got.payload["name"], "left-pad")

    def test_malformed_json_is_error(self):
        resp = mock.MagicMock()
        resp.read.return_value = b"not json{"
        resp.__enter__.return_value = resp
        with mock.patch("glassport.provenance.urllib.request.urlopen",
                        return_value=resp):
            got = fetch_registry("pypi", "foo")
        self.assertEqual(got.status, "error")


class TestCache(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.dir))
        self.dep = Dep(ecosystem="npm", name="left-pad", spec="",
                       manifest="package.json")

    def test_roundtrip_sets_from_cache_true(self):
        _cache_put(self.dir, self.dep,
                   Fetched(status="ok", payload={"name": "left-pad"}))
        got = _cache_get(self.dir, self.dep)
        self.assertIsNotNone(got)
        self.assertEqual(got.status, "ok")
        self.assertEqual(got.payload["name"], "left-pad")
        self.assertTrue(got.from_cache)

    def test_miss_returns_none(self):
        self.assertIsNone(_cache_get(self.dir, self.dep))

    def test_put_survives_unwritable_dir(self):
        bad = self.dir / "afile"
        bad.write_text("not a dir", encoding="utf-8")
        _cache_put(bad, self.dep, Fetched(status="ok", payload={}))


class TestEvaluate(unittest.TestCase):
    def _rules(self, findings):
        return {f.rule for f in findings}

    def test_not_in_registry_is_high(self):
        dep = Dep("pypi", "typo-squat", "", "requirements.txt")
        fs = evaluate(dep, Fetched("not_found", {}), now=NOW)
        self.assertEqual([f.rule for f in fs], ["prov-not-in-registry"])
        self.assertEqual(fs[0].severity, "high")

    def test_error_yields_nothing(self):
        dep = Dep("npm", "x", "", "package.json")
        self.assertEqual(evaluate(dep, Fetched("error", {}), now=NOW), [])

    def test_fresh_signed_multi_maintainer_is_clean(self):
        dep = Dep("npm", "good", "", "package.json")
        payload = _npm(modified=NOW, maintainers=3, signed=True)
        self.assertEqual(evaluate(dep, Fetched("ok", payload), now=NOW), [])

    def test_deprecated_is_medium(self):
        dep = Dep("npm", "old", "", "package.json")
        payload = _npm(modified=NOW, maintainers=3, signed=True,
                       deprecated=True)
        fs = evaluate(dep, Fetched("ok", payload), now=NOW)
        self.assertIn("prov-deprecated", self._rules(fs))

    def test_stale_boundary(self):
        dep = Dep("npm", "old", "", "package.json")
        just_over = NOW - timedelta(days=731)
        just_under = NOW - timedelta(days=729)
        over = evaluate(dep, Fetched("ok", _npm(modified=just_over,
                        maintainers=3, signed=True)), now=NOW)
        under = evaluate(dep, Fetched("ok", _npm(modified=just_under,
                         maintainers=3, signed=True)), now=NOW)
        self.assertIn("prov-stale", self._rules(over))
        self.assertNotIn("prov-stale", self._rules(under))

    def test_single_maintainer_note_npm_only(self):
        dep = Dep("npm", "solo", "", "package.json")
        fs = evaluate(dep, Fetched("ok", _npm(modified=NOW, maintainers=1,
                      signed=True)), now=NOW)
        self.assertIn("prov-single-maintainer", self._rules(fs))

    def test_unsigned_note(self):
        dep = Dep("npm", "nosig", "", "package.json")
        fs = evaluate(dep, Fetched("ok", _npm(modified=NOW, maintainers=3,
                      signed=False)), now=NOW)
        self.assertIn("prov-unsigned", self._rules(fs))

    def test_detail_has_no_registry_prose(self):
        dep = Dep("npm", "old", "", "package.json")
        fs = evaluate(dep, Fetched("ok", _npm(modified=NOW, maintainers=3,
                      signed=True, deprecated=True)), now=NOW)
        dep_finding = next(f for f in fs if f.rule == "prov-deprecated")
        self.assertNotIn("do not use", dep_finding.detail)


class TestEnrich(unittest.TestCase):
    def _root(self, files):
        d = Path(tempfile.mkdtemp())
        for n, t in files.items():
            (d / n).write_text(t, encoding="utf-8")
        self.addCleanup(lambda: shutil.rmtree(d))
        return d

    def test_uses_injected_fetcher_no_network(self):
        root = self._root({"requirements.txt": "typo-squat==1.0\n"})
        fs = enrich(root, fetcher=lambda eco, name: Fetched("not_found", {}),
                    now=NOW)
        self.assertEqual([f.rule for f in fs], ["prov-not-in-registry"])

    def test_error_without_cache_yields_one_aggregate_note(self):
        root = self._root({"requirements.txt": "a\nb\nc\n"})
        fs = enrich(root, fetcher=lambda eco, name: Fetched("error", {}),
                    now=NOW)
        unavail = [f for f in fs if f.rule == "prov-unavailable"]
        self.assertEqual(len(unavail), 1)
        self.assertIn("3", unavail[0].detail)

    def test_cache_hit_serves_offline(self):
        root = self._root({"package.json":
            json.dumps({"dependencies": {"left-pad": "1.0"}})})
        cache = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(cache))
        dep = Dep("npm", "left-pad", "1.0", "package.json")
        _cache_put(cache, dep, Fetched("not_found", {}))

        def forbidden(eco, name):
            raise AssertionError("network must not be called on a cache hit")

        fs = enrich(root, cache_dir=cache, fetcher=forbidden, now=NOW)
        self.assertEqual([f.rule for f in fs], ["prov-not-in-registry"])

    def test_refresh_bypasses_cache(self):
        root = self._root({"package.json":
            json.dumps({"dependencies": {"left-pad": "1.0"}})})
        cache = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(cache))
        dep = Dep("npm", "left-pad", "1.0", "package.json")
        _cache_put(cache, dep, Fetched("not_found", {}))
        called = []

        def fetcher(eco, name):
            called.append(name)
            return Fetched("ok", _npm(modified=NOW, maintainers=3, signed=True))

        fs = enrich(root, cache_dir=cache, refresh=True, fetcher=fetcher,
                    now=NOW)
        self.assertEqual(called, ["left-pad"])
        self.assertEqual(fs, [])


class TestRenderIntegration(unittest.TestCase):
    def _report(self, provenance=None):
        return Report(profile={"path": "p", "runtime": "python",
                               "files_scanned": 1,
                               "depth": {"ast": True, "pattern": True},
                               "package_name": "", "version": ""},
                      findings=[], deductions=[], score=100, grade="A",
                      provenance=provenance or [])

    def test_empty_provenance_text_byte_identical(self):
        r = self._report()
        baseline = audit_mod.render_text(
            Report(profile=r.profile, findings=[], deductions=[], score=100,
                   grade="A"))
        self.assertEqual(audit_mod.render_text(r), baseline)

    def test_empty_provenance_json_has_no_key(self):
        r = self._report()
        self.assertNotIn("provenance", json.loads(audit_mod.render_json(r)))

    def test_nonempty_provenance_text_appends_section(self):
        pf = ProvenanceFinding("prov-stale", "low", "npm", "left-pad",
                               "package.json", "old")
        out = audit_mod.render_text(self._report([pf]))
        self.assertIn("provenance (network-enriched)", out.lower())
        self.assertIn("left-pad", out)

    def test_nonempty_provenance_json_has_array(self):
        pf = ProvenanceFinding("prov-stale", "low", "npm", "left-pad",
                               "package.json", "old")
        obj = json.loads(audit_mod.render_json(self._report([pf])))
        self.assertEqual(obj["provenance"][0]["rule"], "prov-stale")


class TestSarifIntegration(unittest.TestCase):
    def _report(self, provenance):
        return Report(profile={"path": "p", "runtime": "python",
                               "files_scanned": 1,
                               "depth": {"ast": True, "pattern": True},
                               "package_name": "", "version": ""},
                      findings=[], deductions=[], score=100, grade="A",
                      provenance=provenance)

    def test_empty_provenance_sarif_byte_identical(self):
        base = sarif_mod.render_sarif(
            Report(profile=self._report([]).profile, findings=[],
                   deductions=[], score=100, grade="A"))
        self.assertEqual(sarif_mod.render_sarif(self._report([])), base)

    def test_nonempty_provenance_emits_prefixed_rule(self):
        pf = ProvenanceFinding("prov-not-in-registry", "high", "pypi",
                               "typo-squat", "requirements.txt", "missing")
        doc = json.loads(sarif_mod.render_sarif(self._report([pf])))
        results = doc["runs"][0]["results"]
        rule_ids = [r["ruleId"] for r in results]
        self.assertIn("provenance/prov-not-in-registry", rule_ids)
        prov = next(r for r in results
                    if r["ruleId"] == "provenance/prov-not-in-registry")
        self.assertEqual(prov["level"], "error")


class TestCli(unittest.TestCase):
    def _root(self, files):
        d = Path(tempfile.mkdtemp())
        for n, t in files.items():
            (d / n).write_text(t, encoding="utf-8")
        self.addCleanup(lambda: shutil.rmtree(d))
        return d

    def test_no_flag_output_unchanged(self):
        root = self._root({"requirements.txt": "requests\n"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            audit_mod.main([str(root), "--json"])
        self.assertNotIn("provenance", json.loads(out.getvalue()))

    def test_provenance_flag_populates_via_enrich(self):
        root = self._root({"requirements.txt": "typo-squat\n"})
        fake = [ProvenanceFinding("prov-not-in-registry", "high", "pypi",
                                  "typo-squat", "requirements.txt", "missing")]
        out = io.StringIO()
        with mock.patch("glassport.provenance.enrich", return_value=fake):
            with contextlib.redirect_stdout(out):
                audit_mod.main([str(root), "--provenance", "--json"])
        self.assertEqual(json.loads(out.getvalue())["provenance"][0]["rule"],
                         "prov-not-in-registry")


if __name__ == "__main__":
    unittest.main()
