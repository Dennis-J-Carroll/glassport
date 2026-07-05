# H2.03 Network-Enriched Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `glassport audit --provenance` that enriches the static audit with npm/PyPI registry facts (not-in-registry, deprecated, stale, single-maintainer, unsigned) in a separate channel that never changes the core audit's output or score.

**Architecture:** One new network-only module `provenance.py` (the sole socket-opener in the package). The core `audit_path()` is untouched; a `--provenance` branch in `audit.main()` calls `provenance.enrich(...)` and attaches the result to a new `Report.provenance` field that the default audit never populates — so text/json/sarif renders are byte-identical without the flag. HTTP is stdlib `urllib` behind an injectable `fetcher` so tests never hit the network.

**Tech Stack:** Python 3.10+ stdlib only (`urllib.request`, `json`, `dataclasses`, `datetime`; `tomllib` on 3.11+ with a name-only fallback on 3.10). No new runtime dependency.

## Global Constraints

- **Zero runtime dependency.** HTTP via `urllib.request` only — never `requests`.
- **Default audit output byte-identical with and without `--provenance`** (cache aside). Emit provenance in text/json/sarif **only when `Report.provenance` is non-empty**; never add an empty `"provenance": []` key or section.
- **Network failure never raises.** Enrichment runs after the core `Report` is built; every `fetch_*` catches all errors and returns a status, never propagates.
- **Provenance findings never affect score/grade/deductions.** They live only in `Report.provenance`, never in `Report.findings`.
- **No attacker-controlled bytes in output.** A registry `description`/`deprecated` message is attacker-controlled — findings carry glassport's own sentences and structured facts (name, date, count) only.
- **Python 3.10 support** — no `tomllib`; the pyproject parser degrades to a name-only extractor.
- **Branch:** `feat/h2-03-network-enriched-audit`. Run tests with `PYTHONPATH=src python -m unittest <target> -v`.
- **Severities** are strings `high|medium|low|note` — they set SARIF level / advisory rank only.

---

### Task 1: Data model + `Report.provenance` channel

**Files:**
- Create: `src/glassport/provenance.py`
- Modify: `src/glassport/audit.py:152-159` (the `Report` dataclass)
- Test: `tests/test_provenance.py`

**Interfaces:**
- Produces: `Dep(ecosystem:str, name:str, spec:str, manifest:str)` (frozen),
  `ProvenanceFinding(rule:str, severity:str, ecosystem:str, package:str, manifest:str, detail:str)`,
  `Fetched(status:str, payload:dict, from_cache:bool=False)` (frozen).
  `Report.provenance: list` (defaults to `[]`, holds `ProvenanceFinding`s).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_provenance.py
import unittest
from dataclasses import FrozenInstanceError

from glassport.provenance import Dep, ProvenanceFinding, Fetched
from glassport.audit import Report


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'glassport.provenance'`

- [ ] **Step 3: Write minimal implementation**

Create `src/glassport/provenance.py`:

```python
"""Network-enriched audit (roadmap H2.03) — the ONLY module in glassport
that opens a socket. Opt-in via `glassport audit --provenance`; the core
audit never calls in here, so its output stays offline-reproducible and
byte-identical. Findings live in a separate channel and never affect the
score. HTTP is stdlib urllib behind an injectable fetcher.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Dep:
    ecosystem: str      # "npm" | "pypi"
    name: str
    spec: str           # declared version spec (for finding detail)
    manifest: str       # repo-relative path (SARIF location)


@dataclass
class ProvenanceFinding:
    rule: str           # "prov-not-in-registry" | ...
    severity: str       # "high" | "medium" | "low" | "note"
    ecosystem: str
    package: str
    manifest: str
    detail: str         # glassport's own sentence; structured facts only


@dataclass(frozen=True)
class Fetched:
    status: str         # "ok" | "not_found" | "error"
    payload: dict       # {} unless status == "ok"
    from_cache: bool = False
```

In `src/glassport/audit.py`, add the field to `Report` (around line 152):

```python
@dataclass
class Report:
    profile: dict
    findings: list[Finding]
    deductions: list[dict]
    score: int
    grade: str
    rubric_version: str = RUBRIC_VERSION
    # H2.03: opt-in network-enriched findings. Holds provenance.ProvenanceFinding.
    # Default audit_path() never populates it, so every existing render path
    # stays byte-identical. Untyped list to avoid an import cycle.
    provenance: list = field(default_factory=list)
```

Confirm `field` is imported at the top of `audit.py` (it uses `@dataclass` already; the import is `from dataclasses import dataclass, field`). If `field` is missing, add it.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/glassport/provenance.py src/glassport/audit.py tests/test_provenance.py
git commit -m "feat(provenance): data model + Report.provenance channel"
```

---

### Task 2: Manifest discovery — `discover_deps(root)`

**Files:**
- Modify: `src/glassport/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `Dep` (Task 1).
- Produces: `discover_deps(root: Path) -> list[Dep]`. Reads `package.json`
  (npm: `dependencies` + `devDependencies` keys), `requirements.txt` (pypi:
  bare names), `pyproject.toml` (pypi: PEP 621 `[project].dependencies` +
  `[project.optional-dependencies]`, poetry `[tool.poetry.dependencies]`).
  Names normalized (PyPI: PEP 503 lowercase, `_`/`.`→`-`). Deduped by
  `(ecosystem, name)`. Only the top level of `root` is read (direct manifests).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
import json
import tempfile
from pathlib import Path
from glassport.provenance import discover_deps


class TestDiscoverDeps(unittest.TestCase):
    def _root(self, files: dict) -> Path:
        d = Path(tempfile.mkdtemp())
        for name, text in files.items():
            (d / name).write_text(text, encoding="utf-8")
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        return d

    def test_package_json_deps_and_devdeps(self):
        root = self._root({"package.json": json.dumps({
            "dependencies": {"left-pad": "^1.0.0"},
            "devDependencies": {"jest": "29.0.0"}})})
        deps = discover_deps(root)
        got = {(d.ecosystem, d.name) for d in deps}
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
        names = {d.name for d in discover_deps(root)}
        self.assertEqual(names, {"requests", "flask", "urllib3"})
        self.assertTrue(all(d.ecosystem == "pypi" for d in discover_deps(root)))

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
        self.assertEqual(names, {"click"})  # 'python' is not a package

    def test_dedup_across_manifests(self):
        root = self._root({
            "requirements.txt": "requests==2.31.0\n",
            "pyproject.toml": '[project]\ndependencies = ["requests"]\n'})
        pypi = [d for d in discover_deps(root) if d.name == "requests"]
        self.assertEqual(len(pypi), 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestDiscoverDeps -v`
Expected: FAIL — `ImportError: cannot import name 'discover_deps'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/glassport/provenance.py`:

```python
import json
import re
from pathlib import Path

# PEP 508 name is the leading run of name chars before any specifier/marker/extra.
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _npm_deps(text: str) -> list[tuple[str, str]]:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []
    out = []
    for key in ("dependencies", "devDependencies"):
        section = obj.get(key)
        if isinstance(section, dict):
            for name, spec in section.items():
                if isinstance(name, str) and name:
                    out.append((name, spec if isinstance(spec, str) else ""))
    return out


def _req_names(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_NAME.match(line)
        if m:
            out.append(m.group(1))
    return out


def _pyproject_names(text: str) -> list[str]:
    # Prefer a real TOML parse (3.11+); fall back to a name-only extractor on
    # 3.10 — we only need dependency names, not full resolution.
    try:
        import tomllib  # type: ignore[import-not-found]
        obj = tomllib.loads(text)
        names: list[str] = []
        project = obj.get("project", {})
        for spec in project.get("dependencies", []) or []:
            m = _REQ_NAME.match(str(spec))
            if m:
                names.append(m.group(1))
        for group in (project.get("optional-dependencies", {}) or {}).values():
            for spec in group or []:
                m = _REQ_NAME.match(str(spec))
                if m:
                    names.append(m.group(1))
        poetry = obj.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name in poetry:
            if name != "python":
                names.append(name)
        return names
    except ModuleNotFoundError:
        return _pyproject_names_fallback(text)


def _pyproject_names_fallback(text: str) -> list[str]:
    # 3.10 best-effort: pull names from dependency arrays and poetry tables by
    # line scanning. Handles the common flat forms; documented as name-only.
    names: list[str] = []
    in_poetry = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_poetry = line.startswith("[tool.poetry.dependencies")
            continue
        if in_poetry:
            m = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=', line)
            if m and m.group(1) != "python":
                names.append(m.group(1))
            continue
        # array entries like:  "httpx>=0.27",
        m = re.match(r'^["\']([A-Za-z0-9][A-Za-z0-9._-]*)', line)
        if m:
            names.append(m.group(1))
    return names


def discover_deps(root: Path) -> list[Dep]:
    root = Path(root)
    seen: set[tuple[str, str]] = set()
    out: list[Dep] = []

    def add(ecosystem: str, name: str, spec: str, manifest: str) -> None:
        key = (ecosystem, name)
        if name and key not in seen:
            seen.add(key)
            out.append(Dep(ecosystem=ecosystem, name=name, spec=spec,
                           manifest=manifest))

    pkg = root / "package.json"
    if pkg.is_file():
        for name, spec in _npm_deps(pkg.read_text(encoding="utf-8",
                                                  errors="replace")):
            add("npm", name, spec, "package.json")

    req = root / "requirements.txt"
    if req.is_file():
        for name in _req_names(req.read_text(encoding="utf-8",
                                             errors="replace")):
            add("pypi", _norm_pypi(name), "", "requirements.txt")

    pyp = root / "pyproject.toml"
    if pyp.is_file():
        for name in _pyproject_names(pyp.read_text(encoding="utf-8",
                                                    errors="replace")):
            add("pypi", _norm_pypi(name), "", "pyproject.toml")

    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestDiscoverDeps -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Verify the 3.10 fallback path**

Temporarily force the fallback and re-run one test to prove it works without `tomllib`:

Run: `PYTHONPATH=src python -c "import glassport.provenance as p; print(p._pyproject_names_fallback('[project]\ndependencies = [\"httpx>=0.27\", \"rich\"]\n'))"`
Expected: `['httpx', 'rich']`

- [ ] **Step 6: Commit**

```bash
git add src/glassport/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): manifest discovery for npm/pypi (3.10 fallback)"
```

---

### Task 3: Registry client — `fetch_registry`

**Files:**
- Modify: `src/glassport/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `Fetched` (Task 1).
- Produces: `fetch_registry(ecosystem: str, name: str, *, timeout: float = 5.0) -> Fetched`.
  npm URL `https://registry.npmjs.org/<name>`, PyPI URL
  `https://pypi.org/pypi/<name>/json`. Sets `User-Agent`. 404 → status
  `not_found`; any other exception / non-200 / bad JSON → status `error`.
  Never raises. This is the default fetcher; `enrich` accepts an override.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
from unittest import mock
from glassport.provenance import fetch_registry, Fetched


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestFetchRegistry -v`
Expected: FAIL — `ImportError: cannot import name 'fetch_registry'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/glassport/provenance.py` (imports at top with the others):

```python
import urllib.error
import urllib.request

try:
    from glassport import __version__ as _VER
except Exception:  # pragma: no cover - version is best-effort in UA
    _VER = "0"

_REGISTRY = {
    "npm": "https://registry.npmjs.org/{name}",
    "pypi": "https://pypi.org/pypi/{name}/json",
}


def fetch_registry(ecosystem: str, name: str, *, timeout: float = 5.0) -> Fetched:
    url = _REGISTRY.get(ecosystem, "").format(name=name)
    if not url:
        return Fetched(status="error", payload={})
    req = urllib.request.Request(
        url, headers={"User-Agent": f"glassport/{_VER}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return Fetched(status="ok", payload=json.loads(data))
    except urllib.error.HTTPError as exc:
        return Fetched(status="not_found" if exc.code == 404 else "error",
                       payload={})
    except Exception:
        # timeout, DNS, connection reset, bad JSON — never propagate.
        return Fetched(status="error", payload={})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestFetchRegistry -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/glassport/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): stdlib urllib registry client, never raises"
```

---

### Task 4: Cache — `_cache_get` / `_cache_put`

**Files:**
- Modify: `src/glassport/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `Dep`, `Fetched` (Task 1).
- Produces: `_cache_get(cache_dir: Path, dep: Dep) -> Fetched | None`,
  `_cache_put(cache_dir: Path, dep: Dep, fetched: Fetched) -> None`.
  Path `<cache_dir>/<ecosystem>/<name>.json` storing
  `{"fetched_at": iso, "status": ..., "payload": ...}`. Never expires. Put
  swallows write errors (unwritable dir warns to stderr, continues).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
from glassport.provenance import _cache_get, _cache_put


class TestCache(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir))
        self.dep = Dep(ecosystem="npm", name="left-pad", spec="",
                       manifest="package.json")

    def test_roundtrip_sets_from_cache_true(self):
        _cache_put(self.dir, self.dep, Fetched(status="ok",
                                               payload={"name": "left-pad"}))
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
        # Should not raise even though <bad>/npm/left-pad.json is impossible.
        _cache_put(bad, self.dep, Fetched(status="ok", payload={}))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestCache -v`
Expected: FAIL — `ImportError: cannot import name '_cache_get'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/glassport/provenance.py` (add `import sys` and
`from datetime import datetime, timezone` at top):

```python
def _cache_path(cache_dir: Path, dep: Dep) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._@-]", "_", dep.name)
    return Path(cache_dir) / dep.ecosystem / f"{safe}.json"


def _cache_get(cache_dir: Path, dep: Dep) -> "Fetched | None":
    path = _cache_path(cache_dir, dep)
    if not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return Fetched(status=obj["status"], payload=obj.get("payload") or {},
                       from_cache=True)
    except Exception:
        return None


def _cache_put(cache_dir: Path, dep: Dep, fetched: Fetched) -> None:
    path = _cache_path(cache_dir, dep)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "status": fetched.status,
            "payload": fetched.payload,
        }), encoding="utf-8")
    except OSError as exc:
        print(f"[glassport] provenance cache write failed for "
              f"{dep.ecosystem}:{dep.name} ({exc}); continuing without cache",
              file=sys.stderr)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestCache -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/glassport/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): never-expire on-disk cache, write-safe"
```

---

### Task 5: Rubric — `evaluate(dep, fetched, *, now)`

**Files:**
- Modify: `src/glassport/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `Dep`, `Fetched` (Task 1).
- Produces: `evaluate(dep: Dep, fetched: Fetched, *, now: datetime) -> list[ProvenanceFinding]`.
  Pure. Rules: `prov-not-in-registry`(high) when `status=="not_found"`;
  `prov-deprecated`(medium); `prov-stale`(low) when newest release > 730 days
  before `now`; `prov-single-maintainer`(note, npm only) when maintainers==1;
  `prov-unsigned`(note) when no attestation on latest. `status=="error"`
  yields no findings (the aggregate unavailable note is added by `enrich`).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
from datetime import datetime, timezone, timedelta
from glassport.provenance import evaluate

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
        # The 'deprecated' message from the registry must not leak into detail.
        dep = Dep("npm", "old", "", "package.json")
        fs = evaluate(dep, Fetched("ok", _npm(modified=NOW, maintainers=3,
                      signed=True, deprecated=True)), now=NOW)
        dep_finding = next(f for f in fs if f.rule == "prov-deprecated")
        self.assertNotIn("do not use", dep_finding.detail)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestEvaluate -v`
Expected: FAIL — `ImportError: cannot import name 'evaluate'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/glassport/provenance.py`:

```python
_STALE_DAYS = 730


def _npm_latest(payload: dict) -> dict:
    tag = (payload.get("dist-tags") or {}).get("latest")
    versions = payload.get("versions") or {}
    return versions.get(tag, {}) if isinstance(versions, dict) else {}


def _newest_date(dep: Dep, payload: dict) -> "datetime | None":
    raw = None
    if dep.ecosystem == "npm":
        raw = (payload.get("time") or {}).get("modified")
    else:  # pypi
        times = []
        for files in (payload.get("releases") or {}).values():
            for f in files or []:
                t = f.get("upload_time_iso_8601") or f.get("upload_time")
                if t:
                    times.append(t)
        # also the flat urls[] of the latest release
        for f in payload.get("urls") or []:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if t:
                times.append(t)
        raw = max(times) if times else None
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_deprecated(dep: Dep, payload: dict) -> bool:
    if dep.ecosystem == "npm":
        return "deprecated" in _npm_latest(payload)
    return bool((payload.get("info") or {}).get("yanked"))


def _maintainer_count(dep: Dep, payload: dict) -> "int | None":
    if dep.ecosystem == "npm":
        m = payload.get("maintainers")
        return len(m) if isinstance(m, list) else None
    return None  # PyPI JSON has no reliable maintainer count


def _has_attestation(dep: Dep, payload: dict) -> bool:
    if dep.ecosystem == "npm":
        dist = _npm_latest(payload).get("dist") or {}
        return bool(dist.get("attestations") or dist.get("signatures"))
    for f in payload.get("urls") or []:
        if f.get("provenance") or f.get("attestations"):
            return True
    return False


def _pf(dep: Dep, rule: str, severity: str, detail: str) -> ProvenanceFinding:
    return ProvenanceFinding(rule=rule, severity=severity,
                             ecosystem=dep.ecosystem, package=dep.name,
                             manifest=dep.manifest, detail=detail)


def evaluate(dep: Dep, fetched: Fetched, *, now: datetime) -> list[ProvenanceFinding]:
    if fetched.status == "not_found":
        return [_pf(dep, "prov-not-in-registry", "high",
                    f"declared dependency not found in the {dep.ecosystem} "
                    f"registry (possible typosquat or private-name confusion)")]
    if fetched.status != "ok":
        return []  # 'error' handled by enrich as an aggregate note

    out: list[ProvenanceFinding] = []
    payload = fetched.payload

    if _is_deprecated(dep, payload):
        word = "yanked" if dep.ecosystem == "pypi" else "deprecated"
        out.append(_pf(dep, "prov-deprecated", "medium",
                       f"the latest release is marked {word} by the registry"))

    newest = _newest_date(dep, payload)
    if newest is not None:
        age = (now - newest).days
        if age > _STALE_DAYS:
            out.append(_pf(dep, "prov-stale", "low",
                           f"newest release is {age} days old "
                           f"(> {_STALE_DAYS}); the package may be unmaintained"))

    count = _maintainer_count(dep, payload)
    if count == 1:
        out.append(_pf(dep, "prov-single-maintainer", "note",
                       "the package has a single maintainer (bus-factor 1)"))

    if not _has_attestation(dep, payload):
        out.append(_pf(dep, "prov-unsigned", "note",
                       "no build provenance / signature attestation on the "
                       "latest release"))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestEvaluate -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/glassport/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): balanced rubric, structured facts only"
```

---

### Task 6: Orchestration — `enrich(...)`

**Files:**
- Modify: `src/glassport/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `discover_deps`, `fetch_registry`, `_cache_get`, `_cache_put`,
  `evaluate` (Tasks 2–5).
- Produces: `enrich(root, *, cache_dir=None, refresh=False, fetcher=None, now=None, budget_s=30.0) -> list[ProvenanceFinding]`.
  `fetcher` signature `Callable[[str, str], Fetched]` defaulting to
  `fetch_registry`. Walks deps; uses cache unless `refresh`; on `error` with
  no cache, counts toward one aggregate `prov-unavailable` note; a time
  budget past `budget_s` marks remaining deps unavailable without calling out.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
from glassport.provenance import enrich


class TestEnrich(unittest.TestCase):
    def _root(self, files):
        d = Path(tempfile.mkdtemp())
        for n, t in files.items():
            (d / n).write_text(t, encoding="utf-8")
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
        return d

    def test_uses_injected_fetcher_no_network(self):
        root = self._root({"requirements.txt": "typo-squat==1.0\n"})
        fetcher = lambda eco, name: Fetched("not_found", {})
        fs = enrich(root, fetcher=fetcher, now=NOW)
        self.assertEqual([f.rule for f in fs], ["prov-not-in-registry"])

    def test_error_without_cache_yields_one_aggregate_note(self):
        root = self._root({"requirements.txt": "a\nb\nc\n"})
        fetcher = lambda eco, name: Fetched("error", {})
        fs = enrich(root, fetcher=fetcher, now=NOW)
        unavail = [f for f in fs if f.rule == "prov-unavailable"]
        self.assertEqual(len(unavail), 1)
        self.assertIn("3", unavail[0].detail)  # 3 packages unavailable

    def test_cache_hit_serves_offline(self):
        root = self._root({"package.json":
            json.dumps({"dependencies": {"left-pad": "1.0"}})})
        cache = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(cache))
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
        self.addCleanup(lambda: __import__("shutil").rmtree(cache))
        dep = Dep("npm", "left-pad", "1.0", "package.json")
        _cache_put(cache, dep, Fetched("not_found", {}))
        called = []

        def fetcher(eco, name):
            called.append(name)
            return Fetched("ok", _npm(modified=NOW, maintainers=3, signed=True))

        fs = enrich(root, cache_dir=cache, refresh=True, fetcher=fetcher,
                    now=NOW)
        self.assertEqual(called, ["left-pad"])
        self.assertEqual(fs, [])  # fresh data is clean
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestEnrich -v`
Expected: FAIL — `ImportError: cannot import name 'enrich'`

- [ ] **Step 3: Write minimal implementation**

Add to `src/glassport/provenance.py` (add `import time` at top):

```python
def enrich(root, *, cache_dir=None, refresh=False, fetcher=None, now=None,
           budget_s: float = 30.0) -> list[ProvenanceFinding]:
    fetcher = fetcher or fetch_registry
    now = now or datetime.now(timezone.utc)
    cache_dir = Path(cache_dir) if cache_dir else None
    deadline = time.monotonic() + budget_s

    out: list[ProvenanceFinding] = []
    unavailable = 0
    for dep in discover_deps(root):
        fetched = None
        if cache_dir is not None and not refresh:
            fetched = _cache_get(cache_dir, dep)
        if fetched is None:
            if time.monotonic() > deadline:
                fetched = Fetched("error", {})  # budget spent; do not call out
            else:
                fetched = fetcher(dep.ecosystem, dep.name)
                if cache_dir is not None:
                    _cache_put(cache_dir, dep, fetched)
        if fetched.status == "error" and not fetched.from_cache:
            unavailable += 1
            continue
        out.extend(evaluate(dep, fetched, now=now))

    if unavailable:
        out.append(ProvenanceFinding(
            rule="prov-unavailable", severity="note", ecosystem="",
            package="", manifest="",
            detail=f"{unavailable} dependenc"
                   f"{'y' if unavailable == 1 else 'ies'} could not be checked "
                   f"(registry unreachable and no cache); provenance is "
                   f"incomplete"))
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestEnrich -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/glassport/provenance.py tests/test_provenance.py
git commit -m "feat(provenance): enrich orchestration — cache, budget, aggregate note"
```

---

### Task 7: Render integration — text + json, byte-identical default

**Files:**
- Modify: `src/glassport/audit.py:558-597` (`render_text`, `render_json`)
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `Report.provenance` (Task 1), `ProvenanceFinding` (Task 1).
- Produces: `render_text`/`render_json` append provenance **only when
  `report.provenance` is non-empty**. Empty → output unchanged (byte-identical).

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
from glassport import audit as audit_mod


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
        # A default report and one with an explicit empty list must match.
        baseline = audit_mod.render_text(
            Report(profile=r.profile, findings=[], deductions=[], score=100,
                   grade="A"))
        self.assertEqual(audit_mod.render_text(r), baseline)
        self.assertNotIn("provenance", audit_mod.render_text(r).lower()
                         .replace("provenance:", ""))  # no new section

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestRenderIntegration -v`
Expected: FAIL — `test_nonempty_*` fail (section/array missing)

- [ ] **Step 3: Write minimal implementation**

In `src/glassport/audit.py`, in `render_text`, immediately before the final
`out.append(f"rubric:   ...")` line, insert:

```python
    if report.provenance:
        out.append("provenance (network-enriched):")
        for pf in report.provenance:
            where = f" [{pf.ecosystem}:{pf.package}]" if pf.package else ""
            out.append(f"  [{pf.severity}] {pf.rule}{where}")
            out.append(f"      {pf.detail}")
```

In `render_json`, build the base dict then conditionally add the key so the
default stays byte-identical:

```python
def render_json(report: Report) -> str:
    obj = {
        "rubric_version": report.rubric_version,
        "profile": report.profile,
        "score": report.score,
        "grade": report.grade,
        "deductions": report.deductions,
        "findings": [vars(f) for f in report.findings],
    }
    if report.provenance:
        obj["provenance"] = [vars(pf) for pf in report.provenance]
    return json.dumps(obj, indent=2, ensure_ascii=False)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestRenderIntegration -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/glassport/audit.py tests/test_provenance.py
git commit -m "feat(provenance): text/json render, byte-identical when empty"
```

---

### Task 8: SARIF integration — separate `provenance` category

**Files:**
- Modify: `src/glassport/sarif.py` (`render_sarif`, add provenance results)
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `Report.provenance`, `ProvenanceFinding`, `_sarif_level` (existing).
- Produces: `render_sarif(report, base="")` appends one SARIF result per
  provenance finding under rule ids prefixed `provenance/<rule>`, only when
  `report.provenance` is non-empty. Reuses `_sarif_level` for the level.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
from glassport import sarif as sarif_mod


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
        self.assertEqual(prov["level"], "error")  # high -> error
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestSarifIntegration -v`
Expected: FAIL — `test_nonempty_*` (no provenance results)

- [ ] **Step 3: Write minimal implementation**

Read `render_sarif` in `src/glassport/sarif.py` to find where per-finding
`results` are assembled and the list is attached to `runs[0]["results"]`.
After the existing results are built and before the document is serialized,
append provenance results:

```python
    for pf in getattr(report, "provenance", None) or []:
        results.append({
            "ruleId": f"provenance/{pf.rule}",
            "level": _sarif_level(pf.severity),
            "message": {"text": _sanitize_prov(pf)},
            "properties": {"category": "provenance",
                           "ecosystem": pf.ecosystem, "package": pf.package},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": (base.rstrip("/") + "/" + pf.manifest).lstrip("/")
                       if base and pf.manifest else pf.manifest}}}]
            if pf.manifest else [],
        })
```

Add a small helper near the top of the results assembly (glassport's own
sentence only — `pf.detail` is already glassport-authored, but keep the
package/ecosystem structured):

```python
def _sanitize_prov(pf) -> str:
    return f"{pf.ecosystem}:{pf.package} — {pf.detail}" if pf.package \
        else pf.detail
```

Match the exact variable name the function uses for the results list (it may
be `results` or built inline); if the results are constructed with a
comprehension assigned to the run dict, refactor to a named `results` list
first, then append. Do not change any existing result's shape.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestSarifIntegration -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the SARIF red-team grill to prove no poisoning regression**

Run: `PYTHONPATH=src python dogfood/eval_sarif_redteam.py`
Expected: all S-cases PASS

- [ ] **Step 6: Commit**

```bash
git add src/glassport/sarif.py tests/test_provenance.py
git commit -m "feat(provenance): separate SARIF category, byte-identical when empty"
```

---

### Task 9: CLI wiring — `audit --provenance [--provenance-cache DIR] [--provenance-refresh]`

**Files:**
- Modify: `src/glassport/audit.py:615-644` (`main`)
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: `enrich` (Task 6), `audit_path` (existing), the renders (Tasks 7–8).
- Produces: `audit.main(argv)` parses `--provenance`, `--provenance-cache DIR`,
  `--provenance-refresh`; when `--provenance` is present, calls `enrich` and
  assigns `report.provenance`. Without the flag, `main` is unchanged.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/test_provenance.py
import io
import contextlib
from unittest import mock


class TestCli(unittest.TestCase):
    def _root(self, files):
        d = Path(tempfile.mkdtemp())
        for n, t in files.items():
            (d / n).write_text(t, encoding="utf-8")
        self.addCleanup(lambda: __import__("shutil").rmtree(d))
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestCli -v`
Expected: FAIL — `test_provenance_flag_*` (flag not parsed; unknown-arg usage error)

- [ ] **Step 3: Write minimal implementation**

In `src/glassport/audit.py` `main`, after the `--sarif` removal block and
before the `if len(args) != 1` check, parse the provenance flags:

```python
    provenance = "--provenance" in args
    if provenance:
        args.remove("--provenance")
    refresh = "--provenance-refresh" in args
    if refresh:
        args.remove("--provenance-refresh")
        provenance = True  # refresh implies enrichment
    cache_dir = None
    if "--provenance-cache" in args:
        i = args.index("--provenance-cache")
        try:
            cache_dir = args[i + 1]
            del args[i:i + 2]
            provenance = True
        except IndexError:
            print("usage: audit.py <path> --provenance-cache <dir>",
                  file=sys.stderr)
            return 2
```

Then, right after `report = audit_path(target)`:

```python
    if provenance:
        from glassport.provenance import enrich
        report.provenance = enrich(target, cache_dir=cache_dir,
                                   refresh=refresh)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python -m unittest tests.test_provenance.TestCli -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Update help text**

In `src/glassport/tap.py`, update the `audit:` line in the help block (around
line 676) to read:

```
  audit:           glassport audit <path> [--json|--sarif]
                        [--provenance [--provenance-cache DIR]
                         [--provenance-refresh]] | audit --rubric
                   (--provenance: opt-in npm/PyPI registry enrichment;
                    off by default so the core audit stays offline)
```

- [ ] **Step 6: Commit**

```bash
git add src/glassport/audit.py src/glassport/tap.py tests/test_provenance.py
git commit -m "feat(provenance): audit --provenance CLI wiring + help"
```

---

### Task 10: Full-suite guard, example manifest, README, STATUS

**Files:**
- Create: `examples/pii-azure.json`? — NO. Create nothing here except docs.
- Modify: `README.md` (audit section), `STATUS.md` (Tier 1 row + next action)
- Test: run the full suite + grills

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Run the full suite**

Run: `PYTHONPATH=src python -m unittest discover -s tests -t .`
Expected: OK — the pre-existing count plus the new `test_provenance` tests,
zero network calls (all use injected fetchers / mocks).

- [ ] **Step 2: Prove the byte-identical invariant end-to-end**

Run:
```bash
PYTHONPATH=src python -m glassport.tap audit src --json > /tmp/a.json
PYTHONPATH=src python -m glassport.tap audit src --json > /tmp/b.json
diff /tmp/a.json /tmp/b.json && echo "BYTE-IDENTICAL default OK"
```
Expected: no diff; the default audit is deterministic and provenance-free.

- [ ] **Step 3: Smoke-test the real network path (opt-in, not a CI test)**

Run (network required; skip if offline):
```bash
PYTHONPATH=src python -m glassport.tap audit . --provenance --json | python3 -c "import json,sys; d=json.load(sys.stdin); print('provenance findings:', len(d.get('provenance', [])))"
```
Expected: prints a count; no traceback even if some registries are slow.

- [ ] **Step 4: Update README audit section**

Add a subsection under the audit docs describing `--provenance`,
`--provenance-cache`, `--provenance-refresh`, the offline-default guarantee,
and that provenance findings never affect the score. Note the npm+PyPI scope
and that GitHub is a later increment.

- [ ] **Step 5: Update STATUS.md**

Add a Tier-1 row for network-enriched audit and update the "Next action"
section to mark H2.03 shipped and point to the next H2 item (H2.01
streamable-HTTP or H2.06 property tests).

- [ ] **Step 6: Run grills + commit**

```bash
PYTHONPATH=src python dogfood/eval_sarif_redteam.py
PYTHONPATH=src python dogfood/eval_advise_redteam.py
git add README.md STATUS.md
git commit -m "docs(provenance): README + STATUS for H2.03 network-enriched audit"
```

---

## Self-Review

**Spec coverage:**
- Manifest discovery (npm/PyPI, 3.10 fallback) → Task 2 ✓
- Registry client (urllib, timeout, never raises) → Task 3 ✓
- Cache (never-expire, write-safe) → Task 4 ✓
- Rubric (all 5 signals + no prose leak) → Task 5 ✓
- Enrich (cache, refresh, budget, aggregate unavailable) → Task 6 ✓
- Byte-identical default (text/json/sarif) → Tasks 7, 8, 10-step2 ✓
- Separate `provenance` SARIF category → Task 8 ✓
- CLI flags → Task 9 ✓
- Score never affected → guaranteed by the separate `Report.provenance` field (Task 1); no task ever adds to `Report.findings`/`deductions` ✓
- Injected fetcher / offline tests → Tasks 3,5,6,9 all use mocks/fakes ✓

**Placeholder scan:** No TBD/TODO; every code step has full code. Task 8 step 3 asks the implementer to match the existing `results` variable name in `render_sarif` — that is a real, bounded instruction (the exact shape is given), not a placeholder.

**Type consistency:** `Dep(ecosystem,name,spec,manifest)`, `ProvenanceFinding(rule,severity,ecosystem,package,manifest,detail)`, `Fetched(status,payload,from_cache)`, `evaluate(dep,fetched,*,now)`, `enrich(root,*,cache_dir,refresh,fetcher,now,budget_s)` — used identically across Tasks 1–9. `fetcher` signature `(ecosystem, name) -> Fetched` matches `fetch_registry(ecosystem, name, *, timeout)` (enrich calls it positionally with two args) ✓.

**Note for Task 8:** before writing, read `render_sarif` to confirm whether results are assembled into a named list; if built inline, refactor to a `results` list first (behavior-preserving) so the append point exists.
