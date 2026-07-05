"""Network-enriched audit (roadmap H2.03) — the ONLY module in glassport
that opens a socket.

Opt-in via `glassport audit --provenance`. The core audit never calls in
here, so its output stays offline-reproducible and byte-identical whether or
not the flag is passed. Provenance findings live in a separate channel
(`Report.provenance`) and NEVER affect the score. HTTP is stdlib urllib
behind an injectable `fetcher`, so the test suite runs fully offline.

Scope (this increment): npm + PyPI, direct dependencies only. GitHub,
transitive deps, and lockfiles are deliberately out.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

try:
    from glassport import __version__ as _VER
except Exception:  # pragma: no cover - UA version is best-effort
    _VER = "0"


# ─────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────
# Manifest discovery
# ─────────────────────────────────────────────────────────────────
# PEP 508 name: the leading run of name chars before any specifier/marker/extra.
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _npm_deps(text: str) -> list[tuple[str, str]]:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return []
    out: list[tuple[str, str]] = []
    for key in ("dependencies", "devDependencies"):
        section = obj.get(key) if isinstance(obj, dict) else None
        if isinstance(section, dict):
            for name, spec in section.items():
                if isinstance(name, str) and name:
                    out.append((name, spec if isinstance(spec, str) else ""))
    return out


def _req_names(text: str) -> list[str]:
    out: list[str] = []
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
    except ModuleNotFoundError:
        return _pyproject_names_fallback(text)
    try:
        obj = tomllib.loads(text)
    except Exception:
        return _pyproject_names_fallback(text)
    names: list[str] = []
    project = obj.get("project", {}) or {}
    for spec in project.get("dependencies", []) or []:
        m = _REQ_NAME.match(str(spec))
        if m:
            names.append(m.group(1))
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for spec in group or []:
            m = _REQ_NAME.match(str(spec))
            if m:
                names.append(m.group(1))
    poetry = (obj.get("tool", {}) or {}).get("poetry", {}) or {}
    for name in poetry.get("dependencies", {}) or {}:
        if name != "python":
            names.append(name)
    return names


def _pyproject_names_fallback(text: str) -> list[str]:
    # 3.10 best-effort (no tomllib): pull dependency names by line scanning.
    # Scoped by section so keywords/classifiers arrays are not mistaken for
    # dependencies. Handles both inline (`deps = ["a", "b"]`) and multi-line
    # arrays, plus the poetry `name = spec` table. Name-only by design.
    names: list[str] = []
    section = ""          # current [header]
    in_array = False      # inside a dependency array we should capture from
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line
            in_array = False
            continue
        if section.startswith("[tool.poetry.dependencies"):
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", line)
            if m and m.group(1) != "python":
                names.append(m.group(1))
            continue
        opens = False
        if "optional-dependencies]" in section:
            # every `group = [...]` in this table is a dependency array
            opens = bool(re.search(r"=\s*\[", line))
        elif section == "[project]":
            opens = bool(re.match(r"^dependencies\s*=\s*\[", line))
        if opens:
            in_array = True
        if in_array:
            names.extend(re.findall(r"""["']([A-Za-z0-9][A-Za-z0-9._-]*)""",
                                    line))
        if in_array and "]" in line:
            in_array = False
    return names


def discover_deps(root) -> list[Dep]:
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


# ─────────────────────────────────────────────────────────────────
# Registry client (stdlib urllib; never raises)
# ─────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────
# Cache — <cache_dir>/<ecosystem>/<name>.json, never expires
# ─────────────────────────────────────────────────────────────────
def _cache_path(cache_dir, dep: Dep) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._@-]", "_", dep.name)
    return Path(cache_dir) / dep.ecosystem / f"{safe}.json"


def _cache_get(cache_dir, dep: Dep) -> Optional[Fetched]:
    path = _cache_path(cache_dir, dep)
    if not path.is_file():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return Fetched(status=obj["status"], payload=obj.get("payload") or {},
                       from_cache=True)
    except Exception:
        return None


def _cache_put(cache_dir, dep: Dep, fetched: Fetched) -> None:
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


# ─────────────────────────────────────────────────────────────────
# Rubric — pure evaluate(dep, fetched, *, now); structured facts only
# ─────────────────────────────────────────────────────────────────
_STALE_DAYS = 730


def _npm_latest(payload: dict) -> dict:
    tag = (payload.get("dist-tags") or {}).get("latest")
    versions = payload.get("versions") or {}
    return versions.get(tag, {}) if isinstance(versions, dict) else {}


def _newest_date(dep: Dep, payload: dict) -> Optional[datetime]:
    raw = None
    if dep.ecosystem == "npm":
        raw = (payload.get("time") or {}).get("modified")
    else:  # pypi
        times: list[str] = []
        for files in (payload.get("releases") or {}).values():
            for f in files or []:
                t = f.get("upload_time_iso_8601") or f.get("upload_time")
                if t:
                    times.append(t)
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


def _maintainer_count(dep: Dep, payload: dict) -> Optional[int]:
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


# ─────────────────────────────────────────────────────────────────
# Orchestration
# ─────────────────────────────────────────────────────────────────
def enrich(root, *, cache_dir=None, refresh: bool = False,
           fetcher: Optional[Callable[[str, str], Fetched]] = None,
           now: Optional[datetime] = None,
           budget_s: float = 30.0) -> list[ProvenanceFinding]:
    fetcher = fetcher or fetch_registry
    now = now or datetime.now(timezone.utc)
    cache_dir = Path(cache_dir) if cache_dir else None
    deadline = time.monotonic() + budget_s

    out: list[ProvenanceFinding] = []
    unavailable = 0
    for dep in discover_deps(root):
        fetched: Optional[Fetched] = None
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
