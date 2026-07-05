# H2.03 — Network-enriched audit (opt-in)

**Roadmap item:** Horizon 2 · H2.03 · AUDIT. First H2 item after Horizon 1 close-out.
**Date:** 2026-07-05 · **Baseline:** v0.6.3.
**Scope of this increment:** npm + PyPI, direct dependencies only. GitHub,
transitive deps, and lockfile parsing are explicitly out (see Out of Scope).

## Problem

The static audit reads *source* and never runs it — reproducible and offline,
which is a deliberate strength. But it cannot see facts that live off-machine: is
a declared dependency a real published package or a typosquat? Is it deprecated,
abandoned, single-maintainer, unsigned? Those are provenance signals, and they
require the network.

The tension: glassport is zero-runtime-dependency and its core audit is
offline-reproducible. Network enrichment must therefore be **strictly opt-in and
strictly additive** — invisible unless asked for, and incapable of changing the
core audit's output or breaking it when the network is down.

## Doctrine constraints (load-bearing)

1. **Zero runtime dependency.** HTTP via stdlib `urllib.request` only. No `requests`.
2. **Default audit byte-identical with and without `--provenance`** (cache aside).
   This is the roadmap exit criterion and the primary invariant a test locks.
3. **Network failure never breaks the core audit.** Enrichment runs *after* the
   core audit has already produced its Report; every network error degrades to a
   finding, never an exception.
4. **No attacker-controlled bytes in output.** A registry `description` /
   `deprecated` message is attacker-controlled. Provenance findings carry
   glassport's own sentences and structured facts (name, date, count), never
   echoed registry prose — same posture as `advise`/`report`/`sarif`.
5. **Python 3.10 support** — no `tomllib` in the stdlib there; the pyproject
   parser degrades to a name-only extractor.

## Architecture

One new module, `src/glassport/provenance.py`, is the **only** code in the
package that opens a socket. `audit.py`'s existing functions are untouched on the
default path. Integration is a thin CLI branch:

```
glassport audit <path>                       # unchanged, offline, byte-identical
glassport audit <path> --provenance [...]     # core audit THEN enrich
```

```
core audit (audit_path) ──► Report(findings, score, grade, provenance=[])
                                                              │
                    --provenance only:                        ▼
   provenance.enrich(root, cache_dir, refresh, fetcher) ──► Report.provenance
                                                              │
                          render_text / render_json / render_sarif read
                          Report.provenance ONLY when non-empty
```

`Report` gains one field:

```python
@dataclass
class Report:
    ...
    provenance: list[ProvenanceFinding] = field(default_factory=list)
```

Default `audit_path()` never populates it, so every existing render path is
byte-identical. The renderers append a clearly separated "Provenance
(network-enriched)" section / `provenance` JSON array / SARIF category **only when
the list is non-empty**.

### Five isolated units in `provenance.py`

Each has one purpose, a typed interface, and is independently testable.

**1. Manifest discovery** — `discover_deps(root) -> list[Dep]`
- `package.json`: `json.loads`; union of `dependencies` + `devDependencies` keys.
- `requirements.txt`: line parser. Strip comments (`#`), blank lines, `-e`/`-r`
  includes, environment markers (`; python_version…`), and version specifiers
  (`==`, `>=`, `~=`, `<`, `>`, `!=`, `[extras]`). Yield the bare distribution name.
- `pyproject.toml`: PEP 621 `[project].dependencies` + `[project.optional-dependencies]`,
  and poetry `[tool.poetry.dependencies]`. `try: import tomllib` (3.11+); on 3.10,
  a narrow fallback that extracts dependency *names* from the relevant arrays/tables
  via targeted line scanning (names are all the rubric needs; documented best-effort).
- Requirement names normalized (PEP 503 lowercase, `_`→`-` for PyPI). Deduped.
- `Dep = (ecosystem, name, spec, manifest)` where `manifest` is the repo-relative
  path used as the SARIF location.

**2. Registry client** — `fetch_npm(name)` / `fetch_pypi(name)`
- `urllib.request` GET with `User-Agent: glassport/<ver>`, **per-request timeout 5s**.
- npm: `https://registry.npmjs.org/<name>`. PyPI: `https://pypi.org/pypi/<name>/json`.
- Returns `Fetched(status, payload)` where status ∈ {`ok`, `not_found`, `error`}.
  404 → `not_found`; any other exception/5xx → `error`. Never raises.
- A **total wall-clock budget (~30s)** across all packages: once exceeded, remaining
  uncached packages resolve to `error` without a network call, so a slow registry
  can't stall an audit unboundedly.
- Injectable: `enrich(..., fetcher=...)` takes the client so tests pass a fake and
  never touch the network.

**3. Cache** — `<cache_dir>/<ecosystem>/<name>.json`
- Stores `{"fetched_at": iso, "status": ..., "payload": ...}`.
- **Never expires.** A cache hit is used regardless of age — air-gapped
  reproducibility is the point. `--provenance-refresh` bypasses the read (still
  writes the fresh result).
- Unwritable cache dir → warn to stderr, proceed without caching (mirrors the tap's
  log-dir degradation). Absent `--provenance-cache` → no caching at all.

**4. Rubric** — `evaluate(dep, fetched, *, now) -> list[ProvenanceFinding]`
- Pure function over the fetched payload + an injected clock (`now`) for
  deterministic staleness tests. No I/O.
- Balanced starter mapping:

| rule id | signal | severity* |
|---|---|---|
| `prov-not-in-registry` | status == not_found (404) | high |
| `prov-deprecated` | npm `deprecated` present / PyPI latest `yanked` | medium |
| `prov-stale` | newest release upload_time > 2 years before `now` | low |
| `prov-single-maintainer` | npm `maintainers` length == 1 | note |
| `prov-unsigned` | no npm provenance/signature attestation on latest dist | note |
| `prov-unavailable` | status == error AND no cache | note (emitted **once** per audit, aggregated, not per package) |

  *severity sets the SARIF level and advisory rank **only**. Provenance findings
  are NEVER added to `Report.findings`, NEVER produce deductions, NEVER change the
  score or grade. PyPI single-maintainer is skipped (the JSON has no reliable
  maintainer count); documented as an npm-only signal this increment.

**5. SARIF integration** — in `sarif.py`
- Provenance findings render under a distinct `provenance` category (rule ids
  prefixed `provenance/`), appended only when `Report.provenance` is non-empty.
- Reuses `_sarif_level` (the single severity vocabulary) so `high/medium/low/note`
  fold onto `error/warning/note` exactly as the static rules do.
- A no-`--provenance` audit emits SARIF **byte-identical** to today.

### `enrich()` orchestration

```python
def enrich(root, *, cache_dir=None, refresh=False,
           fetcher=None, now=None, budget_s=30.0) -> list[ProvenanceFinding]:
    deps = discover_deps(root)
    out, unavailable = [], 0
    for dep in deps:
        fetched = _cached_or_fetch(dep, cache_dir, refresh, fetcher, budget)
        if fetched.status == "error" and not was_cached:
            unavailable += 1
            continue
        out.extend(evaluate(dep, fetched, now=now))
    if unavailable:
        out.append(_unavailable_finding(unavailable))  # one aggregate note
    return out
```

## Data model

```python
@dataclass(frozen=True)
class Dep:
    ecosystem: str      # "npm" | "pypi"
    name: str
    spec: str           # declared version spec (for finding detail)
    manifest: str       # repo-relative path (SARIF location)

@dataclass
class ProvenanceFinding:
    rule: str           # "prov-not-in-registry" | ...
    severity: str       # high|medium|low|note — SARIF level / rank ONLY
    ecosystem: str
    package: str
    manifest: str
    detail: str         # glassport's own sentence; structured facts only
```

## CLI

```
glassport audit <path> [--provenance] [--provenance-cache DIR]
                       [--provenance-refresh] [--json | --sarif]
```

- No `--provenance`: identical to today.
- `--provenance` without `--provenance-cache`: enrich, no caching.
- `--provenance-refresh` implies enrichment; forces re-fetch past the cache.
- Text render: a "Provenance (network-enriched)" section **after** the scored
  findings, visually separated, each line `[severity] rule  ecosystem:package —
  detail`. JSON: a top-level `provenance` array. SARIF: the extra category.
- Help text and README updated; the offline/reproducible default is stated.

## Error handling (doctrine-critical)

- Core audit completes and is returned *before* any network call; enrichment only
  appends. A total enrichment failure yields a Report identical to the offline one
  plus a single `prov-unavailable` note.
- Every `fetch_*` catches `urllib.error.URLError`, timeout, and JSON-decode errors
  → `error`/`not_found` status, never propagated.
- Wall-clock budget caps total latency.
- Unwritable cache dir → stderr warning, continue uncached.
- No registry `description`/`deprecated`-message text enters any `detail`.

## Testing

- **Manifest parsers** — per ecosystem, edge cases: version specifiers, extras,
  markers, comments, `-r`/`-e`, poetry vs PEP 621, and the 3.10 name-only fallback
  (forced by monkeypatching `tomllib` absent).
- **Rubric** — `evaluate` over synthetic payloads with a fixed `now`: each rule
  fires; not-in-registry; deprecated; stale boundary (just-over / just-under 2y);
  single-maintainer; unsigned.
- **Network isolation** — all tests inject a fake `fetcher`; the suite never opens
  a socket. Real HTTP, if exercised at all, sits behind a `skipUnless` opt-in guard
  like the H1.08 e2e (not required for this increment).
- **Byte-identical guard** — assert `render_text`/`render_json`/`render_sarif` of a
  Report produced with an empty provenance list equals the no-flag output. Locks
  the exit criterion.
- **Cache round-trip** — fetch → cache → re-run with the fetcher disabled resolves
  from cache (proves air-gapped re-run); `--provenance-refresh` bypasses.
- **Enrich orchestration** — budget exhaustion resolves remaining deps to
  unavailable; the aggregate note is emitted once.

## Out of scope (explicit)

- **GitHub provenance** (stars, archived, release signatures) — needs a token,
  rate-limit backoff, and repo-URL resolution; the next increment.
- **Transitive dependencies / lockfiles** (`package-lock.json`, `poetry.lock`) —
  direct deps only, mirroring the existing `dep-surface` rule's scope.
- **Scoring provenance** — findings never affect score/grade (the invariant).
- **PyPI maintainer count** — no reliable field in the JSON API; npm-only signal.

## Exit criteria (from roadmap)

- [ ] `--provenance` produces a separate `provenance` SARIF category.
- [ ] Default audit output (text/json/sarif) byte-identical with and without the
      flag (cache aside) — locked by test.
- [ ] `--provenance-cache` enables offline re-runs; `--provenance-refresh` forces
      re-fetch.
- [ ] Network failure degrades to a `prov-unavailable` note; the core audit is
      unaffected.
- [ ] Zero new runtime dependency; suite passes offline (injected fetcher).
