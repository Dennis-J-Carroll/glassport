# H1.08 — coverage.py opt-in dev-dep + e2e integration test

**Roadmap item:** Horizon 1 · H1.08 (the last open H1 item; H1.01–H1.07, H1.09–H1.10 shipped).
**Date:** 2026-07-04 · **Baseline:** v0.6.3, 526 tests green.
**Doctrine constraint (load-bearing):** the runtime stays zero-dependency and the
main CI matrix stays stdlib-only, straight-from-a-clone. Coverage tooling and the
e2e test are *opt-in* and *skippable*; a fresh clone with no npm/node and no dev
extras must still run the whole suite green.

## Problem

Two gaps versus the roadmap's H1.08 exit criteria:

1. **No coverage measurement.** The zero-dep constraint forbids `coverage.py` in
   core CI, but a *separate opt-in* job can measure it. Nothing does today.
2. **No wire-reality test.** Every existing test builds synthetic tap logs
   line-by-line — good for unit coverage, but nothing drives glassport against a
   *real* MCP server end-to-end. "Faithful trace" is asserted against
   hand-authored JSONL, never against bytes a real server actually emitted.

## Approach (chosen)

Three additive changes, no `src/` behavior change.

### 1. `pyproject.toml` — `dev` optional extra

```toml
[project.optional-dependencies]
tui = ["windows-curses; platform_system == 'Windows'"]   # existing
dev = ["coverage", "hypothesis"]                          # new
```

`hypothesis` lands now because the dev-dep group is *introduced* here; the
property-based validator tests that consume it are **H2.06**, out of scope for
this step. Runtime install is unchanged — `pip install glassport` pulls neither.

### 2. `.github/workflows/ci-coverage.yml` — separate opt-in workflow

Not part of the main `test` matrix (which must stay stdlib-only). Single job,
`ubuntu-latest`, Python 3.12, `setup-node` for the e2e:

- `pip install .[dev]`
- `coverage run --source=src/glassport -m unittest discover -s tests -t .`
  (with node present, the e2e test participates and additionally exercises
  `tap.py`'s live `wrap` path + the `mcp_session` adapter against real bytes)
- **Hard gate:** `coverage report --fail-under=85` scoped to the **core
  detection/analysis pipeline** via `--include`:
  `detectors.py, audit.py, sarif.py, interaction_trace.py, adapters/*.py,
  advise.py, health.py, prune.py`. All already ≥85% at baseline (measured
  2026-07-04: detectors 97, mcp_session 100, interaction_trace 95, sarif 92,
  audit 91, streaming 98, health 89, advise 87, prune 86).
- **Informational:** a second `coverage report` over the whole package (incl.
  `tap.py`/`tui.py`/`console*.py`/`server.py`) printed to the job summary, no
  fail. Documents the CLI/UI gap without punishing the thin-CLI architecture.

**Why scope the gate to core:** glassport's doctrine deliberately keeps judgment
(detectors/audit/sarif) separate from I/O plumbing (`tap.py` CLI dispatch, curses
TUI, web console). A whole-repo `--fail-under` would penalize that separation and
force low-value UI tests. The gate enforces quality where correctness is
load-bearing — the pipeline that decides whether the wire is honest.

### 3. `tests/test_e2e_filesystem.py` — one wire-reality test

```python
@unittest.skipUnless(shutil.which("npx"), "npx/node not available")
class TestE2EFilesystemServer(unittest.TestCase):
    def test_wrap_captures_real_handshake_and_call(self):
        # glassport wrap --log-dir <tmp> -- npx -y \
        #   @modelcontextprotocol/server-filesystem <tmp>
        # drive: initialize -> tools/list -> a real tools/call (list_directory)
        # assert: the JSONL log exists and from_mcp_session(lines) yields a
        #   faithful InteractionTrace with the handshake + the tool call +
        #   its result; the declared tool surface is non-empty and the called
        #   tool is in it (no fabricated-call finding on a legitimate call).
```

**Skip semantics are the doctrine guarantee:** `skipUnless(shutil.which("npx"))`
means the zero-dep main matrix (no `setup-node`) and any clone-and-run skip it
cleanly; only `ci-coverage.yml` (with node) and developers who have node execute
it. The test spawns a subprocess, feeds JSON-RPC frames on stdin, waits for the
log to settle, then reads it back — no new runtime dep, no `src/` change.

The `@modelcontextprotocol/server-filesystem` server is the roadmap's named
reference server: stable, official, no credentials, filesystem-scoped to a temp
dir the test creates and cleans up.

## Data flow

```
stdin JSON-RPC frames
      │
      ▼
glassport wrap ──spawns──► npx @modelcontextprotocol/server-filesystem
      │  (stdio MITM, logs every frame, alters none)
      ▼
<tmp>/*.jsonl  ──from_mcp_session()──►  InteractionTrace
      │
      ▼
assertions: handshake present · tools/list declared surface non-empty ·
            tools/call captured with result · called tool ∈ declared surface
```

## Error handling / robustness

- **npx cold-start latency:** first `npx -y` may download the package. The test
  polls the log file for the expected frame count with a bounded timeout
  (generous, e.g. 60s) rather than a fixed sleep; fails with a clear message if
  the server never handshakes.
- **Subprocess teardown:** the wrap process and its child are terminated in a
  `finally`; the temp dir is removed. A `ResourceWarning` on socket teardown (seen
  elsewhere in the suite) is not a failure.
- **Non-determinism guard:** assertions key on *structure* (kinds, presence,
  membership), never on exact byte content or ordering beyond handshake-then-call,
  so a server version bump doesn't flake the test.

## Testing

- The e2e test IS the new test. Locally verified with node present (skips without).
- `ci-coverage.yml` proves the gate: core ≥85 passes, and a deliberate coverage
  drop in a core module would fail the job (not asserted in-repo, but the
  `--fail-under` mechanism is the proof).
- Main matrix (`ci.yml`) unchanged and must stay green — the new test skips there.

## Out of scope (explicit)

- **H2.06 property-based validator tests** — `hypothesis` is added to the dev
  group but no property tests are written here.
- Any `src/` behavior change. This step is CI + test infrastructure only.
- Coverage gating of `tap.py`/`tui.py`/`console*.py`/`server.py` — informational
  only; raising those is a separate, later effort.

## Exit criteria (from roadmap)

- [ ] `dev` extra provides `coverage` + `hypothesis`; runtime install unchanged.
- [ ] `ci-coverage.yml` runs opt-in; core pipeline `--fail-under=85` passes.
- [ ] e2e test green against the reference filesystem server with node present.
- [ ] Whole clone-and-run suite (no node, no dev extras) still green — e2e skips.
- [ ] CHANGELOG entry; version bump to v0.6.4 on release.
