# GitLab CI + pre-commit templates — design

**Roadmap item:** Tier 3 #1 (STATUS.md). **Date:** 2026-06-23.

## Problem

glassport ships a GitHub Actions integration (`.github/workflows/ci.yml`:
`security-scan` job → `audit --sarif` → Security tab) but nothing for the two
other common gates: **GitLab CI** and **pre-commit**. Consumers on GitLab, or
who want a local commit-time gate, have to wire it themselves.

These are **distribution artifacts only — zero package code change.** Everything
needed already exists: the `glassport` console script and `audit`'s exit-code
contract (exit **1** on any critical/high finding, **0** otherwise —
`audit.py:636`).

## Decisions

- **GitLab depth:** gate + SARIF artifact, no GitLab-native SAST/Code-Quality
  format. GitLab has no SARIF-ingesting Security tab; the template runs the
  audit, saves `glassport.sarif.json` as a downloadable artifact, and exposes the
  exit-1 gate. (A `gl-sast-report.json` renderer was considered and rejected —
  new code + a format to maintain, against the "distribution-only" scope.)
- **GitLab posture:** non-blocking by default (`allow_failure: true`), opt-in to
  gate (flip to `false`). Mirrors the GitHub job's upload-only posture and the
  project's "observe first, enforce later; enforcement is opt-in" doctrine.
- **pre-commit posture:** blocking. Installing the hook *is* the opt-in to
  enforce locally — so a critical/high finding (exit 1) blocks the commit.
- **One artifact format everywhere:** SARIF. No new output format.

## Components

Three new files, no changes to `src/`.

### 1. `.pre-commit-hooks.yml` (repo root — required)

The pre-commit framework discovers hooks from this file at the root of the hook
*provider* repo, so a consumer can reference `repo: <glassport>`.

```yaml
- id: glassport-audit
  name: glassport MCP security audit
  description: Static audit of MCP server source; fails on critical/high findings.
  entry: glassport audit
  language: python
  pass_filenames: false
  types_or: [python, javascript, ts, tsx]
  args: ["."]
```

- `pass_filenames: false` is **forced** by `audit` taking a single path argument
  (no multi-path support; adding it would be a core change, out of scope). The
  hook audits a whole target, not the staged file list.
- `language: python` + the consumer's `repo:` pointing at glassport means
  pre-commit installs glassport into the hook's venv, so `glassport audit`
  resolves. No `additional_dependencies` needed.
- `types_or` limits *when* the hook fires (source changes), not what it audits.
- `args: ["."]` is the default target; consumers override with their server dir.

Consumer usage (documented in README, not shipped):

```yaml
repos:
  - repo: https://github.com/Dennis-J-Carroll/glassport
    rev: v0.3.0
    hooks:
      - id: glassport-audit
        args: ["path/to/server"]
```

### 2. `examples/gitlab-ci.yml` (copy-to-root template)

Not glassport's own pipeline (glassport is on GitHub); a template the consumer
copies to their repo root or merges into an existing `.gitlab-ci.yml`.

```yaml
# glassport security audit for GitLab CI.
# Copy to your repo root as .gitlab-ci.yml, or merge this job into your pipeline.
glassport-audit:
  image: python:3.12-slim
  variables:
    AUDIT_TARGET: "src"        # point at your MCP server source
  before_script:
    - pip install glassport
  script:
    - glassport audit "$AUDIT_TARGET" --sarif > glassport.sarif.json
  allow_failure: true          # observe first — set false to gate the pipeline
  artifacts:
    when: always
    paths: [glassport.sarif.json]
    expire_in: 30 days
```

`audit --sarif` prints the SARIF document *then* returns exit 1 on critical/high.
So the artifact always writes; `when: always` saves it even when the job "fails";
`allow_failure: true` keeps the pipeline green until the consumer opts to gate.

### 3. README "CI integration" section

A subsection covering all three gates side by side: GitHub Actions (already
shipped — link the workflow), GitLab (copy `examples/gitlab-ci.yml`), pre-commit
(reference the repo + `rev`). Re-run the README anchor/link check after editing.

## Testing

The suite is **stdlib-only** (no PyYAML), so YAML is validated by token presence,
with a real end-to-end check in CI where the ecosystem exists.

### `tests/test_ci_templates.py` (unittest, stdlib)

Assert both template files exist and carry the load-bearing tokens — a cheap
contract lock against deletion or a typo in a critical token:

- `.pre-commit-hooks.yml`: contains `id: glassport-audit`, `entry: glassport audit`,
  `language: python`, `pass_filenames: false`.
- `examples/gitlab-ci.yml`: contains `glassport audit`, `--sarif`,
  `allow_failure: true`, `when: always`, and the `set false to gate` comment.

### GitHub Actions integration job (`.github/workflows/ci.yml`)

A new job proves the hook actually fires and **fails on the deliberately-bad**
`examples/fake_server.py`:

```yaml
  pre-commit-hook:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install pre-commit
      # the hook must FAIL on the misbehaving fixture; invert the exit code
      - name: glassport-audit hook fails on the bad fixture
        run: |
          if pre-commit try-repo . glassport-audit --files examples/fake_server.py; then
            echo "hook should have failed on fake_server.py" >&2
            exit 1
          fi
```

This exercises the full pre-commit path (venv build, glassport install, `audit`
run, exit code) against a server glassport is *supposed* to flag.

## Out of scope

- GitLab-native SAST / Code-Quality report formats (`gl-sast-report.json` etc.).
- Multi-path / staged-files-only auditing (would require a core `audit` change).
- Any change to `src/glassport/`.
