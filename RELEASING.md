# Releasing glassport

Runbook for cutting a PyPI release. Written at the 0.2.0 cut; keep it current.

## State at 0.2.0 (2026-06-23)

- **PyPI has 0.1.0** — predates `serve` (the MCP server) and `sarif.py` (SARIF export).
  Installing 0.1.0 and running `glassport serve` falls through to *wrap* mode and
  spawns whatever other `serve` is on PATH (e.g. Ray Serve) — not a glassport bug,
  just a stale package.
- **0.2.0 is built but unpublished.** Artifacts in `dist/`. Version bumped in
  `pyproject.toml` + `src/glassport/__init__.py`. Lives on branch
  `docs/document-serve-command` (PR #4), which carries both the README docs and
  the bump — effectively the release PR.

## Version lives in two places — bump both

- `pyproject.toml` → `version = "X.Y.Z"`
- `src/glassport/__init__.py` → `__version__ = "X.Y.Z"` (the `serve` handshake
  advertises this in `serverInfo`)

Semver: new features (like `serve`, `sarif`) → minor bump. Bugfix only → patch.

## Release steps

- [ ] Land the code first — merge the release PR (#4) into `main` so `main` matches
      what ships. Tag after: `git tag v0.2.0 && git push --tags`.
- [ ] Bump version in **both** files above (skip if already done), commit, and
      push to `main`. The bump MUST be on `main` before the tag — the release
      workflow's build job fails if `tag != pyproject version`.

### Primary path — tag-triggered trusted publishing (no token)

`.github/workflows/release.yml` triggers on a `v*` tag: it runs the test matrix,
builds, checks the tag matches `pyproject.toml`, and publishes to PyPI via
**trusted publishing (OIDC)** — no API token, no local `twine`.

- [ ] Push the tag (THIS is the irreversible publish step):
  - `git tag vX.Y.Z && git push origin vX.Y.Z`
- [ ] Watch the run: `gh run watch` (or the Actions tab). The `publish` job
      uploads to PyPI on success.
- [ ] Verify: `pip install -U glassport` in a clean venv, then `glassport serve`
      (prints the MCP banner, not a wrap-spawn of another binary).

> **Prerequisite:** PyPI must have a *trusted publisher* configured for this repo
> (project → Publishing → add GitHub publisher: repo `Dennis-J-Carroll/glassport`,
> workflow `release.yml`, environment `pypi`). If it isn't set up, the `publish`
> job fails cleanly (nothing partial publishes) — use the fallback below.

### Fallback — manual twine upload

Only if trusted publishing isn't configured (how 0.2.0 shipped):

- [ ] `rm -f dist/* && python3 -m build`
- [ ] Sanity-check: `unzip -l dist/glassport-X.Y.Z-py3-none-any.whl` (server.py,
      sarif.py, tap.py packed); `python3 -m twine check dist/glassport-X.Y.Z*`
- [ ] `pip install twine && python3 -m twine upload dist/glassport-X.Y.Z*`
      (prompts for PyPI API token; irreversible — a version can't be reused)

## Gotchas

- **PyPI uploads are permanent.** Wrong artifact = burn the version, bump again.
  Test on TestPyPI first if unsure: `twine upload -r testpypi dist/*`.
- **The `serve` PATH collision is by design.** Even released, bare
  `glassport <x>` wrap-spawns `<x>`; only `glassport serve` (subcommand) runs the
  MCP server. Document, don't "fix."
- **README is the PyPI page.** Any README edit changes the public listing on the
  next release. Re-run anchor/link checks before shipping.
