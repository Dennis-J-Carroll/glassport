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
- [ ] Bump version in **both** files above (skip if already done).
- [ ] Clean old artifacts: `rm -f dist/*`
- [ ] Build: `python3 -m build` → fresh `dist/glassport-X.Y.Z*` (wheel + sdist)
- [ ] Sanity-check the wheel before upload:
  - `unzip -l dist/glassport-X.Y.Z-py3-none-any.whl` — confirms `server.py`,
    `sarif.py`, `tap.py` are packed
  - `unzip -p dist/glassport-X.Y.Z-py3-none-any.whl '*/METADATA' | grep ^Version:`
  - `python3 -m twine check dist/glassport-X.Y.Z*` — validates the long-description
    (PyPI renders `README.md`; `pyproject.toml` `readme = "README.md"`)
- [ ] Upload (irreversible — a version number can never be reused on PyPI):
  - `pip install twine` (once)
  - `python3 -m twine upload dist/glassport-X.Y.Z*` — prompts for PyPI API token
- [ ] Verify the release: `pip install -U glassport` in a clean venv, then
      `glassport serve` (should print the MCP banner, not wrap-spawn another binary).

## Gotchas

- **PyPI uploads are permanent.** Wrong artifact = burn the version, bump again.
  Test on TestPyPI first if unsure: `twine upload -r testpypi dist/*`.
- **The `serve` PATH collision is by design.** Even released, bare
  `glassport <x>` wrap-spawns `<x>`; only `glassport serve` (subcommand) runs the
  MCP server. Document, don't "fix."
- **README is the PyPI page.** Any README edit changes the public listing on the
  next release. Re-run anchor/link checks before shipping.
