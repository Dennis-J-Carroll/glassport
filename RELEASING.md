# Releasing glassport

Runbook for cutting a PyPI release and versioning the root GitHub Action.
The same `vX.Y.Z` tag triggers package publication and becomes the action ref.

## Version lives in two places — bump both

- `pyproject.toml` → `version = "X.Y.Z"`
- `src/glassport/__init__.py` → `__version__ = "X.Y.Z"` (the `serve` handshake
  advertises this in `serverInfo`)

Semver: new features (like `serve`, `sarif`) → minor bump. Bugfix only → patch.

## Release steps

- [ ] Prepare a release PR from current `main`: bump both version fields above,
      run `python scripts/gen_changelog.py --write` from a full-history clone,
      and review the generated notes. Run the full suite as non-root and wait
      for PR CI before merging.
- [ ] Merge the release PR into `main`. Confirm both version fields and the
      release notes on `main` before creating the tag. The release workflow's
      build job fails if the tag does not match `pyproject.toml`.

### Primary path — tag-triggered trusted publishing (no token)

Release tags also version the root GitHub Action; pushing `vX.Y.Z` makes `Dennis-J-Carroll/glassport@vX.Y.Z` available without a separate publish step.

`.github/workflows/release.yml` triggers on a `v*` tag: it runs the test matrix,
builds, checks the tag matches `pyproject.toml`, and publishes to PyPI via
**trusted publishing (OIDC)** — no API token, no local `twine`.

- [ ] Push the tag from the verified `main` commit (THIS is the irreversible
      publish step):
  - `git tag vX.Y.Z && git push origin vX.Y.Z`
  - The workflow creates the GitHub release with generated notes and attaches
    `dist/`. Edit those notes afterwards; if a release for the tag already
    exists, the workflow only uploads `dist/` to it.
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
