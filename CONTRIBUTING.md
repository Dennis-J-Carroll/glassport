# Contributing to glassport

Thanks for looking. glassport is small, disciplined, and opinionated;
this document exists so your first PR can land without maintainer
hand-holding.

## The dev loop

Zero install steps — a bare clone is the dev environment:

```bash
git clone https://github.com/Dennis-J-Carroll/glassport
cd glassport
python -m unittest discover -s tests -t .        # full suite, stdlib only
PYTHONPATH=src python dogfood/eval_advise_redteam.py    # red-team grills
PYTHONPATH=src python dogfood/eval_report_redteam.py
PYTHONPATH=src python dogfood/eval_sarif_redteam.py
PYTHONPATH=src python dogfood/eval_server_redteam.py
PYTHONPATH=src python dogfood/eval_streaming_redteam.py
```

Everything above must pass before a PR; CI runs exactly these.

## The zero-dependency constraint

`pyproject.toml` has no `[project.dependencies]` section, deliberately.
glassport audits other packages for supply-chain risk; shipping its own
dependency tree would be "do as I say, not as I do." It also keeps the
tool installable on Termux and air-gapped machines.

- **Runtime deps: no.** PRs adding one will be declined regardless of
  how good the library is.
- **Dev/CI-only deps: propose them.** Opt-in tooling that never touches
  the runtime path (coverage, hypothesis, benchmarks) can live in
  `[project.optional-dependencies] dev` and run in separate, non-gating
  CI jobs. Make the case in the PR description.
- **Platform shims: by exception.** `glassport[tui]` installs
  windows-curses behind a platform marker because Windows lacks stdlib
  curses. That is the model: optional, marker-gated, no-op elsewhere.

## The red-team grill discipline

**If you add a detector or a renderer, you add a grill.** A grill is a
script in `dogfood/eval_*_redteam.py` that drives the *real* code path
against hostile fixtures and exits non-zero on any escape. Grills are
required CI jobs — they are how a fixed bypass stays fixed. A detector
PR without adversarial coverage is half a PR.

Suppression hygiene: use scoped `# glassport: ignore[rule-id]` on the
exact line, never a blanket `# nosec`, and say why in the PR.

## Doctrine acceptance

Three principles are enforced in code and in review; PRs that violate
them will be declined unless they first change the doctrine itself (open
an issue titled `RFC: doctrine change` and make the argument):

1. **Observe first, enforce later.** Passive wrap mode is the default
   forever. Enforcement is opt-in, visible, and fail-closed on its own
   config.
2. **The relay is sacred.** Logging and analysis are best-effort and may
   never alter, delay, or kill a live session. The tap stays dumb: it
   logs frames, it does not parse semantics.
3. **Assert only what the wire proves.** Detectors annotate; they never
   mutate the trace. Absence of evidence is reported as absence, not
   guilt. If your feature invents truth the wire never claimed, it
   belongs in a different tool.

The practical test for any new feature: *does it surface truth the wire
already proved, or does it invent truth the wire never claimed?* Ship
the first kind.

## PR mechanics

- Conventional-commit subjects (`feat:`, `fix:`, `docs:`, …) — the
  changelog is generated from them by `scripts/gen_changelog.py`.
- New behavior ships with tests in `tests/` (stdlib `unittest`, no
  mocking frameworks). Match the local style: module docstrings say what
  the file does *and deliberately does not do*.
- One logical change per PR. Small is fast to review.
- `python -m glassport.tap audit src` should stay clean of new findings;
  if your change legitimately trips a rule, scoped-suppress it and
  explain.

## Good first issues

Issues labeled `good-first-issue` are scoped to be landable in an
evening without deep context — typically a new PII pattern + validator +
tests, or an error-message improvement. Comment on the issue to claim it.
