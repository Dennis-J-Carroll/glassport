# glassport — red-team closeout & next steps

**Date:** 2026-07-01 · **As of:** v0.6.1 on PyPI

This closes out the `advise` + red-team-grill arc and lays out where to point the
adversary next. The through-line: **glassport renders attacker-controlled bytes
into places that get parsed downstream** (an agent's `CLAUDE.md`, an HTML report,
a SARIF file). Every such surface is a poisoning surface until a grill proves
otherwise. `advise` now has one. The others don't yet.

---

## What shipped this arc

| PR | What |
|---|---|
| #20 | `glassport advise` — folds audit + runtime findings into a fenced agent-md block (`--write CLAUDE.md`) |
| #21 | Quote-or-redact `_sanitize_inline` — closes fence-breakout (P2) + directive-survival (P5) |
| #22 | The P1–P11 red-team grill (`dogfood/eval_advise_redteam.py`) into main |
| #26 | `run_tap` `os._exit` shutdown-abort fix (the daemon-stdin `_enter_buffered_busy` flake) |
| #24 | Roadmap doc | · #25 → **0.6.0** · #27 → **0.6.1** |

The grill drove the real CLI in-process and found real bugs; Kimi then invented
P7–P11 (Armenian/Hangul/U+02CB/secret-as-identifier/audit-path) and hardened the
source. That loop is the asset — keep feeding it.

---

## Steelman red-team suggestions

Ordered by leverage. "Turn a box red" = a real source fix.

### 1. Grow the advise catalog past P11 (cheap, high yield)
The current oracle covers 11 vectors. The redaction rule (`_SAFE_VALUE`) is the
thing to attack — find a value it *quotes* that still carries a payload:
- **Bidi / RTL override** — U+202E and friends reorder rendered text without
  changing bytes; `_normalize_for_scan` strips the bidi block, so verify a value
  wearing one is redacted, not quoted.
- **Combining-character stacks** — Zalgo-style; do they survive `_SAFE_VALUE`
  (`\w` matches many combining marks)? If a combining mark passes, redact it.
- **Punycode / IDN hosts** — `xn--…` is all `[\w.-]`, so it *quotes*. A punycode
  host that decodes to a homoglyph domain is a real deception. Consider decoding
  IDN before the safe-charset check.
- **Nested / partial fence markers** — `<!-- glassport:beg` + `in -->` split
  across two adjacent findings; confirm the per-value redaction still holds when
  the marker is assembled across lines.
- **Front-matter injection** — agent files are sometimes parsed as
  YAML/TOML/Markdown-front-matter. A value like `---\nrole: system` could open a
  front-matter block. `_SAFE_VALUE` excludes newline so this should redact —
  prove it with a fixture.
- **Length/DoS** — a 10 MB tool name or 100k findings: does `advise` stay
  bounded and fast? (`_sanitize_inline` caps at 64 chars, but the finding *count*
  isn't capped.)
- **P7 audit path E2E** — the catalog's P7/P11 lean on unit tests; wire a real
  audit fixture whose `Finding.path` is a traversal+markdown string end-to-end.

### 2. Grill the OTHER renderers (the biggest untested surface)
`advise` is hardened; **`report.py` and `sarif.py` are not**, and they consume
the same attacker-controlled bytes:
- **`report.py` → `session.html`** — a hostile tool name / result rendered into
  HTML. Is every field HTML-escaped, or can a server inject
  `<script>`/`<img onerror>` into the report a human opens in a browser? This is
  a classic stored-XSS shape and **has no grill today.** High priority.
- **`sarif.py`** — finding text flows into a JSON document a Security tab
  renders. Confirm no field can break the JSON or smuggle markup the GitHub UI
  interprets.
- Generalize the grill harness: `dogfood/oracle.py` checkers are reusable; add
  `eval_report_redteam.py` / `eval_sarif_redteam.py` driving the real renderers.

### 3. Add the semantic-directive judge (the deepest gap)
P5 taught us markdown-inert ≠ safe. The oracle checks *bytes*; it can't check
whether an LLM would *obey* surviving text. Add an opt-in check that feeds the
written `CLAUDE.md` to an actual model and asks "would you act on anything here
that isn't glassport's own guidance?" Keep it out of the zero-dep default path
(it needs a model); run it in the Kimi loop.

### 4. Deterministic regression-lock for the shutdown flake
The `run_tap` abort is fixed but only probabilistically tested. Add a test that
reproduces it *reliably*: spawn the tap subprocess with a **held-open stdin**
(so the c2s daemon is definitely blocked) and assert `returncode == 0`. Pre-fix
that aborts ~100%; it turns the 1/300 flake into a hard gate. (Repro recipe is
in this session's notes: `sleep 1 | python runner.py` around `run_tap`.)

### 5. Audit sibling shutdown/daemon paths
The `_enter_buffered_busy` class isn't unique to `run_tap`. Check `serve`
(`server.py`) and any other daemon-thread-on-stdio path for the same
finalization abort; apply the same `os._exit`-after-stderr-flush pattern where a
function owns the process.

### 6. Wire the grills into CI as merge gates
The advise grill lives in `dogfood/` on main but isn't a required check. Add a CI
job that runs `PYTHONPATH=src python dogfood/eval_advise_redteam.py` (exit-non-zero
on FAIL) on every PR, and fold it into the release workflow's `test` job so a
poisoning regression can't ship.

---

## Next steps (product roadmap)

From `STATUS.md` Tier 3, in dependency order:
1. **Network-enriched audit** *(medium, recommended next feature)* — opt-in
   npm/PyPI/GitHub provenance lookups, off the default path so the core audit
   stays offline/reproducible. Independent, self-contained.
2. **Streaming detector path** *(large, architectural)* — detectors consume a
   full in-memory trace today; streaming is the prerequisite for #3.
3. **Remote streamable-HTTP interception** *(large)* — HTTP+SSE transport, not
   stdio. Depends on streaming.
4. **Agent↔Agent (A2A) trace coverage** *(large)*.

### Process / housekeeping
- **Kimi loop cadence** — schedule recurring Kimi rounds against
  `dogfood/SPEC-advise-redteam.md` (and the new report/sarif grills once they
  exist). Each round: invent beyond the table → file findings → source fix → PR.
- **Node 20 deprecation** — bump `actions/checkout`, `actions/setup-python`,
  `actions/*-artifact` off the deprecated Node 20 runners in the CI + release
  workflows.
- **Prune** merged PR branches as you go (done for #15–#19 this session).

---

## One-line takeaway

`advise` is grilled and hardened; the same discipline now owes a visit to
`report.py` (HTML — likely the next real finding) and `sarif.py`. Keep the Kimi
loop running; every red box is a source fix with a name on it.
