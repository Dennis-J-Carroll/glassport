# HTTP integrity: release and migration notes

Covers `feat/http-session-integrity` (commits `f370fe0..172f8bf` on top of the
foundation checkpoint), the follow-up sequence in
[`docs/priority-engineering.md`](priority-engineering.md#agreed-follow-up-sequence--2026-09-08).
No package version was bumped and no release was tagged by this work; this
document exists so a reviewer or a later release can state exactly what
changed and what its boundaries are. See
[`docs/http-session-isolation.md`](http-session-isolation.md) and
[`docs/http-decision-journal.md`](http-decision-journal.md) for the full
contracts; this file is the compatibility/migration summary.

## What shipped

- **Bounded, opt-in HTTP session isolation** (`src/glassport/http_sessions.py`).
  Each observed HTTP session gets its own detector engine, builder, and wire
  capture, credential-partitioned and bounded (active sessions, idle TTL,
  identifier size, retained transport metadata). No behavior change to the
  default `wrap` path.
- **A versioned decision/delivery journal and replay verifier**
  (`src/glassport/decision_journal.py`, `decision_replay.py`). Every observed
  HTTP request gets a recorded candidate policy verdict (computed the same way
  regardless of mode) and exactly one terminal delivery outcome. Still no
  enforcement — `observe` mode always forwards.
- **An explicit HTTP enforcement gate**: `glassport gate --transport http --url
  <remote>`. The only new code path in this project that can refuse to forward
  a request. It blocks **one narrow case**: a severity-3 `tools/call` proved
  fabricated against a surface this HTTP session actually observed being
  declared (including an observed *empty* surface — that counts as exclusion
  evidence). Everything else forwards, including a missing/incomplete/
  malformed declaration, a faulted or bounded detector pass, an oversized or
  unparseable body, PII/secret findings, and unexpected-egress findings.

## Exact supported boundaries

- **Two independent gates, one shared blocking rule.** The pre-existing stdio
  `gate` and the new `gate --transport http` both refuse only a proved
  out-of-surface `tools/call`; the HTTP gate is *not* a general firewall and
  does not gain any new blocking category the stdio gate lacks. The stdio
  `Gate` class was not touched and was not migrated onto the shared
  `policy.decide()` engine — it keeps its own separate mechanism. HTTP
  enforcement is wired through `policy.decide(..., block_fabricated=True)` and
  `DecisionJournal.evaluate()` instead.
- **`--controllable` is stdio-only.** The stdio gate's runtime on/off toggle
  (an override file `tui --gate-control` can flip) has no HTTP equivalent;
  `gate --controllable --transport http` is refused (exit 2) rather than
  silently accepted or silently ignored.
- **`_run_http_gate` has a narrower CLI surface than `observe`.** No
  `--bind`/`--port`/`--journal-dir`/`--max-sessions` overrides — deliberately,
  matching the stdio gate's own lack of bind/port options. `observe --url
  <remote> --journal-dir ... --max-sessions ...` remains the place to reach
  for those knobs in observation mode.
- **Journal records never carry attacker-controlled free text.** Annotation
  explanations, tool names, hosts, and paths never reach `decision_journal.py`
  records; only structured fields (kind/severity/subcategory/id, action,
  sequence numbers, digests). Wire payloads and secrets stay in the private,
  separately-bounded wire log.
- **Custom PII patterns registered with an arbitrary Python callable validator
  are not replay-reproducible.** An HTTP epoch snapshots the active pattern
  set once at creation; a pattern built through the declarative JSON loader
  (`pii_pattern_from_dict`, named validators only) round-trips through a
  digest and replays as equivalent, but a pattern registered directly with a
  custom callable cannot be reconstructed from that digest and reports
  `incomplete` on replay rather than a false equivalence claim.
- **A recorded detector fault is never re-executed on replay.** If the
  original pass recorded a fault for an event, replay reports that event as
  `incomplete`/recorded-fault, never as re-judged current-run output.
- **Credential partitioning is not authentication.** The salted
  credential-context digest that isolates HTTP sessions from each other
  prevents accidental state reuse; it makes no claim about verifying who is
  actually presenting a credential. Upstream authentication remains
  upstream-owned.

## Known, reviewed, and accepted trade-offs (not fixed, not blocking)

These were raised in task-level or whole-branch review, evaluated, and judged
acceptable to ship as-is — listed here so they aren't rediscovered as
surprises later:

- A party who already possesses a live session's `Mcp-Session-Id` token can
  force-retire every HTTP context bound to that token (including ones in
  unrelated credential partitions) by sending one request with duplicate
  `Authorization`/`Cookie`/`Proxy-Authorization` headers. This can only ever
  *discard* state (forcing re-initialization); it cannot merge partitions,
  misattribute evidence, or leak one partition's data into another's, and it
  requires already holding the token.
- A malformed-annotation failure inside `record_intent()` fails open silently
  (no journal trace for that one event), while a malformed pattern-profile
  failure at epoch creation still writes an explicit `incomplete` record. The
  enforcement decision itself is proven independent of whether the journal
  write succeeds either way; this is an audit-trail completeness gap in an
  already-rare pathological input, not a correctness issue.
- `tests/test_http_gate.py`'s "concurrent sessions" coverage exercises
  per-epoch isolation sequentially rather than with literal thread
  interleaving. Genuine concurrent interleaving of the underlying registry is
  proven separately in `tests/test_http_sessions.py` with real threads; the
  gate-level test is checking verdict independence, not thread-safety.

## Compatibility

- Zero new runtime dependencies.
- Stdio behavior (`wrap`, `gate`, `summarize`, `detect`, ...) is byte-for-byte
  unchanged; the only `tap.py` change touching the stdio dispatch path is the
  two-line replacement of the `gate --transport http` "not supported yet"
  guard.
- Passive `wrap --transport http` and `observe --url ...` are byte-for-byte
  unchanged whether or not a decision journal is attached in observation
  mode; the enforcement branch is structurally unreachable without an
  explicit gate-mode journal.
- `src/glassport/adapters/mcp_http.py` is now included in CI's hard 85% core
  coverage gate (`.github/workflows/ci-coverage.yml`), reflecting that it now
  holds the project's only enforcement decision point.

## Validation at the final commit (`172f8bf`)

- Full suite: 902/902 passing locally (`python -m unittest discover -s tests -t .`).
- All nine security grills: 9/9 exit 0.
- Core pipeline coverage: 93% (gate: ≥85%); `mcp_http.py` itself: 93%;
  `http_sessions.py` 94%, `decision_journal.py` 91%, `decision_replay.py` 92%.
- Repeated scanner benchmark (7 samples/mode): normal, C-tracer, and
  sys.monitoring coverage cores all `status: supported`, no errors.
- Every task (2, 3, 4, and the final-review fix wave) passed an independent
  scoped review with fixes applied and re-reviewed clean, plus one whole-
  branch review across the combined diff with no Critical and no open
  Important findings.
- **Exact-head CI on [PR #80](https://github.com/Dennis-J-Carroll/glassport/pull/80):
  18/18 checks passed** at `172f8bf` — the full ubuntu/macos/windows ×
  Python 3.10-3.13 matrix, `coverage`, `bench`, `redteam-grills`,
  `security-scan`, and `pre-commit-hook`. One round-trip was needed: the
  first CI run at `562efb2` had the ubuntu/macos legs and all non-matrix
  jobs green, but all 4 Windows legs failed on a single test
  (`test_persistence_failure_fails_open_and_records_nothing`) that
  simulated an unwritable directory via POSIX `mkdir(mode=0o500)`, a no-op
  on Windows. Not a product bug — the same fail-open property is covered
  platform-independently by a sibling mock-based test — fixed by skipping
  that one test on non-POSIX platforms (commit `172f8bf`), matching this
  codebase's existing convention for the same situation elsewhere
  (`tests/test_gate.py`, `tests/test_comprehensive_security.py`).

No merge, tag, or release was performed. This branch is pushed to
`origin/feat/http-session-integrity`; [PR #80](https://github.com/Dennis-J-Carroll/glassport/pull/80)
(draft) is open against `fix/foundation-stabilization` (the branch this
work forked from, itself an open, unmerged PR — see
`docs/priority-engineering.md`).
