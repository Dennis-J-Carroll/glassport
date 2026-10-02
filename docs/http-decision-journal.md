# Decision and delivery records (observation mode)

This stage records what analysis concluded and what the transport actually did,
for an explicitly observed HTTP session. **No gate exists.** A candidate BLOCK
is recorded as a candidate and the request is still forwarded; nothing here
changes which bytes are sent or when.

```bash
glassport observe --url http://127.0.0.1:8000/mcp \
    --log-dir ./private-captures [--journal-dir DIR] \
    [--bind HOST] [--port N] [--max-sessions N]

glassport replay-decisions ./private-captures/decisions/<epoch>.jsonl \
    --wire ./private-captures/<epoch>.jsonl [--json]
```

`observe` has its own strict parser: an unknown or repeated option fails with
exit 2 rather than silently selecting a different mode. The `wrap` path's
positional `--log-dir` / `--transport` / `--url` handling is untouched.

Library equivalent:

```python
observer = HTTPObserver(captures)
journal = DecisionJournal(captures / "decisions", observer)
run_http_tap(url, captures, observer=observer, journal=journal)
```

`journal` requires `observer`; without one it is ignored. Journal files live in
their own directory so the log-dir scanners (`watch`, `tui`, `prune`, `health`)
never mistake a decision record for a session capture.

## Two record kinds, and why they are separate

| Record | Written | Says |
|---|---|---|
| `intent` | after the c2s frame is folded, **before** the upstream request begins | the candidate action for that frame |
| `delivery` | after the upstream exchange resolves, on every exit path | what actually happened to the request |

A completed local send is not evidence that a remote tool executed. Delivery
outcomes are deliberately precise:

| `outcome` | Meaning | `code` |
|---|---|---|
| `not_attempted` | no upstream request was ever begun | `framing_rejected`, `not_begun` |
| `not_sent` | begun, but the socket was never established, so zero bytes reached the wire | `connect_failed` |
| `sent` | the complete request left the socket and upstream returned a status | `upstream_response` |
| `failed` | a status was received; the transfer failed afterwards | `body_transfer_failed` |
| `unknown` | indeterminate — a partial send, or `getresponse()` failed after the request had already returned | `send_indeterminate`, `response_indeterminate`, `handler_aborted` |

A `getresponse()` failure is **never** `not_sent`: the request had already left.
For HTTPS, `connect()` assigns the socket before the TLS handshake, so a
handshake failure reads as an established socket and classifies `unknown` —
deliberately conservative. Exactly one terminal record is written per intent,
including when a client disconnect unwinds the handler mid-delivery.

## What never enters a record

Annotation `explanation` text, tool names, hosts, paths, arguments, payload
bytes and secret values are attacker-influenced and are never copied here. Only
fixed vocabularies reach disk: annotation kind, a charset-sanitized subcategory
(lowercase `a-z0-9_.:/-`, 64 chars, anything else becomes `nonconforming`),
integer severity, the decision action and reason, the delivery outcome and code,
sequence numbers, and digests. Findings are compared by a digest of sorted
`(kind, subcategory, severity)` triples; annotation ids are excluded from that
digest because they are fresh random values on every run.

Wire evidence stays in its own private capture. The two streams are joined only
by epoch id plus `event_seq`, which is the capture's own `seq`.

## Versioned configuration profile

One `profile` record is written per epoch and referenced by later records — it
is never copied into them. It carries the journal schema, policy version,
detector engine identity, the frozen PII pattern digest and per-pattern summary,
the registry/session/journal limits in force, and the mode.

The pattern set is **frozen when the epoch is created**, not read per scan. The
PII registry is process-global and mutable (`register_pii_pattern`, the
`GLASSPORT_PII_PATTERNS` autoload); re-reading it on every scan would let a
mid-session change silently alter what a recorded decision was computed from.
Ordinary callers — the stdio tap, `summarize`, `advise`, `audit` — still read
the live registry, unchanged: `detectors._scan_pii()` and friends take an
optional pattern set whose default is `None`.

A pattern is **reproducible** when it is a built-in default (pinned by the
detector engine version) or a consumer pattern whose validator is `None` or one
of the named `_NAMED_VALIDATORS` — i.e. it round-trips through
`pii_pattern_from_dict`. A pattern registered with an arbitrary Python callable
cannot be reconstructed from a digest; it is listed in `unsupported_patterns`,
the profile status becomes `incomplete`, and replay refuses to compare. Custom
patterns are never silently dropped.

## What replay proves, and what it does not

`replay-decisions` re-folds the epoch's wire log through a fresh builder and
detector engine under the recorded session limits, recomputes each candidate
action, and compares.

| Status | Meaning | Exit |
|---|---|---:|
| `equivalent` | every compared record reproduced its action and finding digest | 0 |
| `divergent` | at least one record did not | 1 |
| `incomplete` | preconditions held, but the recording or the evidence was partial | 1 |
| `unsupported` | a precondition failed; nothing was compared | 1 |

Unsupported: missing profile, conflicting duplicate profiles, a mismatch in
schema / policy version / detector engine / pattern digest, unreadable or
malformed artifacts, reordered wire evidence, an epoch mismatch, or a journal
whose records are out of sequence. A repeated *identical* profile is a benign
resume marker, not a conflict.

Incomplete: a non-reproducible pattern profile, a journal truncated by its own
record bound, wire evidence missing for a recorded decision, or a
**recorded fault** — a detector that raised during the original pass. A recorded
fault is never re-executed and compared: whether detectors raise identically
twice is not something this tool will assume. Conversely, a fault that appears
only on replay is reported as a divergence.

Digests cross-check artifacts. They are **not** signatures: an attacker who can
rewrite both the journal and the wire log can make them agree, and nothing here
claims otherwise.

## Fold-version provenance

Two detector-engine identities are in play on every replay, and the result
names both rather than conflating them:

| Field | Where it comes from | What it says |
|---|---|---|
| `recorded_engine` | the journal's `profile` record (`detector_engine`), written by the process that recorded the epoch | the fold the decisions were **actually computed under** |
| `analyzer_engine` | `decision_journal.DETECTOR_ENGINE_VERSION` of the glassport running `replay-decisions` | the fold this reader **would analyze the log with** |

They are compared, never reconciled. A journal whose `recorded_engine` differs
from the analyzer is `unsupported` (`profile_mismatch_detector_engine`), and
the text output prints both values. The analyzer's version is a property of
the reader; it is not written into a log the reader merely opens, and opening
a log with a newer glassport does not upgrade what the log recorded.

The current fold is `glassport.detectors/2`. It differs from `/1` in how a
gate's own actions enter correlation:

- A client request the gate refuses is folded for analysis (its event, its
  stamps, and the session-state fold are exactly those of a forwarded
  request) but never becomes a pending correlation: the server never saw it,
  so it never displaces or quarantines a real request sharing its id. The HTTP
  gate writes the outer fact `http_observation.admitted: false` on that wire
  entry; the stdio gate's `gate.action: "blocked"` marker means the same.
- The error the gate answers with is logged as an `s2c` entry marked
  `gate: {"action": "injected"}` (the stdio gate's existing marker). In the
  trace it pairs to the refused call and pops no real pending request.

Both markers are outer, tap-written facts; peer JSON cannot set them.

**Journals recorded under `/1` are unsupported under `/2`**, by the profile
check above: they were recorded against a fold in which a refused request did
enter correlation, so re-judging them with the current fold would not be a
replay of the same analysis. No claim is made in the other direction either:
a `/1` reader does not know the `admitted` fact or the injected-reply rule, so
it reads a `/2` wire log with the `/1` fold. It is not asserted to interpret
the new provenance correctly, and `replay-decisions` under `/1` refuses a
`/2` journal for the same reason.

## Bounds

| `JournalLimits` | Default | Meaning |
|---|---:|---|
| `max_epochs` | 128 | tracked epochs and open journal files; LRU, evicted files are closed |
| `max_records` | 4096 | records written per epoch, profile included |
| `max_findings` | 32 | findings *listed* per record (the digest still covers all of them) |
| `max_faults` | 8 | detector faults listed per record |

An epoch evicted from the tracked map and later resumed writes its profile
again. An identical repeat is a benign resume marker; if the epoch's context is
also gone by then, the second profile is marked `pattern_snapshot_exact: false`,
which forces its `pattern_status` to `incomplete` — and it is that field's
mismatch against the first profile's `pattern_status` that trips
`profile_conflict`, which replay reports as `unsupported` rather than comparing
against a profile the recording never actually used.

Past `max_records` the epoch writes one `truncated` marker and then stops;
replay reads that marker and reports `incomplete` rather than claiming
equivalence over a prefix. Record ordinals are unique across the whole journal,
so an evicted epoch that later resumes can never reuse a number an earlier
delivery record links to. These are in-memory and per-file bounds, not a disk
retention quota.

## Fail-open

Every recording entry point returns a falsy value instead of raising: an
unwritable directory, a mid-write error or an exhausted bound produces no record
and no exception. The relay never observes journaling at all — the hooks are
wrapped the same way `_observe_call` wraps analysis, and with `journal=None`
(every path except the new `observe` command) not one additional statement runs.
Unavailable evidence stays fail-open, which is also why a request with no
routable epoch is journaled not at all rather than attributed to a guess.

Delivery records are shaped to supply a later transport-owned gate precondition
— a valid complete request, an unambiguous epoch, successful evidence
persistence, no relevant analysis fault. Building the gate is a separate stage.
