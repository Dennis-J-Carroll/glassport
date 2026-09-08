# Priority engineering: #76, #77, and incremental analysis

Implementation record, 2026-09-07. Changes are isolated in sequential commits;
the existing working tree's unrelated changes are excluded.

## Reconnaissance

1. `_TraceBuilder` in `adapters/mcp_session.py` correlates JSON-RPC IDs in
   separate client/server maps. It stores initialization metadata on actors
   and publishes tools/list definitions through server metadata and an agent
   card. Before #76, it accumulated surfaces and published an empty card even
   when no declaration had been observed.
2. `declared_tools()` feeds the CLI, report, MCP query server, and drift
   fingerprints. `fabricated_tool_calls()` also feeds the detector and console
   heatmap. The TUI consumes actor metadata and annotations; SARIF and advisory
   output consume annotations. The browser console consumes the TUI view model.
3. `_relay()` in `adapters/mcp_http.py` creates an upstream connection, sends
   the request, reads headers, and copies JSON or streams SSE. Request/header
   failures, upstream reads, client writes, SSE framing, and logging can exit
   before its old trailing `close()` call.
4. `StreamingSession` already retains `_TraceBuilder` across file polls. It
   parses incrementally but runs all batch detectors again after each poll.
5. Context detection reconstructs initialization order, list-request state,
   first surface, schemas, and capabilities. Exfiltration scans event payloads
   but extracts declared hosts from final actor metadata. Gate annotations are
   event-local. Drift, fingerprints, and aggregate reports remain retrospective.

## Stage 1 — Issue #76

**What / why.** `declared_surface()` represents unknown with `None`, an
explicitly empty declaration with `set()`, and a populated declaration with its
names. A usable correlated tools/list response establishes the current surface.
Malformed lists and protocol errors cannot establish an empty declaration.
Fabricated calls are compared against the declaration observed at call time;
future declarations cannot invent or erase earlier divergence.

**Files.** `interaction_trace.py` owns evidence extraction and trace queries;
`adapters/mcp_session.py` publishes observed current declarations;
`detectors.py` emits severity 3 only for established exclusion. `tap.py`,
`server.py`, `report.py`, `watch.py`, `tui.py`, `console.py`, and
`console_html.py` preserve declaration knowledge in their output/decisions.

**Tests added.** `test_declared_surface.py` covers unknown/empty/populated
surfaces, in-flight lists, later additions and removals, malformed and orphaned
responses, CLI/report/SARIF propagation, and drift to an empty surface.
Streaming and TUI fixtures that assumed retroactive fabrication were corrected:
absence of a declaration cannot justify a HIGH finding. The stale-selection UI
test now uses log rotation to preserve its original purpose.

**Validation.** Full stdlib suite under coverage: 716 tests, OK. Core coverage:
93%, above the unchanged 85% gate. Real stdio and HTTP integration tests ran
with local socket access. Baseline sandbox execution failed on denied sockets;
those environmental failures were resolved by running the required integrations
outside the network sandbox.

**Compatibility.** `declared_tools()` still returns a set. Consumers needing
knowledge use `declared_surface()`; JSON summaries/fingerprints/view models add
`declaration_known`. Latest declarations replace prior surfaces. Empty surfaces
can now prove removal in drift analysis. Low-severity context findings remain.

**Remaining risk / next dependency.** Pagination and bounded session state
need explicit treatment in the incremental foundation. This stage establishes
the call-time semantics required by the first streaming detector. #77 remains
independent and precedes that architectural work.

## Stage 2 — Issue #77

**What / why.** `_relay()` now closes every successfully created connection
in `finally`, including failed requests, failed response parsing, and early
502 returns. It also closes the response: a close-delimited response can own
the socket after `http.client` detaches the connection. Nested cleanup ensures
that a response-close exception cannot skip connection cleanup.

**Files.** `adapters/mcp_http.py` contains the lifecycle correction;
`test_http_connection_lifecycle.py` supplies deterministic response/connection
doubles and direct `close()` assertions.

**Tests added.** Fifteen tests cover normal JSON/SSE, disconnects and read
errors, downstream write/header failures, malformed/rejected responses,
request failures, failing 502 emission, SSE framing and logging exceptions,
response cleanup failures, pre-connect rejection, and real `SessionLog` disk
failure without interrupting SSE forwarding.

**Validation.** Full suite under coverage: 731 tests, OK; core coverage 93%.
Existing HTTP tap and relay adversarial grills pass. Stage 1's advisory,
report, SARIF, streaming, and server grills also passed.

**Compatibility / remaining risk.** Existing forwarding, bounded buffering,
header hardening, timeouts, and response delimiting are preserved. Unexpected
framing/programming exceptions still propagate as before, with deterministic
cleanup; ordinary logger write failures remain fail-open. No HTTP gate was
introduced. Both correctness fixes are now independently tested, unlocking
the incremental session foundation.

## Stage 3 — Incremental session foundation

**What / why.** Public `MCPTraceBuilder.ingest_frame(entry)` extends the
existing parser and returns each event immediately. `SessionState.observe()`
folds normalized evidence into initialization, client/server capabilities,
list-request state, current schemas/surface, and the first complete surface.
Gate evidence is stamped immediately, rather than rescanning and rewriting
historical events on every snapshot. There is no detection or policy here.

**Files.** New `session.py` owns the bounded evidence projection;
`adapters/mcp_session.py` owns direction-aware correlation and normalization;
trace declaration queries replay the same state. `test_incremental_session.py`
locks the contract; the coverage workflow now includes `session.py`.

**Bounds.** Defaults: 4096 pending IDs per direction, 4096 tool definitions,
1,000,000 serialized bytes per retained metadata/declaration value, and 1024
characters per retained name/cursor/ID. Integer correlation IDs are capped at
128 bits. Oldest pending entries are evicted and the triggering event records
`correlation_limited`; later unmatched replies remain observable as orphaned.
Oversized declarations become unknown, with a fixed `limit_reasons` code.
Only current definitions, the first surface, and one bounded pagination chain
are retained. Partial or mismatched pagination cannot prove exclusion.

**Tests / validation.** Twelve new tests cover prefix-by-prefix batch/ingest
equivalence, immediate gate evidence, evidence/state isolation, no-history
mode over 1000 calls, directional eviction, hostile IDs, declaration/schema
limits, pagination completion/mismatch, initialization order, and raw entries.
Full suite: 743 tests, OK; core coverage 93% (`session.py`: 88%). Streaming
adversarial grill passed.

**Compatibility / risks.** `_TraceBuilder` remains an alias and `feed()`
remains supported. Existing report/file callers retain complete history by
default; this explicitly requested retention is not a constant-memory claim.
Use `retain_events=False` for bounded live ingestion and persist wire entries
separately. Its snapshot contains current state, not a forensic event archive.
Custom limits are recorded in snapshot metadata and must be supplied when
replaying original wire entries. Pagination and malformed/oversized declarations
now use conservative unknown semantics. Context/schema and PII detectors still
use their existing batch semantics until their separate migration stages.

**Next dependency.** One streaming fabricated-call detector can now consume
the exact same session facts used by trace queries and batch replay.

## Stage 4 — Streaming lifecycle and first detector

**What / why.** `incremental.py` introduces session-scoped `StreamingDetector`
instances, `DetectorEngine.on_event(event, state)`, and idempotent `finish(state)`.
Only `FabricatedCallsDetector` is migrated in this stage. It returns a finding
as soon as a call outside a known surface is observed. Batch `fabricated_calls()`
replays the same implementation; `annotate(trace)` remains supported.

**Files / tests.** `incremental.py` owns lifecycle and fault isolation;
`detectors.py` keeps the batch entry point. Nine tests in
`test_incremental_detectors.py` compare batch/event/live-frame results using
every semantic annotation field, including explanation, metadata, annotator,
severity, category, and event linkage. Only generated IDs and incidental result
ordering are normalized. Correctness cases separately assert immediate output
and the declaration sequence supporting it. Fault-isolation cases cover errors
with unsafe `__str__`, finish failures, session identity, and repeated finish.

**Validation.** Full suite: 752 tests, OK. Expanded core coverage gate passes.
No context, schema, or PII detector was migrated before this slice passed.

**Compatibility / risks.** Findings gain `declaration_seq` for replayable
supporting evidence. Engine construction starts a session; it retains detector
instances and a reference to bounded state, but no event/annotation history.
Callers pass state after ingestion; the engine does not double-fold it.
Detector failures are event-linked diagnostics with exception type, never raw
exception text. The engine has no transport handle or block/forward operation.
Existing file-poll UI analysis still reruns the remaining batch detectors.

**Next dependency.** Context/schema migration can now use the same lifecycle
and permanent parity harness, with chronological semantics explicitly tested.

## Stage 5 — Context and schema detectors

**What / why.** `ContextDetector` consumes session facts for initialization
ordering, call-before-declaration, schema checks, capability violations,
unknown server requests, orphaned replies, and first-vs-current surface changes.
`context_violations(trace)` is now a replay wrapper. No detector rescans history
to recover these facts during live processing.

**Files / tests.** `incremental.py` owns the per-event checks; `detectors.py`
retains the public batch entry point and schema primitives. Six new parity
tests cover future schemas/capabilities, changed schemas, server-originated
initialization spoofing, every migrated category, and recovery after a malformed
schema causes one event's detector pass to fail.

**Validation.** Full suite: 758 tests, OK; expanded core coverage gate passes.

**Compatibility / remaining risk.** Schema/capability judgments now require
facts observed at the event, rather than final actor metadata. Updated schemas
replace older ones. Only client-originated initialized notifications satisfy
the client ordering check. Schema validation remains the existing top-level
JSON Schema subset. Drift/fingerprints stay retrospective. PII/egress still
awaits its own migration and chronological host-declaration tests.

**Next dependency.** PII and exfiltration can reuse the lifecycle without
duplicating schema/declaration tracking or introducing transport decisions.

## Stage 6 — PII, exfiltration, and live file analysis

**What / why.** `DataExfiltrationDetector` reuses the existing per-event PII
scanner, validators, normalization, redaction, and egress rules. Declared hosts
come from bounded current server metadata and tool definitions, cached until
those facts change. Gate-record interpretation also uses a shared per-event
helper. Default batch `annotate()` now replays all four built-in passes through
one state fold; live analysis never rescans earlier events for these passes.

**Files.** `detectors.py` retains public batch functions and scan primitives;
`incremental.py` owns lifecycle adapters and fixed-code `analysis_limit`
diagnostics. `adapters/streaming.py` consumes newly parsed events immediately.
`test_incremental_detectors.py`, `test_streaming.py`, and the real stdio/HTTP
integration tests lock parity. `scripts/bench_incremental.py` measures repeated
throughput, latency, and long-session retained memory without timing gates.

**Tests / validation.** Added credential/redaction, future/removed host,
trusted-cloud PII, all-detector replay, committed-session replay, gate evidence,
state-limit reporting, bounded growing tails, partial-line bounds, and custom
registry transition cases. The real filesystem-server stdio capture and named
SSE HTTP capture now pass through the same parity oracle. Full suite: 772 tests,
OK; core coverage 92%, incremental module 100%, streaming adapter 97%. All nine
existing grills passed: advise, report, SARIF, redaction, server, streaming,
provenance, HTTP tap, and HTTP relay. The existing 2-second adversarial scanner
test exceeded its threshold by 21 ms while benchmarks ran concurrently; an
isolated recheck and the complete isolated suite passed. No threshold changed.

**Performance evidence.** Python 3.13.5 on this Linux host, five samples of
2000 events: median 18,922 events/sec, median event latency 48.06 microseconds,
p95 74.29 microseconds. After warming through 8192 events, retained allocations
grew 332 bytes through 32,768 events. Pending correlation stayed at 4096;
retained events and annotations stayed at zero. These numbers measure the
builder plus detectors, excluding transport, disk persistence, and rendering;
they are observations, not portable guarantees. Existing batch benchmark also
passed its ceilings.

**Compatibility / remaining risk.** Future host declarations no longer erase
earlier egress findings; removed hosts affect later calls. Custom modifications
to the batch `DETECTORS` registry retain fault-isolated batch execution, and a
registry change rebuilds the file view. `StreamingSession` bounds retained
events, findings, and partial input by its byte window (50 MB default); once a
file exceeds that window, each change replays its bounded tail and explicitly
marks `tail_only`. It can therefore lose early declarations, as batch tail
ingestion does. Continuous analysis should use the no-history builder/engine
pair and persist wire evidence independently. Detector errors and state-limit
diagnostics are returned to callers without an internal annotation archive.

**Next dependency.** A small pure policy interface can consume these findings
without adding security judgments or forwarding decisions to transport code.

**Parity follow-up.** Final review found that an oversized `clientInfo` or
`protocolVersion` produced a live metadata-limit warning that normalized-event
replay lost: the builder recorded truncation only in mutable session state.
Truncation now marks the triggering event with `session_metadata_limited`, and
the shared state fold consumes that fact. Raw payloads remain unchanged. A new
regression first reproduced the failure for client identity and both protocol
version directions, then passed in retained, no-history, and batch replay modes.
The focused session/engine/policy/file-streaming suite passed all 62 tests.

## Stage 7 — Policy boundary and HTTP preparation

**What / why.** New `policy.py` defines immutable `Decision` records and three
actions: allow, warn, and block. `decide()` reads only trusted detector output
linked to the requested event. It ignores informational gate records, zero
severity, earlier events, and session-final diagnostics. Severity-1 observations
remain warnings, as selected by the user. Default policy never blocks. Explicit
`block_fabricated=True` selects only severity-3 hallucination findings with
subcategory `fabricated_tool_call` and `no_declaration_seen is False`.

**Files / tests.** `policy.py` contains the pure decision function; no transport
module imports it. Nine tests in `test_policy.py` cover opt-in and declaration
requirements, PII/other high-severity findings, stale/global findings, gate INFO
records, severity-1 visibility, boolean option validation, immutable decisions,
payload-free reasons, and reconstruction from persisted wire. The core coverage
workflow now includes the policy module. README and STATUS describe implemented
source behavior separately from the unchanged 0.6.10 release baseline.

**Final validation.** All 782 tests passed, including real stdio and HTTP
integration, under coverage.py 7.13 on Python 3.13.5 using its supported
`sys.monitoring` core (42.620 seconds). Core coverage is 93%, above the unchanged
85% gate; incremental and policy modules are each 100%. All nine security
grills passed again against the final source. `git diff --check` is clean.
Default-tracer coverage runs intermittently exceeded the existing scanner
wall-clock assertions (3.036 seconds against 3.0; 2.138 against 2.0).
Lower-overhead monitoring passed the same assertions and collected coverage;
no test, timing threshold, or CI tracer setting was weakened or skipped.
Default-tracer timing sensitivity remains a CI risk, not a functional failure
hidden by the new tests. The successful coverage command was:

```bash
COVERAGE_CORE=sysmon COVERAGE_FILE=/tmp/glassport-priority-sysmon.coverage \
  python -m coverage run --source=src/glassport \
  -m unittest discover -s tests -t .
```

**Compatibility / remaining risk.** No forwarding behavior changes. Existing
stdio `Gate` retains its implementation; active parity is not claimed. HTTP
enforcement still needs one builder/engine per MCP session, routing across
concurrent HTTP requests/SSE streams, explicit behavior for incomplete evidence
and detector failure, and persisted records tying wire sequence, policy version,
decision, and actual delivery together. A pure `ALLOW` means this policy found
no actionable event finding; it is not a safety certification. Session-final
diagnostics belong in reporting and cannot retroactively block completed calls.

**Next dependency.** A later transport integration can consume this shared
session/engine/policy pipeline after defining those delivery and session
contracts. No broad HTTP gate, approval workflow, policy DSL, dependency,
package-version change, push, or release was added here.

## Declaration correlation correction — before HTTP routing

Independent review reproduced four paths to false fabricated-call blocks:
angle-bracket tool names impersonated protocol requests; rejected duplicate
IDs reused stale requests; an old continuation completed a newer listing that
reused its cursor; and eviction of a refresh left stale exclusion active.

Pending records now keep RPC methods separate from tool names. Replacing an
outstanding ID removes its old association before validation and retains a
bounded ambiguous-ID tombstone, so a response cannot stand for either request.
Each root listing starts a new declaration generation immediately and makes
exclusion unknown while its response is pending. Continuations bind to that
generation when requested; duplicate, unmatched, malformed, and lost chains
remain unknown. Superseded responses never replace newer evidence. Relevant
correlation losses are recorded on the triggering normalized event; unrelated
or opposite-direction evictions preserve healthy declarations.

Generation identities are deterministic 128-bit counters, with saturation
leaving declarations unknown instead of reusing an old identity. Only the current
chain and the existing bounded pending maps retain generation data. No event
or finding history is added. Normalized-event and raw-wire replay reconstruct
the same evidence, findings, and policy actions with identical limits.

Calls without a complete available declaration now receive a severity-1
`declaration_unavailable` observation, unless `call_before_declaration` already
explains the missing evidence. Explicit fabricated-call policy consequently
warns while declarations are unknown. Valid complete listings, known-empty
exclusion, completed pagination, and current-schema validation retain their
existing behavior; a fresh valid listing restores declaration knowledge.
Angle-bracket tool results, including errors, are now ordinary tool results.

These are intentional compatibility corrections: pending refreshes suspend
old schema and host declarations as well as exclusion, and new low-severity
observations can appear in analysis. Older normalized events without generation
metadata conservatively remain unknown; reimport their original wire logs to
recover correlated declarations. The adapter's protocol-reply display tags
remain available for existing renderers.

The four independent repros failed before the change. Fifteen focused tests in
`tests/test_declaration_correlation.py` cover the hostile cases, recovery,
positive declarations, direction isolation, retention, and complete event,
finding, and policy parity. The focused declaration/session/detector/policy/
streaming suite passed 145 tests; full-suite coverage validation remains owned
by the integrating controller. No HTTP forwarding behavior changes here.

## Library integration

The caller must persist original tap entries separately and pass one session's
entries in wire order. This example emits each result through a caller-owned
callback without accumulating history:

```python
from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.incremental import DetectorEngine
from glassport.policy import decide
from glassport.session import SessionLimits


def analyze(entries, emit, emit_final, *, limits=None, block_fabricated=False):
    builder = MCPTraceBuilder(
        retain_events=False, limits=limits or SessionLimits()
    )
    engine = DetectorEngine()
    for entry in entries:  # already persisted {seq, dir, frame/raw, ...} entries
        event = builder.ingest_frame(entry)
        if event is None:
            continue
        findings = engine.on_event(event, builder.state)
        decision = decide(event.id, findings, block_fabricated=block_fabricated)
        emit(entry.get("seq"), event, findings, decision)
    emit_final(engine.finish(builder.state))
```

`emit` controls persistence/rendering; it does not have to enforce decisions.
The engine consumes state **after** ingestion. With pre-normalized events,
construct `SessionState`, call `state.observe(event)`, then call
`engine.on_event(event, state)`. Construction starts a detector session;
`finish()` is idempotent, and processing after finish or with another state
raises `ValueError`. Create a fresh builder and engine for each session.

Default batch `annotate(trace)` collects replayed findings for existing report,
SARIF, advisory, and UI consumers. Generated event/annotation IDs differ between
separate raw-wire imports; sequence/order plus finding semantics establish
replay equivalence. Persist identifiers and sequence mappings if recording
live decisions. Reuse the same session limits and PII pattern configuration
when replaying original wire: normalized snapshots record limits, but a raw
wire log alone does not record arbitrary caller options or custom validators.

The builder defaults to retaining events for compatibility. Only explicit
`retain_events=False` provides no-history ingestion. In that mode, `snapshot()`
is a current-state view and must not be treated as a forensic archive. Neither
the detector engine nor policy accumulates findings internally. Input-frame
size still belongs to framing: retained session bounds do not make decoding
one arbitrarily large caller-supplied frame constant-memory.

Repeatable local checks (from the repository root):

```bash
python -m unittest discover -s tests -t .
PYTHONPATH=src python scripts/bench_incremental.py
```

The benchmark reports repeated throughput/latency samples and retained-memory
growth after correlation-map saturation. It asserts structural retention bounds,
not host-dependent elapsed-time ceilings. Existing CI timing tests were left
unchanged; their coverage-instrumentation sensitivity remains documented in
STATUS.md.

## Agreed follow-up sequence — 2026-09-08

Keep each step independently reviewable. The current implementation lives on
`fix/priority-streaming-foundation`; committing/pushing this branch does not
release the package or enable enforcement.

1. **Review and land the current stack.** Review #76 and #77 as independent
   correctness fixes, followed by the session, detector, parity, and policy
   commits. Preserve the existing commit boundaries when preparing PRs. Run PR
   CI against the exact proposed merge head, including real stdio/HTTP captures,
   nine security grills, and the unchanged 85% core coverage gate. Address the
   default-tracer timing sensitivity in a separate, bounded follow-up with
   repeated measurements and an explicit instrumentation strategy; do not
   silently raise timing limits or exclude scanner coverage.
   **Done when:** the reviewed code passes required CI, any timing-methodology
   change has its own evidence, and release notes distinguish changed semantics
   from future enforcement. Choose a release version during release preparation.

2. **Add bounded HTTP session routing.** Give each MCP session its own builder,
   detector engine, and lifecycle. Specify initialization before a session ID
   exists, session binding, concurrent POST/GET/SSE traffic, reconnects, expiry,
   and unknown session IDs before coding forwarding decisions. Bound active
   sessions and idle retention in addition to the existing per-session limits.
   **Done when:** tests interleave two sessions with reused JSON-RPC IDs and
   different tool surfaces without cross-correlation or declaration leakage;
   teardown frees state; captured session replay matches live annotations.

3. **Persist decision evidence and run HTTP policy in observation mode.** Keep
   raw wire evidence separate from interpretation. Add a versioned record
   connecting session identity, wire sequence/event mapping, detector and policy
   versions, limits, reproducible PII configuration, supporting annotations,
   selected action, and actual delivery outcome. Record a candidate block as
   “would block” while forwarding remains observational. Do not duplicate secret
   payloads into decision records.
   **Done when:** replay reconstructs candidate decisions from saved evidence
   and configuration; concurrent streams, disconnects, detector errors, and
   persistence failures have explicit tested behavior. Passive `wrap` continues
   forwarding when interpretation or logging fails.

4. **Add one explicit HTTP enforcement rule.** Integrate the shared policy for
   severity-3 fabricated calls outside an observed surface. Keep severity-1
   warnings visible. Unknown or incomplete declarations and detector failures
   must not become fabricated-call blocks; explicitly empty declarations remain
   valid exclusion evidence. Define protocol-correct blocked responses and
   verify that blocked requests never reach upstream. Keep passive `wrap`
   unchanged and avoid a general policy language.
   **Done when:** allow/warn/block outcomes, upstream delivery, decision logs,
   and replay agree across JSON and SSE fixtures; adversarial tests cover
   concurrent sessions, declaration changes, cancellation, and disconnects.

Migrating the existing stdio `Gate` to the shared engine is a later separate
compatibility task. A2A support, observatory UI work, additional blocking rules,
and release automation remain outside this sequence.
