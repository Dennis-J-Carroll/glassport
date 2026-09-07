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
