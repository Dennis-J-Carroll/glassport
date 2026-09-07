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
