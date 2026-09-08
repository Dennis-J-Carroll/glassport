# Glassport HTTP integrity: implementation plan

## Intent and authority

Execute the user's agreed four-step follow-up, informed by GP_deep_run.md.
The attached document is design guidance; the user's request and the existing
evidence/interpretation, passive-operation, and explicit-enforcement contracts
remain authoritative. Work starts from the completed streaming foundation and
the current upstream main. Existing user changes stay in the original checkout.

## Global constraints

- Python 3.10+, zero runtime dependencies.
- Transport records evidence; session state folds facts; detectors return
  annotations; policy selects actions; explicit enforcement controls delivery.
- Passive wrap continues forwarding when interpretation or logging fails.
- UNKNOWN is distinct from KNOWN_EMPTY. Only observed exclusion can justify
  severity-3 fabricated-call blocking. Other high findings remain warnings.
- Live annotations and candidate policy decisions must reconstruct from saved
  wire evidence plus versioned session configuration.
- Bound per-session state and the session registry; no unbounded event,
  annotation, identity, or replay-deduplication maps.
- Preserve stdio behavior, HTTP framing/header/timeout hardening, and raw bytes.
- Keep each task in a separate commit; do not merge, tag, or publish releases
  during implementation. Prepare concrete release/merge artifacts for review.
- Retain the 85% core coverage gate and all nine existing security grills.
  Never raise a timing threshold or skip scanner coverage to hide failures.
- No A2A, dashboard, policy DSL, authentication system, or stdio Gate migration.

## Task 1: Stabilize coverage and performance measurement

Own scripts/bench_scanner.py (new), docs/performance-methodology.md (new),
.github/workflows/ci-coverage.yml, and only necessary focused benchmark tests.
Read tests/test_hardening.py's BEGIN-marker flood case,
tests/test_comprehensive_security.py's long-argument case, scripts/bench.py,
scripts/bench_incremental.py, and the existing coverage workflow.

Add a reproducible stdlib benchmark driver that compares repeated cold/warm
samples of normal execution, coverage's default/current C tracer, and supported
sys.monitoring coverage. Exercise the actual scanner and full data_exfiltration
entry point for the two adversarial cases; report interpreter, platform,
coverage version/core, sample count, median and p95, and any unsupported mode.
Do not introduce timing gates based on a single run. Keep generated artifacts
out of tracked source. Run timing samples serially, without concurrent suites.

Use measurements to choose and document a supported coverage instrumentation
strategy. An explicit supported low-overhead coverage mode is allowed if it
collects the same line coverage and retains all tests and the 85% gate. Check
the supported runtime and version constraints; fail visibly if CI silently
falls back to a different core. Do not modify runtime scanners or weaken tests.
Keep the normal Python 3.10–3.13 matrix intact. Run the full suite once with the
chosen coverage path, report core coverage, and commit the focused change.

Done when measurements and exact commands are documented, coverage semantics
are unchanged, and the chosen CI path passes the complete suite locally.

## Task 2: Isolate HTTP session state

Own a new bounded HTTP session registry module and focused tests, plus the
minimum HTTP framing/log metadata integration required to route observations.
Each session owns MCPTraceBuilder(retain_events=False), DetectorEngine, and
independent sequence/correlation state. One registry instance belongs to one
configured upstream proxy; concurrency never shares builders across sessions.

Define provisional initialization routing, binding to an upstream session ID,
existing/unknown/missing/malformed IDs, concurrent POST/GET/SSE traffic,
reconnect/resumption, successful DELETE/expiry, and teardown while requests are
active. Bound active sessions, idle TTL, identifier size, and retained transport
metadata. Do not evict a context that is actively leased to a request. Missing
or unknown identity must not silently reuse another client's context. If
analysis cannot be routed reliably, preserve forwarding and record incomplete
observation. Persist enough routing facts to reproduce per-session event order.

Prove isolation with two aggressively interleaved sessions declaring different
tools while reusing identical JSON-RPC IDs. Cover capacity pressure, abandoned
sessions, malformed identifiers, binding collisions, expiry, reconnect, and
SSE/POST overlap. Keep passive HTTP unchanged at the byte boundary and rerun
existing HTTP lifecycle/grill tests. No blocking in this task.

Design rulings for this task:
- Keep the ordinary run_http_tap path compatible. Routing/analysis is explicitly
  enabled through an optional integration object/API; Task 3 exposes observation
  mode and Task 4 exposes enforcement. Neither detector code nor registry code
  receives a transport send/block operation.
- Use opaque local session/epoch IDs in logs and decisions, not raw upstream
  session headers or authorization values. A proxy instance scopes one upstream.
  Partition by an opaque credential-context fingerprint when credentials differ;
  this prevents accidental state reuse, but is not authentication or identity
  verification. Upstream authentication remains upstream-owned.
- Never feed a multiplexed HTTP capture into a single-session builder. Prefer
  one replayable wire stream/file per observed session epoch, including isolated
  request-scoped captures when identity cannot be established. Keep existing
  stdio/file consumers safe without a broad UI redesign. A reset or lost session
  starts a new epoch rather than inheriting an old declaration in replay.
- Session IDs must be bounded visible ASCII and unambiguous single headers.
  Bind only a successful correlated initialization result to its response's
  proposed session ID. Missing/unknown IDs never discover state by JSON-RPC ID,
  source IP, or a global fallback context. Binding collisions invalidate trust
  rather than merge unrelated contexts.
- Do not hold a registry lock while acquiring a context lock or performing I/O.
  Serialize each context's evidence and state fold; lease release is idempotent.
  Capacity counts retired contexts until active leases finish. Only idle
  contexts can be selected for eviction; all-active capacity pressure produces
  incomplete observation for new traffic.
- Deduplicate repeated SSE event IDs only within bounded per-session history,
  and preserve every received wire frame. A repeated ID with different content
  or a resumption cursor outside retained evidence must not restore stale
  declarations. Never infer cancellation from a disconnect.
- In the explicitly analyzed mode, observe complete server frames before their
  completing bytes reach the client, so a client's follow-up cannot outrun the
  declaration fold. Ordinary passive SSE keeps its existing forwarding order.

Protocol references checked for this design:
[MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and [session security](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices).
These describe transport mechanics; they do not authorize any external action.

## Task 3: Record decisions and delivery in observation mode

Own versioned decision/configuration recording and replay validation modules,
with focused tests and minimum integration into the session router/HTTP relay.
Keep decision evidence separate from raw wire logs. Record session and event
sequence linkage, detector/policy versions, limits and reproducible PII
configuration, semantic supporting findings, candidate action, mode, and delivery
outcome. Do not copy attacker-controlled payloads or secret values into records.

Make candidate block distinct from actual delivery: observation mode records
would-block yet forwards. A successful local socket write is not proof that a
remote tool executed. Use precise sent/not-sent/failed/unknown outcomes and
define behavior when writes fail after partial transmission. Persist decision
intent before delivery when possible; record terminal outcome afterward.
Logging or detector failure remains fail-open in passive observation.

Replay must verify matching implementation/configuration profiles before
claiming equivalence and compare semantic findings and actions. Do not silently
claim reproducibility for arbitrary callable custom validators. Bound record
size and in-memory retention. Test tampered/missing configuration, reordered or
missing wire evidence, detector errors, persistence failure, disconnect, and
simultaneous sessions; no blocking yet.

## Task 4: Add narrow explicit HTTP enforcement

Only after tasks 1–3 pass their reviews and tests, integrate explicit HTTP gate
mode through the shared engine and policy. Preserve passive wrap. Block only
severity-3 fabricated calls supported by an observed surface; known-empty is
valid exclusion evidence. Missing, incomplete, or malformed declarations and
detector failure must forward with a diagnostic. PII and unexpected egress
remain warn/observe only. No arbitrary detector/plugin blocking.

Return a protocol-valid JSON-RPC error preserving the request ID and verify
that blocked requests never reach upstream. Define notifications, unsupported
or oversized/malformed bodies, concurrent declarations, cancellation, stale
sessions, reconnect, persistence failure, and uncertain delivery conservatively.
Keep raw incoming evidence separate from the synthetic response and record
candidate/selected action plus actual delivery outcome. Expose the smallest
explicit library/CLI surface consistent with existing wrap/gate commands.

Required integration matrix: unknown/incomplete/malformed declaration forwards;
allowed declared tool forwards; excluded/known-empty call blocks; detector error
forwards with diagnostic; PII-only high forwards. Repeat decisive block test
with JSON/SSE negotiation, concurrent sessions, surface updates, disconnects,
cancellation, and record persistence failures. Replay must reproduce decisions.

## Task 5: Validate and prepare review/release artifacts

Run full unit/integration/coverage, all nine grills, repeated benchmarks, and a
broad independent review of the completed branch. Resolve actionable findings
and verify only affected tests after focused fixes. Update README/STATUS and
write migration/release notes with exact supported boundaries. Prepare PRs or
review-ready commits preserving #76/#77 isolation and the staged implementation.
Capture exact CI head and results. Merging and publishing remain explicit final
actions after a concrete reviewable result exists; do not invent a release
version or claim a release occurred.

## Task 6: Repair declaration evidence before HTTP integration

Inserted after Task 1 and before Task 2 by independent foundation review.
Own src/glassport/adapters/mcp_session.py, src/glassport/session.py,
src/glassport/incremental.py for declaration-uncertainty diagnostics,
src/glassport/interaction_trace.py only if needed, and focused declaration,
incremental-state/parity/policy regression tests. Update the implementation
record with intentional compatibility changes. Do not modify HTTP transport,
PII scanners, coverage settings, or unrelated consumers.

Four Important findings must be fixed as one coherent correlation correction:

1. Pending entries encode both tool names and RPC method tags in one string.
   A tools/call named `<tools/list>` followed by result {tools: []} establishes
   exclusion despite no tools/list request. A `<initialize>` tool name can
   similarly impersonate protocol initialization. Separate request kind/method
   from the untrusted tool name; legitimate angle-bracket tool names must remain
   ordinary calls/results.
2. An invalid/oversized replacement request returns before removing the prior
   same-ID pending record. Remove stale associations when a replacement is
   rejected; ambiguous duplicate IDs must not establish declaration evidence.
   Preserve per-direction ID isolation and bounds.
3. Pagination currently associates continuations by cursor string alone.
   A pending continuation from chain A can complete a newer chain B when both
   reuse the cursor. Bind each continuation to the generation observed when it
   was requested. Interrupted, superseded, or ambiguous chains stay unknown;
   never assemble a surface from different list operations. Keep retained state
   bounded and reconstructed identically from normalized events and raw wire.
4. Evicting a pending tools/list refresh leaves stale exclusion active.
   Lost or ambiguous declaration correlation must invalidate relevant surface
   knowledge through replayable evidence. Do not invalidate a healthy surface
  merely because an unrelated ping/result is evicted. A pending refresh must
  not become false exclusion when its response cannot be correlated.

When a tools/call cannot be evaluated because declaration evidence is pending,
malformed, superseded, or lost, preserve a severity-1 declaration-unavailable
observation through the shared ContextDetector. Avoid duplicate low observations
when call_before_declaration already explains the same missing evidence. This
supports the agreed forward-plus-warning behavior in later explicit HTTP mode.

Required negative examples (frames in wire order):
- tools/call `<tools/list>` id=1; result id=1 {tools: []}; call real id=2:
  no fabricated block. Also test `<initialize>` and ordinary angle-bracket names.
- max_name_chars=12: root tools/list id=1; tools/list id=1 cursor of 20 x's;
  result id=1 {tools: []}; call real id=2: no fabricated block.
- A root id=1 -> [a1], nextCursor=page2; A continuation id=2 cursor=page2;
  B root id=3 -> [b1], nextCursor=page2; A continuation reply id=2 -> [a2]:
  never declare the synthetic set {b1,a2}; a1 must not be blocked by that set.
- max_pending=1: root id=1 -> []; refresh tools/list id=2; ping id=3 evicts
  refresh; reply id=2 -> [real]; call real id=4: no fabricated block.

Prove positives too: valid root/complete pagination, known-empty exclusion,
ordinary current-schema validation, unrelated correlation pressure, restoration
after a fresh valid listing, and no-history bounded retention. Use the permanent
semantic parity oracle including policy outcomes for every hostile case.
Generated chain identity must not create raw-wire replay divergence.
Add failing regressions first, then fix; retain full covering-test output.
Run focused tests during iteration and the full suite once under the supported
coverage core before committing. Report any adjacent concerns separately.
