# Opt-in HTTP session observation

This stage adds a library observation API. The ordinary HTTP `wrap` path keeps
its passive behavior. No HTTP gate or CLI observation flag is enabled by this
stage. Detectors return findings; the transport owns forwarding.

```python
from pathlib import Path
from glassport.http_sessions import HTTPObserver, HTTPRegistryLimits
from glassport.adapters.mcp_http import run_http_tap

captures = Path("./private-captures")
observer = HTTPObserver(captures, limits=HTTPRegistryLimits(max_sessions=32))
run_http_tap("http://127.0.0.1:8000/mcp", captures, observer=observer)
```

The proxy closes the observer when its server exits. Each epoch has a private
JSONL capture, a no-history `MCPTraceBuilder`, and a `DetectorEngine`. Epoch IDs
are local random identifiers. Session headers and credentials are not copied
into routing metadata; payloads remain in private wire captures as before.
Exact captured frame bytes are also retained as `wire_b64`. Oversized frames
retain only a bounded prefix, explicitly marked incomplete.

## Why session identity is part of evidence

Different clients can both issue request ID `1` and declare different tool
sets. Sharing a builder would join unrelated evidence. A registry belongs to
one configured upstream and partitions bindings by session token plus a salted
credential-context digest. Only credential headers retained by the relay's
hop-header filtering contribute to that digest. Session and resumption headers
use the same filtering. Duplicate effective Authorization, Cookie or
Proxy-Authorization fields are ambiguous and cannot reuse established context.
For an ambiguous request carrying a session token, all existing bindings for
that token are retired: the observer cannot know which credential the upstream
will select. This is partitioning, not authentication;
upstream authentication remains responsible for its own credentials, including
any deployment-specific custom credential headers.

Only a successful, correlated JSON-RPC InitializeResult can bind a proposed
session token. Duplicate, malformed, missing and unknown identities never
reuse a global context. Unroutable traffic receives a request-local capture
when capacity permits; it cannot declare a trusted session. Binding collisions
retire both contexts and invalidate their knowledge. A changed response token
also invalidates evidence.

## Bounds and lifecycle

| Setting | Default | Meaning |
|---|---:|---|
| `max_sessions` | 128 | Includes provisional and retired contexts with active leases |
| `idle_ttl` | 300 seconds | Idle contexts become eligible for expiry on the next request |
| `max_identifier_chars` | 256 | Session/resumption/SSE identifier bound |
| `max_sse_ids` | 1024 | Remembered SSE IDs per epoch |
| `max_frame_bytes` | 1,000,000 | Observation prefix bound; SSE also retains its 256 KiB transport cap |

Each context also uses `SessionLimits` for pending requests, ambiguous IDs,
declarations and retained metadata. Disk captures grow with traffic; these are
in-memory bounds, not disk retention quotas.

Only idle contexts are evicted. If all slots are actively leased, new traffic
forwards with `http_capacity` diagnostic and **no context or capture**. It is
never claimed as replayable. Registry locks do not encompass context locking
or I/O. Context folds serialize evidence; observation callbacks run outside
context locks and must use epoch/sequence linkage rather than callback arrival
order. Callback failure cannot stop forwarding. Lease release is idempotent.

Successful DELETE and HTTP 404 retire the context. DELETE 405 leaves a healthy
binding intact. Expiry, binding collision, reset and shutdown cannot redirect
an existing lease into a newer epoch. Retired active contexts remain counted
until their last lease is released. Disconnect alone is not cancellation.

Repeated SSE IDs with identical payloads are captured but skipped by analysis.
An ID with different content, an invalid resumption ID, or a resumption cursor
outside retained history invalidates the epoch. The ID cache never silently
forgets a duplicate: when its fixed capacity fills, the next new ID marks
`http_sse_history_full`. Analysis then remains unavailable until fresh
initialization. This intentionally sacrifices continued analysis rather than
let an old response correlate against a reused request ID. Larger configured
history costs more bounded memory; unbounded history is not offered.

## Incomplete observations and replay

Malformed/oversized frames, unsupported message envelopes, changed identities,
and analysis loss produce namespaced outer `http_observation` facts. Peer JSON
cannot set these outer facts. The adapter preserves their payload as text,
clears declaration knowledge, and reproduces severity-1
`http_observation_unavailable` findings through the shared detector engine.
Later responses in a lost epoch cannot restore exclusion evidence; clients
must initialize a fresh session. Valid requests use POST. Failure-status or
DELETE response bodies cannot supply new declarations.

Both live and saved-wire analysis honor duplicate and loss markers. Normalized
event replay honors the same loss facts. With custom `SessionLimits`, explicitly
supply matching limits to `from_mcp_session_file(path, limits=limits)`; inputs
never silently expand the reader's resource limits. Use matching PII pattern
configuration as well. Versioned configuration recording and verification are
the next stage. Default file readers may load only the trailing 50 MB; use
`tail_cap_bytes=None` when deliberately verifying a complete capture.

`Observation.persisted` means the exact envelope's write call succeeded. It
does not promise fsync durability, client delivery, or remote execution.
Logging failure still returns local observations with `persisted=False` and a
fixed diagnostic. No replay-equivalence claim is made for missing capture data.
The HTTP context supplies the capture sequence, so subsequent successful
records retain exact linkage after a failed write. Deeply nested JSON that
exceeds the parser's recursion limit is retained as raw wire evidence.

## Transport and validation

Explicit observation folds complete JSON bodies or complete SSE frames before
their completing bytes reach the client. JSON lookahead is bounded; excess
bytes continue streaming. SSE uses `read1` so an open stream can deliver a
small event without waiting for 4096 bytes or EOF. Failed analysis remains
fail-open; upstream read failures still forward the received buffered prefix
before transport closes. Ordinary passive SSE forwarding order is unchanged.

Tests cover reused RPC IDs across sessions and threads, POST/GET overlap,
credential partitions, malformed identities, collisions, TTL, capacity,
DELETE/404/reset semantics, SSE duplicate/collision/history saturation/resumption,
raw and normalized replay, custom limits, unavailable logs, callback lock
ownership, partial/oversized bodies, and an open SSE socket. The existing
HTTP lifecycle and hardening suite remains part of validation. Listening
sockets now close on server exit as part of observer teardown.

Next dependency: versioned configuration, candidate decisions, and actual
delivery records for an explicit CLI observation mode. Blocking remains a
subsequent transport integration.
