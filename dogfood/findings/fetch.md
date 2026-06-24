# Dogfood Finding — mcp-server-fetch

**Date:** 2026-06-24  
**Glassport worktree:** `kimi/eval`  
**Server:** `mcp-server-fetch` (serverInfo: `mcp-fetch` v1.28.0)  
**Driver:** `dogfood/eval_fetch.py`  
**Session log:** `dogfood/logs/fetch/20260624T003355Z_uvx_411207.jsonl`

## Setup

Launched the fetch server behind glassport tap. No API key is required; the server makes outbound HTTP requests.

```bash
python glassport_tap.py --log-dir dogfood/logs/fetch -- \
  uvx mcp-server-fetch
```

Driver performed MCP handshake (`initialize` → `notifications/initialized` → `tools/list`) then issued all calls in one session.

## Tool surface observed

1 tool declared:

- `fetch` — Fetches a URL from the internet and optionally extracts its contents as markdown.

`inputSchema`:

| Field | Type | Constraints |
|-------|------|-------------|
| `url` | string | required, `format: uri`, `minLength: 1` |
| `max_length` | integer | default `5000`, `exclusiveMinimum: 0`, `exclusiveMaximum: 1000000` |
| `start_index` | integer | default `0`, `minimum: 0` |
| `raw` | boolean | default `false` |

## Benign behavior

| Call | Payload | Result |
|------|---------|--------|
| `fetch` | `{"url": "https://example.com", "max_length": 1000}` | **No response within 60 s.** The server accepted the call but never returned a result before the driver timed out. Repeated in isolation with the same outcome. Outbound HTTP appears to hang in this environment. |

## Adversarial behavior

| Test | Payload | Result |
|------|---------|--------|
| `file://` URL | `{"url": "file:///etc/passwd", "max_length": 1000}` | Blocked: `isError=true`, text: `"Failed to fetch robots.txt file:///robots.txt due to a connection issue"`. The server attempts a robots.txt fetch for the supplied scheme rather than rejecting `file://` outright. |
| `localhost` URL | `{"url": "http://localhost:22", "max_length": 1000}` | **No response within 60 s.** Like the benign fetch, the call hung without returning. |
| Oversized `max_length` | `{"url": "https://example.com", "max_length": 999999999}` | Blocked by input validation: `isError=true`, text: `"Input validation error: 999999999 is greater than or equal to the maximum of 1000000"`. |
| Invalid scheme | `{"url": "foo://bar", "max_length": 1000}` | Blocked: `isError=true`, text: `"Failed to fetch robots.txt foo://bar/robots.txt due to a connection issue"`. Same robots.txt pre-fetch behavior as `file://`. |
| Invalid URL | `{"url": "not-a-url", "max_length": 1000}` | **No response within 60 s.** The call hung; likely treated as a resolvable host and attempted. |
| Unknown tool | `{"name": "unknown_tool_xyz", "arguments": {"url": "https://example.com"}}` | **No response within 60 s.** glassport logged a warning: `Tool 'unknown_tool_xyz' not listed, no validation will be performed`, then passed the call through. The server did not return an error before timeout. |

## glassport observations

- **Tap:** logged all 15 frames cleanly; no dropped bytes. Session exited with code 0 after the driver timed out and terminated the subprocess.
- **Summarize:**
  - Correctly extracted the declared tool (`fetch`) and all called tools.
  - Correctly flagged the fabricated call: `FABRICATED CALLS: [(10, 'unknown_tool_xyz')]`.
  - **Issue:** reported three "protocol errors" for frames 13, 14, and 15, which are valid `tools/call` responses containing `isError=true`. Those are normal server-side error results, not protocol violations.
    - **✅ RESOLVED (2026-06-24):** `summarize` now splits `tool_errors` (isError results) from `protocol_errors` (real JSON-RPC errors). Frames 13/14/15 render under `tool errors:`. Fixed in `tap.py`; locked by `tests/test_cli.py::TestSummarizeErrorTaxonomy`.
- **Detect:**
  ```
  [HIGH] seq=10 fabricated_tool_call: tools/call 'unknown_tool_xyz' is outside the declared surface
  [WARN] seq=4 unexpected_egress_host: tools/call 'fetch' reaches example.com (undeclared)
  [WARN] seq=7 unexpected_egress_host: tools/call 'fetch' reaches example.com (undeclared)
  [WARN] seq=10 unexpected_egress_host: tools/call 'unknown_tool_xyz' reaches example.com (undeclared)
  ```
  - The `seq=10` fabricated-tool finding is correct and useful.
  - `seq=4` (`fetch` to `https://example.com`) is a reasonable egress observation.
  - ~~**Issue:** `seq=7` is the `foo://bar` call, yet detect reports the host as `example.com`. The egress parser appears to reuse a previously-seen host instead of extracting `bar` (or no valid host) from the actual payload.~~
    - **❌ RETRACTED (2026-06-24) — misread, not a bug.** Frame `seq` counts *all* frames, not just calls. seq=7's args are genuinely `{"url": "https://example.com", "max_length": 999999999}` (the oversized-`max_length` probe, which reused example.com). The `foo://bar` **call** is `seq=8`; `seq=15` is its *result*. The `foo://bar` call correctly produces **no** egress finding (`foo://` matches neither the http(s)/ws(s) URL regex nor the bare-domain check). `_extract_hosts_from_args` is stateless — verified by feeding each payload independently. No glassport defect.
  - `seq=10` also flags `example.com` because the unknown-tool arguments contain that URL; this is redundant with the fabricated-tool finding.

## Findings

1. **Outbound HTTP fetches hang indefinitely** in this environment. Both the benign `https://example.com` call and the `http://localhost:22` probe produced no server response within 60 seconds. Normal operation of the fetch server is blocked.
2. **Non-HTTP schemes are rejected at the robots.txt stage, not by scheme allow-listing.** Both `file://` and `foo://` triggered `"Failed to fetch robots.txt <scheme>:///robots.txt"`. This leaks the server's internal behavior (it tries to retrieve a robots.txt for any scheme) and produces confusing error messages.
3. **`max_length` input validation is effective.** The oversized value was rejected immediately with a clear schema error.
4. **glassport `summarize` misclassifies `isError=true` tool results as protocol errors.** Server-side error responses should be treated as normal MCP results, not protocol violations. **✅ FIXED** — `tool_errors` field added (see Summarize note above).
5. ~~**glassport `detect` reports an incorrect egress host for the `foo://bar` call.**~~ **❌ RETRACTED — analyst misread of frame `seq`.** seq=7 genuinely targeted example.com; the `foo://bar` call (seq=8) correctly yields no egress host. Extraction is stateless; no defect (see Detect note above).
6. **glassport correctly surfaces fabricated tool calls** (`unknown_tool_xyz`), even when the server itself does not respond promptly.

## Recommendations

- Investigate why `mcp-server-fetch` cannot complete outbound HTTP requests (network policy, DNS resolution, or a server-side async client bug).
- ~~Update glassport `summarize` to distinguish JSON-RPC protocol errors from valid `tools/call` responses that carry `isError=true`.~~ **Done.**
- ~~Fix glassport egress-host extraction so each call is parsed independently~~ — **no fix needed**; extraction is already per-call and stateless. When auditing future logs, correlate findings by frame `seq` carefully: `seq` numbers *all* frames (requests, responses, notifications), so a call and its result have different `seq` values.
- Consider whether glassport should warn when a wrapped server does not respond to a tool call within the session timeout (possible DoS/hang indicator).
