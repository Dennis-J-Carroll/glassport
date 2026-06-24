# Dogfood Finding — exa-mcp-server

**Date:** 2026-06-24  
**Glassport worktree:** `kimi/eval`  
**Server:** `exa-mcp-server@3.2.1` (via Smithery CLI / npx)  
**Driver:** `dogfood/eval_exa.py`  
**Session log:** `dogfood/logs/exa/20260624T003116Z_npx_410437.jsonl`

## Setup

Launched the exa MCP server behind glassport tap:

```bash
python glassport_tap.py --log-dir dogfood/logs/exa -- \
  npx -y exa-mcp-server
```

Driver performed MCP handshake (`initialize` → `notifications/initialized` → `tools/list`) then called tools. The evaluation was run **without** `EXA_API_KEY`; the script still probes the declared surface and error paths.

## Tool surface observed

2 tools declared:

- `web_search_exa` — semantic web search. Requires `query` (string); optional `numResults` (number, 1–100). `additionalProperties: false`.
- `web_fetch_exa` — fetch one or more URLs as markdown. Requires `urls` (array of strings); optional `maxCharacters` (number, ≥1). `additionalProperties: false`.

Both tools are annotated `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`, `idempotentHint=true`, and `taskSupport=forbidden`.

**Note:** The server exposes `web_search_exa` / `web_fetch_exa`, not `exa_search`. Prompts or clients that assume the older `exa_search` name will receive `MCP error -32602: Tool exa_search not found`.

## Benign behavior

| Call | Result |
|------|--------|
| `web_search_exa` `{"query":"python asyncio","numResults":1}` | `isError=true`, HTTP 401: "API key must be provided as an argument or as an environment variable (EXA_API_KEY)" |
| `web_fetch_exa` `{"urls":["https://example.com"],"maxCharacters":500}` | `isError=true`, same 401 API-key error |

The calls were well-formed and reached the exa backend; they failed only because no `EXA_API_KEY` was configured. Server debug logs confirm each search was initiated before the auth failure.

## Adversarial behavior

| Test | Payload | Result |
|------|---------|--------|
| Unknown tool | `nonexistent_tool_xyz` | Blocked: `isError=true`, `MCP error -32602: Tool nonexistent_tool_xyz not found` |
| Missing required arg | `web_search_exa {}` | Blocked: `isError=true`, Zod validation error — `query: Required` |
| Wrong type | `web_search_exa {"query":12345}` | Blocked: `isError=true`, `Expected string, received number` |
| Extra property | `web_search_exa {"bad_param":"ignored"}` | Blocked: `isError=true`, `query: Required` (additionalProperties false) |
| Empty query | `web_search_exa {"query":""}` | Reached backend; returned 401 API-key error (empty string is schema-valid) |
| Oversized query | `web_search_exa {"query":"a"*5000}` | Reached backend; returned 401 API-key error (no maxLength in schema) |
| `file://` URL | `web_fetch_exa {"urls":["file:///etc/passwd"]}` | Reached backend; returned 401 API-key error before URL policy is applied |
| Localhost URL | `web_fetch_exa {"urls":["http://localhost:22"]}` | Reached backend; returned 401 API-key error before URL policy is applied |
| Empty URLs array | `web_fetch_exa {"urls":[]}` | Reached backend; returned 401 API-key error |

The server validates arguments against the declared JSON Schema before invoking the tool. Because the API key is checked immediately after argument validation, adversarial URL targets (file, localhost) could not be exercised end-to-end without a key.

## glassport observations

- **Tap:** logged 25 frames cleanly; no dropped bytes or parser errors.
- **Summarize:** correctly extracted the 2 declared tools and 10 tool calls. Listed one fabricated call for `nonexistent_tool_xyz` and reported protocol errors for every `isError=true` response.
- **Detect:** 5 findings:
  - `[HIGH] seq=6 fabricated_tool_call: tools/call 'nonexistent_tool_xyz' is outside the declared surface` — expected for the adversarial unknown-tool probe.
  - `[WARN] seq=5 unexpected_egress_host: tools/call 'web_fetch_exa' reaches example.com (undeclared)` — triggered by the benign `https://example.com` fetch probe.
  - `[WARN] seq=9 schema_violation: 'web_search_exa': missing required argument 'query'`
  - `[WARN] seq=9 schema_violation: 'web_search_exa': unexpected argument 'bad_param' (additionalProperties: false)`
  - `[WARN] seq=10 schema_violation: 'web_search_exa': argument 'query' is int, schema expects string`

## Server-side notes

- **API key required.** Without `EXA_API_KEY`, every real tool call returns a 401 with a clear message. No secrets were leaked in error text.
- **Deprecation warnings.** `npx` prints `uuid@9.0.1` deprecation and Node prints a `punycode` deprecation warning; these are cosmetic.
- **Out-of-order responses.** The server returns tool-call responses asynchronously (IDs 3–12 arrived in non-sequential order). This is valid JSON-RPC over independent requests, but consumers should correlate by `id`.
- **No crash or hang.** The server exited cleanly (exit 0) after stdin EOF.

## Findings

1. **Schema validation is strict and effective.** Missing required fields, wrong types, and extra properties are rejected before any backend call.
2. **API key is a hard blocker.** No benign or adversarial call reached exa's search/fetch services without authentication.
3. **glassport detects fabricated calls and schema violations correctly.** The `nonexistent_tool_xyz` probe is accurately flagged as outside the declared surface.
4. **`unexpected_egress_host` fires on benign example.com traffic.** This is a true observation (the fetch tool declared no egress allow-list), but it is expected behavior for an open-web search server and may produce noise in production.

## Recommendations

- Re-run this evaluation with a valid `EXA_API_KEY` to verify backend-side URL validation (file://, localhost, SSRF payloads) and query-length limits.
- Update any client/prompt templates that reference `exa_search`; the live tool name is `web_search_exa`.
- Consider whether glassport should distinguish intentional adversarial probes from actual fabricated calls in `detect` output, or allow eval scripts to annotate probe calls so they do not inflate the finding count.
