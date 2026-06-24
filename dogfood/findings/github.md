# Dogfood Finding — @modelcontextprotocol/server-github

**Date:** 2026-06-24  
**Glassport worktree:** `kimi/eval`  
**Server:** `github-mcp-server` v0.6.2 (`@modelcontextprotocol/server-github@2025.4.8`)  
**Driver:** `dogfood/eval_github.py`  
**Session log:** `dogfood/logs/github/20260624T003052Z_npx_410268.jsonl`

## Setup

Launched the GitHub MCP server behind the glassport tap without a `GITHUB_PERSONAL_ACCESS_TOKEN`:

```bash
python glassport_tap.py --log-dir dogfood/logs/github -- \
  npx -y @modelcontextprotocol/server-github
```

Environment:

```bash
GITHUB_PERSONAL_ACCESS_TOKEN=<missing>
```

The driver performed the MCP handshake (`initialize` → `notifications/initialized` → `tools/list`) and then exercised `search_repositories` with benign and adversarial payloads.

## Tool surface observed

25 tools declared (alphabetical):

- `add_issue_comment`
- `create_branch`
- `create_issue`
- `create_or_update_file`
- `create_pull_request`
- `create_pull_request_review`
- `create_repository`
- `fork_repository`
- `get_file_contents`
- `get_issue`
- `get_pull_request`
- `get_pull_request_comments`
- `get_pull_request_files`
- `get_pull_request_reviews`
- `get_pull_request_status`
- `list_commits`
- `list_issues`
- `list_pull_requests`
- `merge_pull_request`
- `push_files`
- `search_code`
- `search_issues`
- `search_repositories`
- `search_users`
- `update_issue`
- `update_pull_request_branch`

All tools carry JSON Schema `inputSchema` with `additionalProperties: false`. Several expose high-impact operations (repo creation, file writes, PR merge, issue creation). No write/delete tool annotations (e.g. `destructiveHint`) were present in the declared surface.

## Benign behavior

| Call | Payload | Result |
|------|---------|--------|
| `search_repositories` | `{"query":"language:python stars:>1000","perPage":1}` | **OK** — returned one repository (`public-apis/public-apis`) with full metadata JSON. |

Despite the missing token, the GitHub Search API endpoint used by this tool is public, so the call succeeded. Other tools (writes, private repo access, etc.) are expected to fail with GitHub auth errors without a token.

## Adversarial behavior

| Test | Payload | Result |
|------|---------|--------|
| Malformed query type | `{"query": 12345}` | **Blocked** — JSON-RPC error `-32603`: `Invalid input: [{"code":"invalid_type","expected":"string","received":"number","path":["query"],"message":"Expected string, received number"}]` |
| Unknown tool | `{"name":"__does_not_exist__","arguments":{"foo":"bar"}}` | **Blocked** — JSON-RPC error `-32603`: `Unknown tool: __does_not_exist__` |
| Oversized query | `{"query": "a" * 5000, "perPage": 1}` | **Blocked at GitHub API** — JSON-RPC error `-32603`: `Validation Error: Validation Failed
Details: {"message":"Validation Failed","errors":[{"message":"The search is longer than 256 characters.","resource":"Search","field":"q","code":"invalid"}],"documentation_url":"https://docs.github.com/v3/search/","status":"422"}` |

No server crash or uncaught exception was observed; the process exited cleanly with code `0`.

## glassport observations

- **Tap:** captured all 13 frames cleanly to `dogfood/logs/github/20260624T003052Z_npx_410268.jsonl`.
- **Summarize:**
  - Parsed 13 frames.
  - Declared 25 tools, called `search_repositories` three times and `__does_not_exist__` once.
  - Flagged `FABRICATED CALLS: [(7, '__does_not_exist__')]`.
  - Listed protocol errors for the malformed-type and oversized-query calls.
  - Reported a context violation: `[sev 2] seq 5 schema_violation: 'search_repositories': argument 'query' is int, schema expects string`.
- **Detect:**
  - Return code `1` (findings present).
  - `[HIGH] seq=7 fabricated_tool_call: tools/call '__does_not_exist__' is outside the declared surface`
  - `[WARN] seq=5 schema_violation: 'search_repositories': argument 'query' is int, schema expects string`

## Findings

1. **Declared surface is broad and high-impact.** The server exposes 25 tools including repository mutation, file writes, issue/PR creation, and merges. This is a large attack surface if the proxy is misconfigured to allow all tools to an untrusted client.
2. **Input validation is enforced before GitHub API calls.** Type mismatches are rejected by the server's Zod/schema layer; oversized inputs are rejected by the GitHub Search API. No injection or crash was achieved with the tested payloads.
3. **The `search_repositories` tool works unauthenticated** because GitHub's search endpoint is public. This is not a vulnerability, but it means the missing `GITHUB_PERSONAL_ACCESS_TOKEN` did not block the benign test.
4. **glassport detectors correctly identified the adversarial calls.** The fabricated-tool and schema-violation findings are true positives; the benign search produced no detector alerts.

## Recommendations

- When deploying this server behind glassport, configure an allow-list that restricts high-impact tools (`create_or_update_file`, `create_repository`, `merge_pull_request`, `push_files`, `fork_repository`, etc.) unless the client is explicitly trusted.
- Provide a `GITHUB_PERSONAL_ACCESS_TOKEN` with the minimum required scopes; without it, state-changing tools will fail at the GitHub API, but read-only public tools such as `search_repositories` still function.
- Consider whether glassport should offer a higher-severity detector for broad repository-mutation tool surfaces (many declared destructive tools) independent of individual call behavior.
