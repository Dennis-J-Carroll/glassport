# Dogfood Finding — @modelcontextprotocol/server-filesystem

**Date:** 2026-06-23  
**Glassport worktree:** `kimi/eval`  
**Server:** `@modelcontextprotocol/server-filesystem@2026.1.14`  
**Driver:** `dogfood/eval_filesystem.py`  
**Session log:** `dogfood/logs/filesystem/20260624T002921Z_npx_409774.jsonl`

## Setup

Launched the filesystem server behind glassport tap with a single allowed directory:

```bash
python glassport_tap.py --log-dir dogfood/logs/filesystem -- \
  npx -y @modelcontextprotocol/server-filesystem /tmp/glassport-dogfood-allowed-fbuax3gl
```

Driver performed MCP handshake (`initialize` → `notifications/initialized` → `tools/list`) then called tools.

## Tool surface observed

14 tools declared:

- `create_directory`, `directory_tree`, `edit_file`, `get_file_info`
- `list_allowed_directories`, `list_directory`, `list_directory_with_sizes`
- `move_file`, `read_file`, `read_media_file`, `read_multiple_files`
- `read_text_file`, `search_files`, `write_file`

All have proper `inputSchema` and `annotations` (readOnlyHint, destructiveHint, etc.).

## Benign behavior

| Call | Result |
|------|--------|
| `list_directory` on allowed dir | OK |
| `read_file` inside allowed dir | OK |
| `write_file` inside allowed dir | OK |

## Adversarial behavior

| Test | Payload | Result |
|------|---------|--------|
| Read traversal | `allowed/../..\..\secret.txt` | Blocked: `isError=true`, "Access denied - path outside allowed directories" |
| Write traversal | `allowed\..\..\..\pwned.txt` | Blocked: `isError=true` |
| Multi-file traversal | `[inside.txt, outside/secret.txt]` | Partial: inside read succeeded, outside denied with explanation |
| Null-byte path | `inside.txt\x00.txt` | Blocked: path normalization rejected |
| Large write | 100 KB content | OK, wrote successfully |

## glassport observations

- **Tap:** logged all 21 frames cleanly; no dropped bytes.
- **Summarize:** correctly extracted declared/called tools; flagged no fabricated calls.
- **Detect:** no findings (expected — no PII/secrets exfiltrated).
- **Protocol note:** the server requires `params.clientInfo` in `initialize`; a minimal handshake without it returns a Zod validation error. This is a server strictness issue, not a glassport bug, but it is worth noting for anyone wiring glassport to a real client.

## Findings

1. **Path containment is server-enforced and effective.** No traversal succeeded. The server normalizes paths and checks against the allowed roots before any I/O.
2. **No glassport detector false positives** on normal filesystem traffic, including 100 KB writes.
3. **No exploitable weaknesses found** in this configuration.

## Recommendations

- Continue using the filesystem server with confidence; its path validation is solid.
- Consider whether glassport should warn when a wrapped server returns `isError=true` for access-denied calls at high volume (possible reconnaissance indicator). Not a blocker.
