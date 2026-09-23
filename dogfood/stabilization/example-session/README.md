# Example Session Bundle

This directory contains a minimal synthetic MCP session suitable for demonstrating glassport's functionality without external dependencies or real credentials.

## Contents

- **example.jsonl** — A 7-frame synthetic session log in glassport's JSONL format showing:
  - MCP initialize handshake
  - tools/list declaration (one tool: "search")
  - A successful tools/call and result
  - notifications/initialized from server
  
  No external hosts, no real credentials, no user data beyond synthetic values.

- **example.summary.txt** — Output of `glassport summarize example.jsonl`
- **example.summary.json** — Output of `glassport summarize --json example.jsonl`
- **example.detect.txt** — Output of `glassport detect example.jsonl` (no findings expected)
- **example.detect.sarif** — SARIF 2.1.0 output from `glassport detect --sarif example.jsonl`
- **example.html** — Static HTML report rendered from the session

## How It Was Made

This bundle was created by a brand-new user following the README.md quickstart instructions:

1. Create a fresh Python 3.10+ venv
2. `pip install glassport` from PyPI (version 0.6.10)
3. Create a minimal 7-frame synthetic session log (see example.jsonl)
4. Run each glassport command: `summarize`, `detect`, `report`, etc.

The session log was hand-crafted to be:
- Minimal and readable (7 lines)
- Schema-compliant (schema_version 0.1)
- Realistic but not tied to any real server or domain
- Safe to publish (no credentials, no real hosts, no usernames)

## Reproduction

To recreate this bundle:

```bash
pip install glassport
glassport summarize example.jsonl
glassport detect example.jsonl
glassport report example.jsonl -o example.html
glassport summarize --json example.jsonl > example.summary.json
glassport detect --sarif example.jsonl > example.detect.sarif
```

All commands exit 0 on this clean session.

## Notes

- Frame count: 7
- Declared tools: ['search']
- Called tools: ['search']
- Fabricated calls: none
- Context violations: none
- HTML report opens in a browser; uses no external resources, no JavaScript, no network calls
