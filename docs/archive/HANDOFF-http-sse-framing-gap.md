# Handoff: HTTP tap loses tools/list + tool-result correlation on named-event SSE

**Branch:** `main` (post-0.6.9, commit `e6e2553`)
**Status:** confirmed real, reproduced independently on two different real MCP servers
over the Streamable-HTTP transport. Not yet fixed. No production source touched.

## What's broken

`glassport wrap --transport http --url <remote>` silently loses the ability to
correlate server→client (`s2c`) responses whenever the upstream frames its SSE
stream with a named `event:` field — e.g. `event: message\r\ndata: {...}`. This
is not an obscure edge case: it's what the official Python MCP SDK's
`FastMCP(...).run(transport="streamable-http")` sends by default, and almost
certainly what most Python/TS Streamable-HTTP MCP servers built on the
reference SDKs emit.

Concretely, over two independently-run real servers on 0.6.9:

- `glassport summarize` reports `declared_tools: []` / `no tools/list seen`
  even when `tools/list` genuinely succeeded (visible in the MCP client's own
  request/response log).
- `glassport detect` flags **every single tool call** as
  `[HIGH] fabricated_tool_call: outside the declared surface` — 100% false
  positive rate on this transport, because there is no declared surface to
  check against.
- `unexpected_egress_host` and similar detectors that don't depend on
  `declared_tools` still fire correctly (confirmed: real fetch to an
  undeclared host was flagged `[WARN]`), so the gap is scoped to whatever
  reads `tools/list` responses and `tools/call` results, not the whole
  detector pass.

## Why this matters for security, not just correctness

`pii_in_result_*` (the credential/PII detector that watches tool *results*
for leaked secrets) depends on the same `s2c` response correlation. If the
adapter can't parse a `tools/call` result on this framing style, a secret
leaked back from a compromised/malicious server over Streamable-HTTP using
this SSE style would not be caught by `pii_in_result_*` — the exact detector
this whole project exists to run. This needs verifying directly, not assumed.

## Root cause, as far as it's been traced

**`src/glassport/adapters/mcp_http.py::_log_sse_event`** (line 196):

```python
def _log_sse_event(event: bytes, log: SessionLog, *, partial: bool = False) -> None:
    """Log one SSE event. data: lines are joined with \\n; if the event carries
    event:/id:/retry: fields (or is an over-limit partial flush) the full event
    text is logged as raw so transport metadata is not silently discarded."""
    ...
    if has_meta:
        # Preserve metadata by logging the full reconstructed event text.
        log.record("s2c", event)
    else:
        ...
```

When the SSE event carries an `event:`/`id:`/`retry:` field (`has_meta =
True`), the **entire raw event text** — `event: message\r\ndata:
{...}` — gets passed to `log.record()`, not just the JSON payload. This is
deliberate (the docstring says so: preserve transport metadata, don't
silently discard it).

**`src/glassport/tap.py::SessionLog.record`** then tries `json.loads(text)`
on that whole line. `"event: message\r\ndata: {...}"` is not valid JSON, so
`frame = None`, `raw = text` — the entry gets logged with `"frame": null`.

**`src/glassport/adapters/mcp_session.py::feed()`** (line 120-138):

```python
frame = entry.get("frame")
if not isinstance(frame, dict):
    # raw/unparseable wire line — preserve it as a MESSAGE so no
    # data is lost on import (Open design Q #2: don't drop on ingest)
    ...
    kind=EventKind.MESSAGE,
    ...
    metadata={"seq": entry.get("seq"), "unparsed": True, "dir": entry.get("dir")},
```

Any entry with `frame: null` becomes a generic `MESSAGE` event, never a
`TOOL_RESULT` or a parsed `tools/list` response. So every `s2c` frame on this
SSE style — every tool result, every `tools/list` response, everything —
degrades to "unparsed," permanently invisible to `declared_tools()`,
`called_tools()` correlation, and (needs confirming) `pii_in_result_*`.

## Reproduction (verified twice, independently, on 0.6.9)

Two minimal real Python MCP servers, in `dogfood/repro-http-sse-gap/` in this
checkout — not fabricated fixtures, genuinely functional
`mcp.server.fastmcp.FastMCP` servers (`pip install mcp` if not already
present):

1. `clean_notes_server.py` — `add_note`/`get_note`/`list_notes`, port 8801.
2. `noisy_fetch_server.py` — `fetch_url`/`divide`/`echo_with_extra`, port 8802.

For either:
```bash
python3 <server>.py                                          # real server
glassport wrap --transport http --url http://127.0.0.1:<PORT>/mcp   # tap
# connect any real MCP client (MCP Inspector, Streamable HTTP, "Via Proxy")
#   to the printed glassport proxy URL, call a couple of tools
glassport summarize --json ~/.glassport/sessions/<newest>.jsonl
glassport detect ~/.glassport/sessions/<newest>.jsonl
```

Both runs: `declared_tools: []`, every call in `fabricated_calls`, matching
`detect` output `[HIGH] fabricated_tool_call` for each one, despite a real,
successful `tools/list` visible in the client's own request log.

## What this session needs from you

This is scoped to **one specific, already-diagnosed gap** — not a general
Unicode/red-team hunt, not a review of anything else in the HTTP tap or
adapter.

1. **Confirm the root cause independently.** Don't take the trace above on
   faith — reproduce it yourself against a minimal SSE server you write (or
   the two attached), read the actual session log bytes, confirm `frame:
   null` / `has_meta: True` is really what's happening, not something else
   that looks similar.
2. **Determine the full blast radius.** Which specific detectors/fields are
   blind on this framing style, and which aren't? Confirm or refute the
   `pii_in_result_*` concern above with a real leaked-secret-in-tool-result
   repro over this exact SSE framing — that's the one that actually matters
   for the project's threat model, don't skip it.
3. **Design the smallest correct fix.** The likely shape: when logging an
   `s2c` SSE event that carries `event:`/`id:`/`retry:` metadata, still
   extract and log the JSON `data:` payload as the `frame` (structured,
   parseable), while separately preserving the metadata fields (`event`,
   `id`, `retry`) in the log entry rather than smashing everything into one
   unparseable raw string. Don't assume this is right — it's a hypothesis,
   not a spec. If a better shape exists, use it.
4. **Prove the fix is real**, the same way every fix in this project has
   been proven: an independent oracle (not sharing code with the fix), a
   false-positive/regression suite (normal SSE traffic without `event:`
   fields must still work exactly as before — that path is currently fine,
   don't break it), and teeth-proofing (revert the fix, confirm the repro
   comes back RED; restore it, confirm GREEN).
5. **No production changes without an accompanying fix + tests.** If you
   determine the safe fix is larger than expected, say so explicitly rather
   than silently scoping it down or silently expanding into unrelated HTTP
   tap surfaces.

## Stop condition

Report back: root cause confirmed or refuted, blast radius (exact list of
what's blind vs. what still works, with the `pii_in_result_*` question
answered concretely), and either a working fix + green regression suite, or
a clear statement of why the safe fix needs to be scoped/deferred. Do not
expand into a broader HTTP tap audit or a new red-team pass on unrelated
surfaces — this is one bug, diagnosed, needing a fix and proof.
