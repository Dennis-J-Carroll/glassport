# Hardening plan — Kimi red-team of the HTTP relay path (`adapters/mcp_http.py::_relay`)

**Why now:** the previous round (PR #52) closed the SSE *streaming* path — buffer
cap, mid-stream BOM parity, disk-DoS. It deliberately left the rest of `_relay`
unprobed. `_relay` is the code that actually sits in the middle of live HTTP MCP
traffic: it reads a client request body, opens an upstream connection, and copies
the response back. Both endpoints are attacker-reachable (the MCP **server** is
the hostile party in glassport's threat model; a compromised or malicious
**client** is also in scope for a tap that markets "safe in live agent traffic").
The non-streaming response branch and the request-framing logic never had an
adversarial pass.

**Target (exact):** `src/glassport/adapters/mcp_http.py` on `main` (post-#52).

**Companion prompt:** `docs/redteam/2026-07-09-kimi-prompt-relay.md` (paste into Kimi).

---

## Three defects already identified (fix without waiting for Kimi)

These are the F1/F2-equivalents of this round — concrete, each ~a fix + a
regression test. They ship in the same PR that stands up the grill.

### R1 — unbounded response read → memory + disk DoS · non-SSE branch

```python
else:
    data = resp.read()                     # <-- whole hostile body into memory
    self.send_header("Content-Length", str(len(data)))
    self.end_headers()
    if data:
        log.record("s2c", data)            # <-- and the whole body onto disk
```

The SSE branch is now bounded (#52). This branch is not. A hostile/compromised
upstream answers a `tools/call` with a 2 GB `application/json` body: `resp.read()`
buffers all of it, and `log.record` writes all of it to the session log. Same
class as the SSE disk-DoS, on the path that handles *every ordinary JSON reply*.

**Fix:** stream the response to the client in bounded chunks (the relay stays
sacred — every byte still reaches the client), and cap what is logged: log up to
`_MAX_LOGGED_BODY`, then one `s2c_body_truncated_oversize` note. Mirror the SSE
fix's philosophy exactly. The request-body read (`self.rfile.read(length)`) gets
the same treatment: cap what is buffered/logged, stream the remainder upstream.

**Regression test:** a mock upstream returns a large non-SSE body with no
terminator; assert (a) the client receives all bytes, (b) the log holds a bounded
note, not the whole body, (c) memory does not scale with body size.

### R2 — request smuggling via ambiguous framing · request read

```python
length = int(self.headers.get("Content-Length", 0) or 0)
body = self.rfile.read(length) if length else b""
```

`length` comes from the *first* `Content-Length` only. Two smuggling vectors:

1. **`Transfer-Encoding: chunked` with no `Content-Length`** → `length == 0` →
   glassport reads a **zero-byte** body and forwards it upstream, leaving the
   real chunked body sitting unread in the client socket. On a keep-alive
   connection those bytes are then parsed as the *next* request → classic
   TE.CL desync / request smuggling.
2. **Duplicate `Content-Length`** (two different values) → `.get()` picks one,
   the upstream may pick the other → desync.

`_HOP` strips `transfer-encoding`/`content-length` on the *forwarded* set (good,
the upstream reframes), but glassport still has to *read the client body* by some
length, and it reads it wrong.

**Fix:** refuse ambiguous framing rather than guess. Reject (400, logged) any
request that carries `Transfer-Encoding` or a duplicate/invalid `Content-Length`.
MCP Streamable-HTTP posts a single `Content-Length`-framed JSON body; chunked
request bodies are out of transport scope, so refusing them closes the desync
without touching a conformant session.

**Regression test:** a raw request with `Transfer-Encoding: chunked` and no
`Content-Length`, then a pipelined second request on the same socket; assert the
proxy returns 400 for the first and does **not** forward the smuggled second
request as a body — and a request with two conflicting `Content-Length` headers
is rejected.

### R3 — slowloris / thread starvation · no handler timeout

`ThreadingHTTPServer` spawns one thread per connection, and `BaseHTTPRequestHandler`
sets **no socket timeout** by default. A client that sends
`Content-Length: 1000000` then dribbles bytes (or none) makes
`self.rfile.read(length)` block that thread indefinitely. A handful of such
clients exhausts the thread/memory budget while the tap looks alive.

**Fix:** set `timeout` on the handler (e.g. 30s, matching the upstream
`_connect` timeout) so a stalled client is dropped and its thread reclaimed; pair
with the R1 body cap so a huge declared `Content-Length` can't request a giant
allocation up front. Confirm one aborted/slow request never prevents a later
request from being served.

**Regression test:** assert `_ProxyHandler.timeout` is set; functionally, drive a
request that aborts mid-body and then a normal request on a fresh connection —
the second must succeed (server survived, thread reclaimed).

---

## Kimi target surfaces (the hunt — beyond R1–R3)

1. **Response framing abuse** — a `Content-Length` that disagrees with the body
   length; trailing bytes after the declared length; a `Content-Length` on a
   `text/event-stream` response (we strip it — confirm no desync); duplicate
   response `Content-Length`/`Transfer-Encoding` from the upstream.
2. **Method / path smuggling** — unusual methods, absolute-URI request targets,
   `remote.path` empty vs `/`, path with embedded control bytes; does the
   forwarded request-target ever carry attacker bytes unescaped?
3. **Header set abuse (forwarded)** — a header the client sets that we forward
   verbatim and that changes upstream framing or auth (`Expect: 100-continue`,
   `Range`, `Authorization` reflection), oversized header blocks, many headers.
4. **Connection lifecycle** — keep-alive reuse across requests on the proxy
   (`protocol_version = "HTTP/1.1"`); a response that half-closes; `DELETE`/`GET`
   with a body; a remote that returns 1xx/`Upgrade`.
5. **Log-vs-client parity** (the round-1 theme, on the non-SSE path) — can the
   bytes logged as one `c2s`/`s2c` frame ever differ from the bytes actually
   forwarded?
6. **R3 variants** — slow upstream *response* (distinct from the live SSE case),
   a remote that accepts the connection then never sends status.

Each confirmed finding → a fix → a unit regression test, and the load-bearing
ones promoted into `dogfood/eval_http_relay_redteam.py` as a CI gate (mirroring
`eval_http_tap_redteam.py`).

---

## The loop
1. **Land R1 + R2 + R3** (identified above), each with a regression test, and
   stand up `dogfood/eval_http_relay_redteam.py` wired into `ci.yml` + `release.yml`.
2. **Triage Kimi's findings** — reproduce, rank by real impact
   (desync/leak/DoS > cosmetic), fix each with a test; promote load-bearing ones
   into the grill.
3. Patch-bump if anything user-facing changed.

## Exit criteria
- [ ] R1 (bounded response/request copy) + R2 (reject ambiguous framing) + R3
      (handler timeout) fixed and regression-locked.
- [ ] Every confirmed Kimi finding fixed with a test; load-bearing ones gated by
      `eval_http_relay_redteam.py` in CI.
- [ ] Full suite + all grills green.
- [ ] No unbounded read on either direction; no request the tap forwards with a
      framing it read differently from the upstream; no single request can pin a
      thread forever.
