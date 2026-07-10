# Dogfood Spec — HTTP-Relay Red-Team Grill (adapters/mcp_http.py framing resistance)

**Status:** grill implemented and running all-green — R1–R3 + RF (response-framing) + round-3 surfaces PASS, exit 0. A hard CI + release gate (`ci.yml` `redteam-grills`, `release.yml`). 607 tests.
**Author handoff:** Kimi.
**Motivation:** the same through-line as the renderer grills — *glassport sits in the middle of a byte stream it does not trust*. For `advise`/`report`/`sarif` the untrusted bytes are rendered into a downstream-parsed surface. Here they are **relayed** between an MCP client and a remote server over Streamable-HTTP, and glassport is a man-in-the-middle proxy. Two properties are in tension and both must hold:

- **The relay is sacred.** Every byte the upstream sends must reach the client. glassport observes; it must never corrupt, drop, or stall a live session. A logging or framing decision that eats a byte is a production outage glassport caused.
- **glassport must not be desyncable or DoS-able.** A hostile upstream (or client) must not be able to make the proxy buffer unbounded memory, pin a worker thread, or forward framing that desyncs the client from the bytes actually sent — the classic request/response-smuggling shape, one HTTP hop removed.

The renderer grills proved the method: build the strongest adversary, point it at the **real** code path (`run_http_tap`, not a hand-built handler), treat every survival as proof and every breakage as a named source fix. This spec hands Kimi that discipline for the relay.

---

## Current state — the floor Kimi must beat

Three rounds have run against `adapters/mcp_http.py`. This is the floor, not the ceiling. Grill: `dogfood/eval_http_relay_redteam.py`. Regression locks: `tests/test_http_relay_hardening.py`.

### Round 1–2 — bounded copy, request smuggling, slowloris (`27a63f7`, 0.6.5)

- **R1 — unbounded-copy DoS.** The relay streams request/response bodies in bounded `_RELAY_CHUNK` (64 KB) pieces and logs at most `_MAX_LOGGED_BODY` (1 MB) per frame. A 4 MB hostile response reaches the client in full but cannot balloon proxy memory or the session log.
- **R2 — request smuggling.** `_read_client_body` rejects ambiguous **request** framing: any `Transfer-Encoding`, or duplicate/conflicting `Content-Length`, gets a `400` and the connection closed (so pipelined bytes are never reparsed).
- **R3 — slowloris.** `_ProxyHandler.timeout = 30` drops a stalled client so it cannot pin a `ThreadingHTTPServer` thread.

### Round 2–3 — response framing (`b38812c` 0.6.5; round-3 `hardening/http-relay-round3`)

The **response** path was the least-grilled surface. The forward loop re-emits upstream headers (minus `_HOP`) and must frame the body so the client reads exactly what the relay sent.

- **RF · duplicate `Content-Length` header lines** — two `Content-Length` lines → drop CL, `Connection: close`, close-delimit. (round 2)
- **RF · comma-folded / non-numeric `Content-Length`** — a single `Content-Length: 5, 50` folds the same ambiguity onto one line; the line-count guard missed it and forwarded it verbatim → client hang. Guard now forwards CL **only** when a single, purely-numeric value with no Transfer-Encoding (`clen.strip().isdigit()`); else drop + close-delimit. (round 2, this session)
- **RF · lying-short `Content-Length`** — upstream declares `Content-Length: 100`, sends 5 bytes, closes. The proxy can't verify the length before sending headers without buffering the whole body (that reintroduces the R1 DoS). Fix: after the stream ends, if bytes forwarded ≠ declared, force `close_connection = True` so the client gets a prompt EOF (`IncompleteRead`) instead of hanging on a kept-alive socket. (round 3)
- **RF · bare-LF header smuggling** — a bare `\n` inside a header value trying to smuggle a second `Content-Length`. `http.client` normalizes header framing on read, so the proxy sees two CLs and the dedup guard drops CL + close-delimits. **Proven safe** — a green lock, not a fix.
- **RF · chunked upstream** — a `Transfer-Encoding: chunked` upstream response reaches the client as clean de-chunked bytes with no TE header and no leaked `5\r\n` chunk markers (`http.client` de-chunks on read; the proxy strips TE as a `_HOP` header). **Proven safe** — a green lock.

Load-bearing invariant across every fix: **the relay stays sacred.** Ambiguous or lying framing never drops a byte — it drops the *Content-Length promise* and close-delimits instead. Every real byte still reaches the client.

---

## Why an in-process harness, not a live network

The bugs live in the chain, not a single object:

```
hostile client/upstream bytes → _ProxyHandler._relay → http.client (upstream) → _stream_sse / bounded copy → client socket
```

The grill drives the **real** `run_http_tap` against a raw-socket upstream or client. A raw socket is mandatory for the interesting cases: a `BaseHTTPRequestHandler` cannot emit a comma-folded header, a bare LF, or a lying Content-Length — the exact framings an attacker uses. `_serve_raw(raw_bytes)` in the grill serves one hostile raw response and half-closes cleanly (FIN, then drain) so the proxy reads a graceful EOF rather than racing a RST.

Each case returns `(ok, detail)`; `run()` prints `[PASS]/[FAIL]`, writes `dogfood/findings/http-relay-redteam.md`, and exits non-zero on any FAIL.

---

## Kimi's charge — the open surfaces

The framing surfaces above are locked. The proxy still has two under-grilled regions and a wide fuzz space. Make the table quaint.

### Surface #4 — SSE stream abuse (`_stream_sse`, `mcp_http.py:84`)

The SSE path forwards bytes to the client as they arrive and *separately* cuts complete events to log each `data:` payload. Forwarding must never wait on framing. Hunt:

- **Oversized event, no terminator.** `_MAX_SSE_BUF` (256 KB) is meant to bound per-event buffering. Verify a hostile server streaming megabytes with no `\n\n` cannot grow proxy memory *and* that the drop-note (`sse_frame_dropped_oversize`) fires once per overflow, not per chunk.
- **Terminator smuggling.** Events split across `\r\r`, `\n\n`, `\r\n\r\n`, and a `data:` payload that itself contains a bare terminator or a mid-stream BOM. Does the logged frame match what the client received?
- **Content-Type flip.** A response whose `Content-Type` flips the `streaming` branch (`"text/event-stream" in ctype` is a substring test — try `application/json; x=text/event-stream`). Does a non-SSE body get mis-framed as SSE, or vice-versa?
- **SSE + a Content-Length header** (the loop drops CL when streaming — verify it can't leak).

### Surface #5 — connection / hop-by-hop abuse

- **`Connection: keep-alive` vs. `close_connection`.** An upstream `Connection` header is a `_HOP` (stripped), but probe whether a hostile client `Connection` header, or the proxy's own keep-alive under `HTTP/1.1`, can leave a socket in a state that desyncs the next pipelined request after a close-delimited body.
- **Header pass-through as an exfil/deception surface.** `Set-Cookie` and arbitrary upstream headers are forwarded verbatim. Not a framing bug, but is there a header the proxy should refuse to relay?
- **Status-line / trailer abuse.** Chunked responses with trailers; unusual status codes; `100 Continue` handling on the request path.

### Method

For each surface: build the raw-socket adversary, drive `run_http_tap`, assert the relay stays sacred **and** the proxy can't be desynced/stalled. Every red row → a named source fix in `adapters/mcp_http.py` + a regression lock in `tests/test_http_relay_hardening.py`, kept as **separate commits from the grill** (repo convention). Keep source and grill in sync — both are CI merge gates.

A design decision that is *not* a bug must be locked as a green row with a comment (e.g. chunked-de-chunk, bare-LF-normalized), so a later round doesn't re-litigate it.
