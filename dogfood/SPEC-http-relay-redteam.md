# Dogfood Spec — HTTP-Relay Red-Team Grill (adapters/mcp_http.py framing resistance)

**Status:** grill implemented and running all-green — R1–R3 + RF (response-framing) + round-4 SSE + round-5 connection/header surfaces PASS, exit 0. A hard CI + release gate (`ci.yml` `redteam-grills`, `release.yml`).
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

### Round-4 — SSE framing (`0.6.7`, this session)

A self-driven pre-probe of surfaces #4/#5 before handing them to Kimi, so the loop starts from a harder floor. Two real bugs found + fixed, four surfaces proven safe.

- **SSE keep-alive hang (fixed).** An SSE response carries no Content-Length and the proxy strips the upstream's `Transfer-Encoding` (a `_HOP` header), so there was no framing telling the client the response ended — when the upstream closed the stream the client blocked to its own timeout on a kept-alive socket. Fix: the SSE branch now sends `Connection: close` + sets `close_connection`, so the upstream's close reaches the client as a prompt EOF.
- **Content-Type substring flip (fixed).** `streaming` was `"text/event-stream" in ctype` — a substring test, so `application/json; note=text/event-stream` flipped a normal JSON body onto the SSE path, dropping its Content-Length and reframing it (then hanging on the point above). Fix: match the **media type** — `ctype.split(";", 1)[0].strip().lower() == "text/event-stream"`.
- **Oversized SSE event (safe, green lock).** A 2 MB `data:` with no terminator reaches the client in full (relay sacred) while the session log stays ~277 bytes — `_MAX_SSE_BUF` (256 KB) bounds buffering and one drop-note replaces the runaway.
- **Pipeline after ambiguous body (safe, green lock).** After a close-delimited response the proxy closes, so a second pipelined request on the same socket is not reparsed against leftover bytes — one response comes back, the second request dies with the connection.

### Round-5 — SSE residue + connection/header path (this session)

Kimi's charge: probe the narrower residue in `_stream_sse` and the connection/hop-by-hop/header path.

- **Terminated oversized SSE event (fixed).** A huge event *with* a terminator was buffered and partially logged (up to the buffer cap), so the session log grew with the attacker and the logged frame did not match the client's event. Fix: cap logged events at `_MAX_SSE_BUF`; an oversized terminated event is replaced by one `sse_frame_dropped_oversize` note, just like an unterminated flood. Metadata lines do not exempt the event.
- **1xx responses other than 100 Continue (fixed).** `http.client` skips only 100; a 102 Processing (or any other 1xx) was forwarded to the client as the final answer, hiding the real response. Fix: a custom `HTTPResponse` swallows every 1xx status line + headers before the final response is processed.
- **Duplicate Content-Type flips JSON to SSE (fixed).** An upstream that emits two `Content-Type` headers could make `resp.getheader("Content-Type")` return `text/event-stream`, forcing the SSE path and dropping `Content-Length`. Fix: streaming requires exactly one `Content-Type` header line and a media-type match; ambiguous CT defaults to non-streaming.
- **204/304 with a hostile Content-Length (fixed).** A bodiless status that carried a `Content-Length` would forward the lying length. Fix: treat 204/304 as bodiless — drop `Content-Length` and close-delimit.
- **Duplicate identical Content-Length (hardened).** The proxy used to accept two identical `Content-Length` values; RFC 7230 forbids any duplicate. Fix: reject all duplicate `Content-Length` header lines.
- **Chunked trailers (safe, green lock).** Trailer headers on a chunked response are consumed during de-chunking and never forwarded; because `Transfer-Encoding` is stripped, the client has no trailer channel.
- **Client header CRLF injection (safe, green lock).** An embedded CRLF in a header value is parsed by `http.server` as a separate header. Because framing/hop headers are stripped before the upstream and the proxy's request-target is fixed to `remote.path`, this cannot desync client vs. upstream framing; it merely produces two pipelined requests, both forwarded to the configured path.
- **Expect: 100-continue (safe, green lock).** A client `Expect: 100-continue` request is forwarded with headers and body; the upstream's final response reaches the client.

### Method

For each surface: build the raw-socket adversary, drive `run_http_tap`, assert the relay stays sacred **and** the proxy can't be desynced/stalled. Every red row → a named source fix in `adapters/mcp_http.py` + a regression lock in `tests/test_http_relay_hardening.py`, kept as **separate commits from the grill** (repo convention). Keep source and grill in sync — both are CI merge gates.

A design decision that is *not* a bug must be locked as a green row with a comment (e.g. chunked-de-chunk, bare-LF-normalized), so a later round doesn't re-litigate it.
