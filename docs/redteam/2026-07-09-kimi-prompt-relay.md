# Kimi red-team prompt — glassport HTTP relay path

> Paste the block below into Kimi, running in the `glassport-kimi` workspace
> synced to `main` (post-#52, so `_stream_sse` is already bounded and the
> provenance SSRF/scrub fixes are in). Single-module focus this round.

---

You are an adversarial security researcher attacking **glassport**, a
zero-dependency, stdio/HTTP man-in-the-middle observability tool for the Model
Context Protocol (MCP). Its doctrine: *the relay is sacred (never alter, delay,
drop, or kill a live session), assert only what the wire proves, the log is a
faithful record of the bytes that crossed the wire, and never let
attacker-controlled bytes reach a human- or agent-facing surface.* Your job is to
break those promises.

## Scope — one function, one module

`src/glassport/adapters/mcp_http.py`, specifically the request/response relay:
`_ProxyHandler._relay`, `_req_headers`, `_connect`, and the non-SSE response
branch. The SSE *streaming* path (`_stream_sse`) was hardened last round — you may
poke it, but spend your effort on the **request read**, the **non-streaming
response copy**, **header forwarding**, and **connection lifecycle**.

Both endpoints are attacker-reachable: the MCP **server** (upstream) is the
primary hostile party, and a malicious or compromised **client** is in scope for
a tap that markets "safe to sit in live agent traffic." Read the file fully
before attacking. Ignore the rest of the repo.

## What counts as a finding — highest value first

- **Request/response smuggling & framing desync** — a request whose body
  glassport reads with a different length than the upstream will (TE/CL
  ambiguity, duplicate `Content-Length`, chunked request with no
  `Content-Length`), leaving bytes in a socket to be reparsed as a second
  request; or a response whose forwarded framing desyncs from what glassport
  logged.
- **Log-vs-client parity** — the bytes glassport records as one `c2s`/`s2c`
  frame differing from the bytes actually forwarded (the round-1 theme, now on
  the non-SSE path).
- **DoS** — unbounded memory/disk on the request body (`self.rfile.read(length)`)
  or the non-SSE response (`resp.read()`); a slowloris client that pins a
  `ThreadingHTTPServer` thread; a slow/never-responding upstream; thread death
  that a later request can't recover from.
- **Header abuse** — a forwarded client header that changes upstream framing,
  auth, or continuation (`Transfer-Encoding`, `Expect: 100-continue`, `Range`,
  a hop-by-hop bypass, header injection, oversized header blocks).
- **Relay-breaking / info-leak** — any input that makes the proxy alter, delay,
  drop, or fabricate a live message, or that leaks internal detail
  (paths/hostnames) into the 502 body or a log frame.

Cosmetic nits are low priority.

## Seed ideas (not exhaustive — surprise me)

- `POST` with `Transfer-Encoding: chunked` and **no** `Content-Length`, followed
  by a pipelined second request on the same keep-alive socket — what does
  glassport forward, and where do the smuggled bytes go?
- Two `Content-Length` headers with different values; a negative, non-numeric, or
  absurdly large `Content-Length`.
- A hostile upstream that answers a normal `tools/call` with a multi-hundred-MB
  `application/json` body — where does it end up (RAM? the session log?).
- A client that declares a large `Content-Length` then sends bytes at 1/sec (or
  none) — how long does the worker thread stay pinned?
- An upstream that accepts the TCP connection, then never sends a status line;
  or sends `100 Continue` / `101 Upgrade` / a trailer.
- `GET`/`DELETE` carrying a body; an absolute-URI or control-byte-laden request
  target; `remote.path` empty.
- A response `Content-Length` that lies (shorter/longer than the body); trailing
  bytes after the declared length.

## Rules of engagement

- **Report, don't fix.** The maintainer applies fixes and writes the tests.
- Every finding needs a **concrete repro**: exact request/response bytes or
  headers and the observed bad outcome. A runnable snippet or a failing
  `unittest` is ideal — findings become `dogfood/eval_http_relay_redteam.py`
  grills, so shaped-as-a-test is best.
- No live network — mock the client with a raw socket and the upstream with a
  stdlib `http.server` in a thread, as `tests/test_http_tap.py` already does.
- Assume the maintainer already suspects three holes and is fixing them: (R1)
  unbounded `resp.read()` / request-body read, (R2) request smuggling via
  `Transfer-Encoding`/duplicate `Content-Length`, (R3) no handler socket timeout
  (slowloris). Confirm/extend these, but spend most effort on what they
  *haven't* named.

## Output format

A ranked list, most severe first. For each:

```
### [severity: critical|high|medium|low] <one-line title>
- Location: <file:function>
- Class: <smuggling | parity | dos | header-abuse | relay-break | info-leak>
- Repro: <exact bytes/headers + how to run it>
- Observed: <the bad outcome>
- Why it matters: <the doctrine promise it breaks>
- Suggested direction: <one line; the maintainer writes the actual fix>
```

End with a one-paragraph summary: which doctrine promise was easiest to break,
and — reported as absence, not guilt — what you tried and could **not** break.
