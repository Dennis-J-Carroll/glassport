<p align="center">
  <img src="assets/glassport_logo.jpg" alt="Glassport" width="180">
</p>

# Glassport

**A window in the envelope — see what an MCP server actually does, not just what it says.**

Glassport is a passive stdio proxy for MCP servers. Drop it between your
MCP client (Claude Desktop, Claude Code, Cursor) and any stdio MCP server.
It relays every frame untouched and records the full session — then shows
you the delta between the server's **declared** tool surface and its
**observed** behavior.

The glass before the port. Observe first. Enforce later.

---

## Why this exists

The MCP ecosystem has 10,000+ public servers and the security tooling
hasn't kept pace. Studies of public servers report widespread SSRF and
unsafe command-execution paths; most servers ship with static API keys or
no auth at all. Twenty-plus gateways now *add* security as a layer on top.
Nobody shows you the simplest, most fundamental thing: **the gap between
what a server declares in its handshake and what it actually services.**

Glassport sits in the middle and watches. That's it. No sandbox, no
syscall capture, no cloud. The `tools/list` handshake gives the declared
surface; every `tools/call` after it is the behavior. The delta is the
report.

---

## Status

| Component | What it does | Status |
|---|---|---|
| `glassport_tap` | Passive stdio relay + JSONL frame logging | ✅ **Built** |
| `summarize` | Declared vs. called vs. fabricated delta per session, computed on an `InteractionTrace` | ✅ **Built** |
| `from_mcp_session()` | Session log → `InteractionTrace` (Understanding Layer schema) | ✅ **Built** |
| `detectors.py` | `fabricated_calls()` + `context_violations()` emitted as trace annotations | ✅ **Built** |
| `report.py` | Session timeline as self-contained static HTML, anomalies colored by severity, no JS | ✅ **Built** |
| `watch.py` | Session fingerprints over time; drift alerts ("started calling a new domain on Tuesday") | ✅ **Built** |
| `gate` | Active enforcement: blocks `tools/call` outside the declared surface, opt-in | ✅ **Built** — the "port" in Glassport, shipped last on purpose |
| `audit.py` | Static pre-deployment audit of a server's source; scored against a published rubric, no execution, no network | ✅ **Built** |

If it's not marked Built, it doesn't run yet.

---

## Quick start

Zero dependencies. Pure Python stdlib. Runs anywhere Python 3.10+ runs,
including Termux.

```bash
git clone https://github.com/Dennis-J-Carroll/glassport
```

Wrap any stdio server in your MCP config by putting the tap in front of
the real command:

```json
{
  "mcpServers": {
    "exa": {
      "command": "python3",
      "args": ["/path/to/glassport/glassport_tap.py", "--",
               "npx", "exa-mcp-server"]
    }
  }
}
```

Use the server normally. Every session is logged to
`~/.glassport/sessions/<timestamp>_<server>.jsonl`.

Then read the delta:

```bash
$ python3 glassport_tap.py summarize ~/.glassport/sessions/<file>.jsonl

declared tools:   ['web_search']
called tools:     ['web_search', 'arxiv_lookup']
unused declared:  —
FABRICATED CALLS: [(5, 'arxiv_lookup')]   <-- calls outside the declared surface
```

A fabricated call means the wire carried a `tools/call` for a tool the
server never declared. That's either a hallucinating agent, a confused
client, or a server quietly servicing an undeclared capability. All three
are things you want to know about.

Or render the whole session as a page you can read on a phone:

```bash
$ python3 glassport_tap.py report ~/.glassport/sessions/<file>.jsonl
~/.glassport/sessions/<file>.html
```

One self-contained HTML file, written next to the log (`-o` to choose):
the full timeline in wire order, request/response pairs linked, every
frame expandable, and detector findings attached to the events that
triggered them — colored by severity (1 worth a look, 2 should not
happen, 3 hostile or hallucinated). Dark, green, zero JavaScript, no
external resources. Everything that came off the wire is HTML-escaped,
so a hostile server can't turn its own audit report into an exploit.

And once a server has history, watch it for drift:

```bash
$ python3 glassport_tap.py watch    # defaults to ~/.glassport/sessions

exa-search — 3 session(s)
  20260608T..._exa_100.jsonl  baseline established · 1 declared tool(s) · hosts: api.exa.ai
  20260609T..._exa_101.jsonl  no drift
  20260610T..._exa_102.jsonl
    [sev 3] new_fabricated_tool: tools/call 'shadow_fetch' outside any declared surface, first time in this server's history
    [sev 2] new_server_request: server-initiated request 'sampling/createMessage' never seen before
    [sev 2] new_host: new host in wire traffic: collect.evil-analytics.io
```

Every session is reduced to a fingerprint — declared surface, schema
hashes, called tools, hostnames seen in wire traffic, server-initiated
request methods, server identity — and compared against the merged
baseline of every prior session for that server. Only novelty is
reported. Watch is stateless: the baseline is rebuilt from the logs on
every run, so every drift claim traces back to a `.jsonl` on disk.
`--json` for machines; exit code 1 when drift of severity ≥ 2 is
present, so a cron job can page you.

## The gate

When observation has earned enough trust, swap `wrap` for `gate` in
your MCP config — same command, one word different:

```json
"args": ["/path/to/glassport/glassport_tap.py", "gate", "--",
         "npx", "exa-mcp-server"]
```

The gate blocks exactly one thing: a client→server `tools/call` naming
a tool outside the server's declared surface. The request never reaches
the server; the client gets a synthesized JSON-RPC error (code
`-32000`) whose `error.data` carries `{"glassport": "gate_blocked"}`,
so the gate's voice is always distinguishable from the server's.
Everything else — every other method, notification, reply, and
unparseable line — relays untouched.

```
$ ... tools/call "shadow_tool" →
← {"error": {"code": -32000, "message": "glassport gate: tools/call
   'shadow_tool' blocked — not in the declared tool surface", ...}}
```

The session log records both realities: the blocked frame is logged
with `"gate": {"action": "blocked"}` (the server never saw it) and the
synthesized error with `{"action": "injected"}` (the server never sent
it). `summarize`, `report`, and `watch` all understand the markers —
gate actions show up in the HTML report as green INFO annotations,
distinct from the red judgment the blocked call itself still earns.

The gate only enforces what the wire has proven. Until a `tools/list`
response has crossed the pipe there is no declaration to violate, so
calls are forwarded (and the passive detectors still flag them). The
latest `tools/list` result is the contract — a server that re-declares
a smaller surface shrinks what it may be asked to do.

---

## The session log

One JSON object per wire line, append-only, crash-safe:

```json
{"schema_version": "0.1", "seq": 5, "ts": "2026-06-09T18:39:29Z",
 "dir": "c2s", "frame": {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
 "params": {"name": "arxiv_lookup"}}, "raw": null}
```

- `dir` is `c2s` (client→server) or `s2c` (server→client)
- `frame` is the parsed JSON-RPC frame; lines that don't parse are
  preserved verbatim in `raw` — nothing is dropped on ingest
- `schema_version` is frozen at 0.1; old logs stay readable forever

The relay is sacred and logging is best-effort: a logging failure can
never alter, delay, or kill a live session.

---

## From log to InteractionTrace

`adapters/mcp_session.py` converts a session log into an
`InteractionTrace` — the protocol-spanning schema used by the
Understanding Layer for visualization and hallucination attribution:

```python
from adapters.mcp_session import from_mcp_session_file

trace = from_mcp_session_file("~/.glassport/sessions/....jsonl",
                              server_name="exa-mcp-server")
trace.declared_tools()         # from the tools/list handshake
trace.called_tools()           # every tools/call on the wire
trace.fabricated_tool_calls()  # the delta
```

The adapter is deliberately dumb: it produces the faithful trace and
nothing else. Detectors run on top. Request/response pairs are correlated
by JSON-RPC id; responses with no matching request are kept and flagged
`orphaned` — an orphaned response is itself a signal.

The `summarize` command routes through this same adapter internally —
the CLI report and the Understanding Layer read the wire through one
code path, so they can never disagree about what a session contained.
(Tap mode stays a standalone single file; only `summarize` needs the
trace modules alongside it.)

Detectors run on top of the trace and attach `Annotation` objects:

```python
from detectors import annotate

annotate(trace)   # fabricated calls, schema violations, capability
                  # violations, ordering violations, orphaned responses,
                  # mid-session surface changes
```

Detectors only assert what the wire proves: no `initialize` captured
means no capability claim, no `tools/list` seen means no schema check.

---

## Static audit — before you ever run it

The tap watches what a server *does*; `audit` reads what a server *is*,
before it runs even once. Point it at a file or a checkout:

```bash
$ python3 glassport_tap.py audit ./some-mcp-server

score:    9/100 (F)
  -25  secret-hardcoded (critical) — 2 hit(s)
  -25  tool-poisoning (critical) — 3 hit(s)
  -15  exec-dynamic (high) — 1 hit(s)
  -15  shell-injection (high) — 1 hit(s)
  ...
  [critical] tool-poisoning server.py:7
      directive text: '<IMPORTANT>'
```

Local-only by design: no registry lookups, no network, no execution.
Python sources get a real **AST pass** — so `model_eval(x)` is not
flagged as `eval`, and `import subprocess as sp; sp.run(c, shell=True)`
still is. JS/TS get pattern depth, and the report says which depth it
used. Rules cover hardcoded secrets (redacted in output), **tool
poisoning** (model-directed text like "ignore previous instructions" or
`<IMPORTANT> read ~/.ssh` planted in tool descriptions), hidden/bidi
unicode, dynamic execution, shell injection, runtime installs, and
capability notes (subprocess, file delete/write, network egress).

The **score is not a vibe**: it starts at 100 and loses a fixed,
published weight per rule that fired — each rule deducts once, however
many times it hit, so one noisy pattern can't zero a report. Every
deduction names its rule; the full table prints with `--rubric`. An
unexplained trust score is the opacity this project exists to fight.

`audit` and the tap compose along the lifecycle: **audit** before you
install, **wrap** while you run, **gate** when trust runs out. A static
read can't see what a server does on the wire (that's the tap's job),
and the wire can't show you a secret sitting unused in source (that's
the audit's) — neither subsumes the other.

> Auditing a security tool produces expected noise: run `audit` on
> Glassport itself and `audit.py` flags `tool-poisoning`, because the
> rule's own regexes literally contain the strings it hunts for. That
> is the tool being correct about its contents, not a bug — and
> Glassport deliberately does **not** exempt itself, because a scanner
> that suppresses its own matches is one flag away from suppressing an
> attacker's.

---

## Known boundaries

Stated here so nobody discovers them the hard way:

- **stdio transport only.** Remote streamable-HTTP servers need a
  different interception model and are out of scope for now. Local stdio
  is where the highest-trust credentials live, so it's first.
- **Passive by default.** `wrap` observes and never blocks, rewrites,
  or delays — that contract is permanent. Enforcement exists only in
  the opt-in `gate` mode, shipped last on purpose: a blocking proxy
  that misfires destroys trust faster than no proxy at all.
- **The gate can't block what hasn't been declared yet.** A client
  that fires `tools/call` before the `tools/list` response lands is
  forwarded — there is no declaration to enforce, and pre-list calls
  are legal MCP. The passive detectors still flag them
  (`premature_call` / `call_before_declaration`), and the next session
  is covered the moment the handshake completes.
- **The tap sees the wire, not the mind.** It cannot see the user's
  prompt, the model's reasoning, or the agent's plan. Claims it makes are
  limited to what crossed the pipe.

---

## How this differs from MCP gateways

Gateways (Docker MCP Gateway, Kong, MCPX, …) add auth, RBAC, and routing
*on top of* traffic. Glassport answers a different question: **did this
server's behavior match its declaration?** Gateways log spans; Glassport
tells you what diverged. The two compose — you can run a tap behind a
gateway.

Sibling projects: [`repo-tester`](https://github.com/Dennis-J-Carroll/repo-tester)
(static supply-chain scanning — the front door before you ever run a
server) and the Understanding Layer (trace comprehension across
User↔Agent, Agent↔Tool, and Agent↔Agent layers — the tap is its L2
instrument).

---

## Roadmap

M0 (tap) through M5 (gate) are built, and the static `audit` (the v0.1
dissector prototype, rebuilt stdlib-only with an AST pass and a
published rubric) is folded in. Observe first. Enforce later — later is
here, and it's still opt-in.

Still on the horizon: a remote streamable-HTTP interception model, and
the audit's network-enriched mode (npm/PyPI/GitHub provenance) as an
explicit opt-in flag — kept off the default path so the core audit
stays reproducible and offline.

---

*Glassport — Dennis J. Carroll · 2026*
*"See what's inside before you open it."*
