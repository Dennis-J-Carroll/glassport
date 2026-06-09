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
| Session HTML report | Visual timeline with anomalies highlighted | 🔜 Planned (M3) |
| Watch mode | Behavioral drift across sessions over time | 🔜 Planned (M4) |
| Static audit tools | Pre-deployment dissection + scoring (`glassport_audit`, `glassport_dissect`) | 🔜 Planned — earlier v0.1 prototype being folded in |
| Policy gate | Active enforcement: block calls outside declared scope | 🔜 Planned (M5) — the "port" in Glassport, last on purpose |

Nothing in the Planned rows ships today. If it's not marked Built, it
doesn't run yet.

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

---

## Known boundaries

Stated here so nobody discovers them the hard way:

- **stdio transport only.** Remote streamable-HTTP servers need a
  different interception model and are out of scope for now. Local stdio
  is where the highest-trust credentials live, so it's first.
- **Passive only.** The tap observes; it never blocks, rewrites, or
  delays. Enforcement (the policy gate) ships only after the detectors
  have a track record — a blocking proxy that misfires destroys trust
  faster than no proxy at all.
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

1. **M3 — Session report.** Single-file HTML render of a session
   timeline, anomalies colored, parent arrows drawn. No JS, opens on a
   phone.
2. **M4 — Watch mode.** Fingerprint sessions over time; alert when a
   server's behavior drifts ("started calling a new tool on Tuesday").
3. **Static audit (folded in).** The earlier v0.1 dissector/static-audit
   prototype returns as `glassport audit` — the pre-deployment
   complement to the runtime tap. Scores, when they ship, will publish
   the rubric that produced them; an unexplained trust score is the
   opacity this project exists to fight.
4. **M5 — The gate.** Opt-in enforcement: block `tools/call` frames
   outside the declared surface. Last, on purpose.

---

*Glassport — Dennis J. Carroll · 2026*
*"See what's inside before you open it."*
