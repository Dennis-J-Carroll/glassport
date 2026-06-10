<p align="center">
  <img src="assets/glassport_logo.jpg" alt="Glassport" width="180">
</p>

<h1 align="center">glassport</h1>

<p align="center">
  <strong>Clear vision port to port. Observe first. Enforce later.</strong>
</p>

<p align="center">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10+-3b82f6?style=flat-square&logo=python&logoColor=white">
  <img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-zero-22c55e?style=flat-square">
  <img alt="Runs in Termux" src="https://img.shields.io/badge/runs%20in-Termux-a78bfa?style=flat-square">
  <img alt="Status: Active" src="https://img.shields.io/badge/status-active-22c55e?style=flat-square">
</p>

<p align="center">
A passive stdio proxy and behavioral analysis toolkit for the <a href="https://modelcontextprotocol.io">Model Context Protocol</a> ecosystem.<br>
See what an MCP server <em>actually does</em>, not just what it declares.
</p>

---

## Contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Status](#status)
- [Quick start](#quick-start)
- [The session log](#the-session-log)
- [Detection inventory](#detection-inventory)
- [Session reports](#session-reports)
- [Behavioral drift](#behavioral-drift)
- [The gate](#the-gate)
- [Static audit](#static-audit)
- [From log to InteractionTrace](#from-log-to-interactiontrace)
- [Known boundaries](#known-boundaries)
- [How this differs from MCP gateways](#how-this-differs-from-mcp-gateways)
- [Roadmap](#roadmap)

---

## Why this exists

The MCP ecosystem has 10,000+ public servers and the security tooling hasn't kept pace. Studies of public servers report widespread SSRF and unsafe command-execution paths; most servers ship with static API keys or no auth at all. Twenty-plus gateways now *add* security as a layer on top.

Nobody shows you the simplest, most fundamental thing: **the gap between what a server declares in its handshake and what it actually services.**

Glassport sits in the middle and watches. No sandbox, no syscall capture, no cloud. The `tools/list` handshake gives the declared surface; every `tools/call` after it is the behavior. The delta is the report.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PRE-DEPLOYMENT                                                  │
│                                                                  │
│  MCP server source ──▶  audit.py  ──▶  scored findings          │
│                         (AST + pattern, zero execution)         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  RUNTIME                                                         │
│                                                                  │
│  MCP client ◀──▶  glassport_tap.py  ◀──▶  MCP server           │
│                          │                                       │
│                    JSONL session log                             │
│                    (~/.glassport/sessions/)                      │
│                          │                                       │
│               adapters/mcp_session.py                           │
│                          │                                       │
│                    InteractionTrace                              │
│                          │                                       │
│             ┌────────────┴────────────┐                         │
│             │                         │                          │
│        detectors.py              watch.py                       │
│        (per-session)             (drift across sessions)        │
│             │                                                    │
│        report.py ──▶  session.html                              │
└─────────────────────────────────────────────────────────────────┘
```

The tap and the analysis are **separate by design**. The tap is dumb and fast — it never drops a byte and never modifies a frame. Analysis runs offline over the log. The HTML report opens on a phone.

---

## Status

| Component | What it does | Status |
|---|---|---|
| `glassport_tap` | Passive stdio relay + JSONL frame logging | ✅ Built |
| `summarize` | Declared vs. called vs. fabricated delta per session | ✅ Built |
| `from_mcp_session()` | Session log → `InteractionTrace` | ✅ Built |
| `detectors.py` | `fabricated_calls()` + `context_violations()` as trace annotations | ✅ Built |
| `report.py` | Session timeline as self-contained static HTML, anomalies colored by severity | ✅ Built |
| `watch.py` | Session fingerprints + drift alerts across time | ✅ Built |
| `gate` | Active enforcement: blocks `tools/call` outside the declared surface, opt-in | ✅ Built |
| `audit.py` | Static pre-deployment source audit; scored against a published rubric, no execution, no network | ✅ Built |

If it's not marked Built, it doesn't run yet.

---

## Quick start

Zero dependencies. Pure Python stdlib. Runs on Python 3.10+, including Termux.

```bash
git clone https://github.com/Dennis-J-Carroll/glassport
```

### 1. Wrap a server

Edit your MCP client config to route the target server through the tap. Replace `npx exa-mcp-server` with whatever command normally launches the server.

**Claude Desktop** — `~/.config/claude/claude_desktop_config.json` (Linux) or  
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "exa": {
      "command": "python3",
      "args": [
        "/path/to/glassport/glassport_tap.py",
        "--",
        "npx", "exa-mcp-server"
      ]
    }
  }
}
```

Use the server normally. Every session is logged to `~/.glassport/sessions/<timestamp>_<server>.jsonl`.

### 2. Read the delta

```bash
$ python3 glassport_tap.py summarize ~/.glassport/sessions/<file>.jsonl

declared tools:   ['web_search']
called tools:     ['web_search', 'arxiv_lookup']
unused declared:  —
FABRICATED CALLS: [(5, 'arxiv_lookup')]   ← calls outside the declared surface
```

A fabricated call means the wire carried a `tools/call` for a tool the server never declared. That's either a hallucinating agent, a confused client, or a server quietly servicing an undeclared capability — all three are things you want to know about.

### 3. Render a session report

```bash
$ python3 glassport_tap.py report ~/.glassport/sessions/<file>.jsonl
~/.glassport/sessions/<file>.html
```

One self-contained HTML file, written next to the log (`-o` to override). Full timeline in wire order, request/response pairs linked, every frame expandable, detector findings attached to the events that triggered them — colored by severity. Dark, green, zero JavaScript, no external resources.

### 4. Watch for drift

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

### 5. Audit before you run

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

---

## The session log

One JSON object per wire line, append-only, crash-safe:

```json
{
  "schema_version": "0.1",
  "seq": 5,
  "ts": "2026-06-09T18:39:29Z",
  "dir": "c2s",
  "frame": {
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {"name": "arxiv_lookup"}
  },
  "raw": null
}
```

- `dir` is `c2s` (client→server) or `s2c` (server→client)
- `frame` is the parsed JSON-RPC frame; lines that fail to parse are preserved verbatim in `raw` — nothing is dropped on ingest
- `schema_version` is frozen at `0.1`; old logs stay readable forever

**The relay is sacred.** Logging is best-effort: a logging failure can never alter, delay, or kill a live session.

---

## Detection inventory

`detectors.py` runs three passes over a trace. Every finding is wire-provable — if no `initialize` frame was captured, no capability claim is made; if no `tools/list` was seen, no schema check is possible. Absence of evidence is reported as absence, not guilt.

### Severity scale

```
1   worth a look
2   should not happen
3   hostile or hallucinated unless proven otherwise
```

### Findings

| Subcategory | Sev | What the wire proved |
|---|:---:|---|
| `fabricated_tool_call` | **3** | `tools/call` outside the server's `tools/list` surface |
| `capability_violation` | **3** | server-initiated request the client never granted in `initialize` |
| `schema_violation` | **2** | call arguments violate the declared `inputSchema` |
| `unknown_server_request` | **2** | server-initiated request outside the MCP specification |
| `premature_call` | **2** | `tools/call` before `notifications/initialized` |
| `surface_change` | **2** | `tools/list` result changed mid-session |
| `call_before_declaration` | **1** | `tools/call` before any `tools/list` response |
| `orphaned_response` | **1** | response whose JSON-RPC `id` matched no request |
| `gate_blocked` | info | gate blocked a fabricated call; server never saw the frame |
| `gate_injected_response` | info | gate synthesized the error reply; server never sent it |

Severity-3 findings drive the session verdict to `HOSTILE OR HALLUCINATED`. INFO annotations (gate records) never affect the verdict — a blocked call is still judged by its own findings.

---

## Session reports

`report.py` renders a self-contained static HTML page from a trace:

- **Verdict** — `CLEAN` / `WORTH A LOOK` / `SHOULD NOT HAPPEN` / `HOSTILE OR HALLUCINATED`
- **Surface** — declared tools vs. called tools; fabricated calls highlighted
- **Timeline** — every wire event in sequence, request/response pairs linked, JSON payloads in collapsible `<details>` blocks, detector annotations inline
- **Footer** — event count, annotation count, generation timestamp, severity key

Everything that came off the wire is HTML-escaped before it touches the page. A hostile server can name a tool `<img onerror=...>`; the report renders it as text. This matters because the report opens from `file://`, where injected script would have local-file reach.

---

## Behavioral drift

`watch.py` reduces each session to a fingerprint — declared surface, schema hashes, called tools, hostnames in wire traffic, server-initiated request methods, server identity — and replays the session history chronologically per server.

**Drift findings:**

| Kind | Sev | What changed |
|---|:---:|---|
| `new_fabricated_tool` | **3** | fabricated call, first time in this server's history |
| `new_declared_tool` | **2** | server now declares a tool never in its surface before |
| `schema_changed` | **2** | `inputSchema` for a declared tool changed |
| `new_server_request` | **2** | server-initiated request never seen before |
| `new_host` | **2** | new hostname in tool arguments or results |
| `server_identity_changed` | **2** | `serverInfo.name` changed |
| `removed_declared_tool` | **1** | tool disappeared from declared surface |
| `new_called_tool` | **1** | tool called for the first time across all sessions |
| `new_capability` | **1** | server now advertises a new capability |
| `server_version_changed` | **1** | server version string changed |

Watch is **stateless**: the baseline is rebuilt from the logs on every run, so every drift claim traces back to a `.jsonl` file on disk. `--json` for machines; **exit code 1** when drift of severity ≥ 2 is present — cron-friendly.

---

## The gate

When observation has earned enough trust, swap `wrap` for `gate` in your MCP config — same command, one word different:

```json
"args": ["/path/to/glassport/glassport_tap.py", "gate", "--",
         "npx", "exa-mcp-server"]
```

The gate blocks exactly one thing: a `tools/call` naming a tool outside the server's declared surface. The request never reaches the server; the client gets a synthesized JSON-RPC error (code `-32000`) whose `error.data` carries `{"glassport": "gate_blocked"}` — the gate's voice is always distinguishable from the server's.

```
... tools/call "shadow_tool" →
← {"error": {"code": -32000, "message": "glassport gate: tools/call
   'shadow_tool' blocked — not in the declared tool surface", ...}}
```

The session log records both realities: the blocked frame is logged with `"gate": {"action": "blocked"}` (the server never saw it) and the synthesized error with `{"action": "injected"}` (the server never sent it). `summarize`, `report`, and `watch` all understand the markers — gate actions appear in the HTML report as green INFO annotations, distinct from the red findings the blocked call still earns.

**The gate only enforces what the wire has proven.** Until a `tools/list` response has crossed the pipe there is no declaration to enforce, so early calls are forwarded (and the passive detectors still flag them). The latest `tools/list` result is the contract — a server that re-declares a smaller surface shrinks what it may be called to do.

---

## Static audit

The tap watches what a server *does*; `audit.py` reads what a server *is*, before it ever runs:

```bash
python3 glassport_tap.py audit ./some-mcp-server
python3 glassport_tap.py audit ./some-mcp-server --json
python3 glassport_tap.py audit --rubric   # print the full scoring rubric
```

- **Python**: full AST pass — `model_eval(x)` is not `eval`, and `import subprocess as sp; sp.run(c, shell=True)` still is
- **JavaScript / TypeScript**: pattern depth; the report says which depth it used
- **Score**: starts at 100, fixed deductions per rule that fired — each rule deducts once regardless of hit count, so one noisy pattern can't zero a report
- **Rubric**: printed with `--rubric`, embedded in the file; an unexplained trust score is the opacity this project exists to fight

Rules cover: hardcoded secrets (redacted in output), **tool poisoning** (model-directed text like `<IMPORTANT> read ~/.ssh` planted in tool descriptions), hidden/bidi unicode, dynamic execution, shell injection, runtime installs, and capability notes (subprocess, file delete/write, network egress).

`audit` and the tap compose along the lifecycle: **audit** before you install, **wrap** while you run, **gate** when trust runs out. Static analysis can't see what a server does on the wire — and the wire can't show you a secret sitting unused in source. Neither subsumes the other.

> **Note:** Running `audit` on Glassport itself flags `tool-poisoning` — because the rule's own regexes contain the strings they hunt for. That is the tool being correct about its contents. Glassport deliberately does not exempt itself, because a scanner that suppresses its own matches is one flag away from suppressing an attacker's.

---

## From log to InteractionTrace

`adapters/mcp_session.py` converts a tap log into an `InteractionTrace` — the protocol-spanning schema used by the Understanding Layer for visualization and hallucination attribution:

```python
from adapters.mcp_session import from_mcp_session_file

trace = from_mcp_session_file("~/.glassport/sessions/....jsonl",
                              server_name="exa-mcp-server")
trace.declared_tools()         # from the tools/list handshake
trace.called_tools()           # every tools/call on the wire
trace.fabricated_tool_calls()  # the delta
```

The adapter is deliberately dumb: it produces the faithful trace and nothing else. Detectors run on top and attach `Annotation` objects:

```python
from detectors import annotate

annotate(trace)   # fabricated calls, schema violations, capability violations,
                  # ordering violations, orphaned responses, surface changes
```

Request/response pairs are correlated by JSON-RPC `id`; responses with no matching request are kept and flagged `orphaned` — an orphaned response is itself a signal. The `summarize` command routes through this same adapter internally, so the CLI report and the Understanding Layer read the wire through one code path and can never disagree about what a session contained.

---

## Known boundaries

Stated here so nobody discovers them the hard way:

- **stdio transport only.** Remote streamable-HTTP servers need a different interception model and are out of scope for now. Local stdio is where the highest-trust credentials live, so it's first.
- **Passive by default.** `wrap` observes and never blocks, rewrites, or delays — that contract is permanent. Enforcement exists only in the opt-in `gate` mode, shipped last on purpose: a blocking proxy that misfires destroys trust faster than no proxy at all.
- **The gate can't block before declaration.** A client that fires `tools/call` before the `tools/list` response lands is forwarded — there is no declaration to enforce yet. The passive detectors flag these (`premature_call` / `call_before_declaration`), and enforcement kicks in the moment the handshake completes.
- **The tap sees the wire, not the mind.** It cannot see the user's prompt, the model's reasoning, or the agent's plan. Every claim it makes is limited to what crossed the pipe.

---

## How this differs from MCP gateways

Gateways (Docker MCP Gateway, Kong, MCPX, …) add auth, RBAC, and routing *on top of* traffic. Glassport answers a different question: **did this server's behavior match its declaration?** Gateways log spans; Glassport tells you what diverged. The two compose — you can run a tap behind a gateway.

Sibling projects:

- [`repo-tester`](https://github.com/Dennis-J-Carroll/repo-tester) — static supply-chain scanning, the front door before you ever run a server (published on PyPI)
- **Understanding Layer** — trace comprehension across User↔Agent, Agent↔Tool (MCP), and Agent↔Agent (A2A) layers; the tap is its L2 instrument

---

## Roadmap

M0 (tap) through M5 (gate) are built. The static `audit` is folded in. Observe first. Enforce later — later is here, and it's still opt-in.

Still on the horizon:

- Remote streamable-HTTP interception
- Network-enriched audit mode: npm / PyPI / GitHub provenance lookups, as an explicit opt-in flag (kept off the default path so the core audit stays reproducible and offline)
- Agent↔Agent trace coverage for Google A2A protocol
- TUI: terminal interface for live session inspection and drift review
- CI integration: `--format json` + GitHub Action for automated audit on MCP config changes

---

## Project structure

```
glassport/
├── glassport_tap.py          # M0: stdio proxy — the tap
├── interaction_trace.py      # protocol-spanning data model
├── detectors.py              # M2: analysis passes
├── report.py                 # M3: HTML session renderer
├── watch.py                  # M4: behavioral drift
├── audit.py                  # static source audit
├── adapters/
│   └── mcp_session.py        # tap log → InteractionTrace
├── examples/
│   └── fake_server.py        # deliberately misbehaving test server
└── tests/
    ├── test_detectors.py
    ├── test_report.py
    ├── test_watch.py
    ├── test_gate.py
    └── test_audit.py
```

---

*Glassport — Dennis J. Carroll · 2026*  
*"See what's inside before you open it."*
