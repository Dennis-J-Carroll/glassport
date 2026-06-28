<p align="center">
  <img src="assets/glassport_logo.jpg" alt="Glassport" width="180">
</p>

<h1 align="center">glassport</h1>

<p align="center">
  <strong>Clear vision port to port. Observe first. Enforce later.</strong>
</p>

<p align="center">
  <img alt="CI" src="https://github.com/Dennis-J-Carroll/glassport/actions/workflows/ci.yml/badge.svg">
  <a href="https://pypi.org/project/glassport/"><img alt="PyPI" src="https://img.shields.io/pypi/v/glassport?style=flat-square&color=3b82f6"></a>
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
- [Query the history](#query-the-history)
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
| `tui` | Live curses session inspector: picker, timeline, findings feed, frame overlay | ✅ Built |
| `serve` | Glassport itself as a queryable MCP server: the agent interrogates its own session history over stdio | ✅ Built |

If it's not marked Built, it doesn't run yet.

---

## Quick start

Zero dependencies. Pure Python stdlib. Runs on Python 3.10+, including Termux.

```bash
pip install glassport     # installs the `glassport` command
```

or, equivalently — a bare clone is fully runnable, no install step:

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
      "command": "glassport",
      "args": ["--", "npx", "exa-mcp-server"]
    }
  }
}
```

(Running from a bare clone instead? Use `"command": "python3"`, `"args": ["/path/to/glassport/glassport_tap.py", "--", ...]` — the root shim is kept for exactly this.)

Use the server normally. Every session is logged to `~/.glassport/sessions/<timestamp>_<server>.jsonl`.

### 2. Read the delta

```bash
$ glassport summarize ~/.glassport/sessions/<file>.jsonl

declared tools:   ['web_search']
called tools:     ['web_search', 'arxiv_lookup']
unused declared:  —
FABRICATED CALLS: [(5, 'arxiv_lookup')]   ← calls outside the declared surface
```

A fabricated call means the wire carried a `tools/call` for a tool the server never declared. That's either a hallucinating agent, a confused client, or a server quietly servicing an undeclared capability — all three are things you want to know about.

### 3. Render a session report

```bash
$ glassport report ~/.glassport/sessions/<file>.jsonl
~/.glassport/sessions/<file>.html
```

One self-contained HTML file, written next to the log (`-o` to override). Full timeline in wire order, request/response pairs linked, every frame expandable, detector findings attached to the events that triggered them — colored by severity. Dark, green, zero JavaScript, no external resources.

### 4. Watch for drift

```bash
$ glassport watch    # defaults to ~/.glassport/sessions

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
$ glassport audit ./some-mcp-server

score:    9/100 (F)
  -25  secret-hardcoded (critical) — 2 hit(s)
  -25  tool-poisoning (critical) — 3 hit(s)
  -15  exec-dynamic (high) — 1 hit(s)
  -15  shell-injection (high) — 1 hit(s)
  ...
  [critical] tool-poisoning server.py:7
      directive text: '<IMPORTANT>'
```

### 6. Inspect live in the terminal

```bash
$ glassport tui          # session picker → live dashboard
$ glassport tui ~/.glassport/sessions/<file>.jsonl
```

### 7. Let the agent query its own history

```bash
$ glassport serve        # MCP server on stdio; speaks to your agent
[glassport] serve: MCP audit server on stdio; log dir: ~/.glassport/sessions
```

Register it in your MCP client (see [Query the history](#query-the-history)) and the agent gets five read-only tools over the same logs — `list_sessions`, `analyze_session`, `audit_server`, `get_gate_status`, `watch_drift`. Glassport watches the servers; the agent watches Glassport.

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

`detectors.py` runs four passes over a trace. Every finding is wire-provable — if no `initialize` frame was captured, no capability claim is made; if no `tools/list` was seen, no schema check is possible. Absence of evidence is reported as absence, not guilt.

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

**Data exfiltration** (`data_exfiltration`) is the fourth pass: it reads the payloads, not just the protocol. It flags PII and credentials in tool-call arguments, sensitive data leaving for hosts the server never declared, and secrets leaked back in tool results.

| Subcategory | Sev | What the wire proved |
|---|:---:|---|
| `pii_<category>` | **3**/2/1 | credential or PII in tool-call arguments — `pii_rsa_private_key`, `pii_openai_key`, `pii_aws_secret_key`, `pii_github_token`, `pii_ssn`, `pii_credit_card`, … (sev by category) |
| `unexpected_egress_host` | **3**/2 | tool call reaches a host outside the declared surface; **3** when sensitive data rides along, **2** otherwise |
| `pii_in_result_<category>` | **3** | a credential came back in a tool *result* — a server leaking secrets to the client |

Three properties keep this honest:

- **Validated, not greedy.** Credit cards pass Luhn, SSNs pass SSA-range checks, generic secrets must clear an entropy floor. A random 16-digit order number is not a card.
- **Non-reversible redaction.** A flagged secret never appears in the annotation — not even a prefix. The explanation carries `[category redacted · N chars]`, so the detector's own output can't become the leak.
- **The allowlist downgrades, it never silences.** Traffic to `*.amazonaws.com`, `*.googleapis.com`, and peers is expected and quiet — *until* a secret rides along, at which point it's flagged anyway (severity 2). An attacker-controlled bucket on a trusted domain is the most common real exfil channel; trusting the domain must not mean trusting the payload.
- **It sees through obfuscation, and it can't be wedged by what it scans.** A secret sprinkled with zero-width joiners (`s​k​-​a​n​t​-​…`) or disguised in fullwidth homoglyphs reads as plaintext to the validators: every blob is invisible-stripped and NFKC-folded before matching. And because the scanner's input is hostile by definition, the credential patterns are ReDoS-hardened (a flood of PEM `BEGIN` markers can't force catastrophic backtracking) and each blob is capped — the traffic glassport inspects cannot turn the inspection into a denial of service.

The detector pass is also **fault-isolated**: if one detector raises, `annotate()` records a `detector_error` annotation and the rest still run, so a single bad pass can't blind the overwatch.

### Custom PII patterns

The built-in catalog covers the common credentials, but your secrets are your own. Two ways to extend it — both feed the same scan, kept separate from the built-ins so the baseline can't be corrupted:

**Declarative (CI-friendly, no code).** Point an env var at a JSON file:

```bash
export GLASSPORT_PII_PATTERNS=/etc/glassport/pii.json
```

```json
[
  { "category": "acme_token", "severity": 3,
    "pattern": "acme-[A-Za-z0-9]{32}",
    "description": "Acme API token",
    "validator": "entropy" }
]
```

`severity` is `1`–`3`; `validator` is optional and names a built-in precision check — `luhn`, `ssn`, `entropy` (>3.0 bits/char), or `entropy_high` (>4.0, culls high-entropy non-secrets like a hex digest). A bad regex, an out-of-range severity, or an unknown validator name is rejected **loudly** when loaded explicitly — but the env-var path is **fail-safe**: a misconfigured file warns to stderr and the built-in scan keeps running. A typo in your custom patterns can never blind the detector.

**In code (full power).** Register a `PIIPattern` with your own callable validator — anything JSON can't express:

```python
from glassport.detectors import register_pii_pattern, PIIPattern
import re

register_pii_pattern(PIIPattern(
    "acme_token", 3, re.compile(r"acme-[A-Za-z0-9]{32}-(?:live|test)"),
    lambda s: s.endswith("-live"), "Acme live token"))
```

Custom patterns are first-class: same dedup, same non-reversible redaction, same egress escalation as the built-ins.

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
"command": "glassport",
"args": ["gate", "--", "npx", "exa-mcp-server"]
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
glassport audit ./some-mcp-server
glassport audit ./some-mcp-server --json
glassport audit ./some-mcp-server --sarif   # SARIF 2.1.0 for code scanning
glassport audit --rubric   # print the full scoring rubric
```

- **Python**: full AST pass — `model_eval(x)` is not `eval`, and `import subprocess as sp; sp.run(c, shell=True)` still is
- **JavaScript / TypeScript**: pattern depth; the report says which depth it used
- **Score**: starts at 100, fixed deductions per rule that fired — each rule deducts once regardless of hit count, so one noisy pattern can't zero a report
- **Score measures risk, not capability** (rubric v0.3): a `note`-tier rule is **surfaced but weight 0**. `cmd-exec` (spawns a subprocess) and `fs-write` (writes a file) are capabilities, not violations — their *dangerous* forms have their own scored rules (`shell-injection`, `fs-delete`). Penalizing the mere presence of a capability would only reward hiding it, which is the opacity this tool exists to fight. The capability still appears in every report as a `[note]` finding.
- **Rubric**: printed with `--rubric`, embedded in the file; an unexplained trust score is the opacity this project exists to fight

Rules cover: hardcoded secrets (redacted in output), **tool poisoning** (model-directed text like `<IMPORTANT> read ~/.ssh` planted in tool descriptions), hidden/bidi unicode, dynamic execution, shell injection, runtime installs, and capability notes (subprocess, file delete/write, network egress). The tool-poisoning pass runs on an **invisible-stripped view** of the source — a directive split with zero-width joiners is caught and mapped back to its real line number, not hidden by the same trick `unicode-hidden` flags.

`audit` and the tap compose along the lifecycle: **audit** before you install, **wrap** while you run, **gate** when trust runs out. Static analysis can't see what a server does on the wire — and the wire can't show you a secret sitting unused in source. Neither subsumes the other.

### SARIF export and CI

`--sarif` emits a SARIF 2.1.0 document over the audit findings. Result locations are **repo-root-relative** (the audited path is folded back in), so GitHub code scanning annotates the offending line on the diff rather than pointing at nothing. One severity vocabulary maps both the audit's string severities and the runtime detectors' integer severities onto SARIF `error` / `warning` / `note`, so a single report can carry both without two scales fighting.

The shipped GitHub Actions workflow (`.github/workflows/ci.yml`) runs `audit --sarif` and uploads to the Security tab; point `AUDIT_TARGET` at your server directory. The upload runs even when the audit exits non-zero — a high or critical finding is exactly what the Security tab is for.

The *runtime* side has a SARIF path too: both `glassport detect <session>.jsonl --sarif` (runs every behavioral detector) and `glassport summarize <session>.jsonl --sarif` emit a SARIF 2.1.0 document over the **detector annotations** of a session — fabricated calls, data exfiltration, drift, gate actions. Unlike the audit (which locates into repo source), these results locate into the session `.jsonl` itself (`region.startLine` is the wire event's line in the log), since a behavioral finding's evidence lives on the wire, not in a source file. Same severity vocabulary; consume it as a generic SARIF artifact.

The CI workflow uploads the runtime SARIF too — a `detect --sarif` over a committed session fixture, posted to the Security tab under a distinct `glassport-runtime` category so the runtime findings sit beside the static `glassport-audit` ones without the two severity scales colliding.

### CI integration

glassport's static audit drops into any pipeline as a gate (exit 1 on
critical/high) or a SARIF artifact.

**GitHub Actions** — shipped in `.github/workflows/ci.yml` (`security-scan` job):
`audit --sarif` → Security tab (`glassport-audit`), and `detect --sarif` over a
session fixture → Security tab (`glassport-runtime`).

**GitLab CI** — copy [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) to your
repo root as `.gitlab-ci.yml`. Two jobs mirroring the GitHub workflow:
`glassport-audit` runs `audit --sarif` over your source, and `glassport-runtime`
runs `detect --sarif` over a captured tap session log (`SESSION_LOG`, only when
one is present). Both save SARIF 2.1.0 as a build artifact and are non-blocking
by default (`allow_failure: true`); set it to `false` to gate the pipeline.

**pre-commit** — add glassport as a hook so a critical/high finding blocks the
commit:

    repos:
      - repo: https://github.com/Dennis-J-Carroll/glassport
        rev: v0.3.0
        hooks:
          - id: glassport-audit
            args: ["path/to/server"]

### Inline suppression

A finding can be waived **on the line that produced it**, in source, where the diff records it:

```python
sp.run(cmd, shell=True)        # nosec
sp.run(cmd, shell=True)        # glassport: ignore
sp.run(cmd, shell=True)        # glassport: ignore[shell-injection]
```

`# nosec` (bandit-compatible) and bare `# glassport: ignore` waive every finding on the line; the scoped `# glassport: ignore[rule-id]` waives only the named rule and lets everything else still fire.

> **Note — observe, learn, act.** Running `audit` on Glassport once flagged its own `tool-poisoning` rule, because the rule's text *quotes* the strings it hunts (`<IMPORTANT> read ~/.ssh`) to explain the attack. The scanner was correct: that text is **information** — documentation of a threat — and observing it is the tool doing its job. The question is what to do with a true observation about benign content.
>
> The wrong answer is a silent self-exemption: a scanner that quietly drops its own matches is one config away from quietly dropping an attacker's. The right answer is an **auditable** one. The catalog now carries a scoped `# glassport: ignore[tool-poisoning]` on exactly the lines that document the attack — visible in every diff, limited to one rule, on one line, reviewable by anyone. The suppression is itself part of the record, not a hole in it. That is the same doctrine the detectors follow on the wire — assert only what the evidence shows, and make every judgment traceable — applied back to Glassport's own source. Observe the finding, learn that the match is documentation, act in the open.

---

## Query the history

The same logs the tap writes can be read back *by the agent itself*. `glassport serve` exposes Glassport as an MCP server over stdio — add it alongside the servers you're watching, and the agent can interrogate its own session history mid-conversation:

```json
{
  "mcpServers": {
    "glassport": { "command": "glassport", "args": ["serve"] },
    "filesystem": {
      "command": "glassport",
      "args": ["gate", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

Five read-only tools, every one backed by a `.jsonl` on disk:

| Tool | What it returns |
|---|---|
| `list_sessions` | recent session logs, newest first |
| `analyze_session` | declared vs. called vs. fabricated tools + every detector annotation |
| `audit_server` | the static AST audit on a server source path (reads, never runs) |
| `get_gate_status` | the calls the gate blocked in a session |
| `watch_drift` | behavioral drift across all sessions, grouped by server |

Recursive in the right way: Glassport watches the servers, and the agent watches Glassport's findings. Same zero-dependency stdio path as the tap — newline-delimited JSON-RPC, stdlib `json`. A tool failure comes back as an MCP result with `isError`, not a protocol error, so the agent sees it as content it can reason about.

---

## From log to InteractionTrace

`adapters/mcp_session.py` converts a tap log into an `InteractionTrace` — the protocol-spanning schema used by the Understanding Layer for visualization and hallucination attribution:

```python
from glassport.adapters.mcp_session import from_mcp_session_file

trace = from_mcp_session_file("~/.glassport/sessions/....jsonl",
                              server_name="exa-mcp-server")
trace.declared_tools()         # from the tools/list handshake
trace.called_tools()           # every tools/call on the wire
trace.fabricated_tool_calls()  # the delta
```

The adapter is deliberately dumb: it produces the faithful trace and nothing else. Detectors run on top and attach `Annotation` objects:

```python
from glassport.detectors import annotate

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
- ~~TUI: terminal interface for live session inspection and drift review~~ ✅ Built (`glassport tui`)
- ~~CI integration: JSON + SARIF export and a GitHub Action that uploads audit findings to the Security tab~~ ✅ Built (`audit --sarif`, `.github/workflows/ci.yml`)

---

## Project structure

```
glassport/
├── pyproject.toml            # packaging — `glassport` console script
├── glassport_tap.py          # back-compat shim for clone-and-run / MCP configs
├── src/glassport/
│   ├── tap.py                # M0: stdio proxy — the tap, gate, and CLI
│   ├── interaction_trace.py  # protocol-spanning data model
│   ├── detectors.py          # M2: analysis passes (incl. data exfiltration)
│   ├── report.py             # M3: HTML session renderer
│   ├── watch.py              # M4: behavioral drift
│   ├── audit.py              # static source audit (+ --sarif, suppression)
│   ├── sarif.py              # SARIF 2.1.0 export for code scanning
│   ├── server.py             # glassport as a queryable MCP server (`serve`)
│   ├── tui.py                # live curses session inspector
│   └── adapters/
│       └── mcp_session.py    # tap log → InteractionTrace
├── examples/
│   └── fake_server.py        # deliberately misbehaving test server
├── .github/workflows/ci.yml  # test matrix + audit → SARIF → Security tab
└── tests/
    ├── test_detectors.py
    ├── test_sarif.py
    ├── test_suppress.py
    ├── test_report.py
    ├── test_watch.py
    ├── test_gate.py
    ├── test_audit.py
    └── test_tui.py
```

---

*Glassport — Dennis J. Carroll · 2026*  
*"See what's inside before you open it."*
