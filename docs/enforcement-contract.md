# Enforcement contract by execution path

Glassport sees a call only when the client routes it through glassport. A
`tools/list` reply is a **server declaration**, not an authorization decision.
No path validates the caller's right to invoke a tool. The table describes
whether a `tools/call` can reach its upstream server; a client-visible error
alone is not evidence of a block. `tests/test_enforcement_contract.py` checks
upstream receipt for every row.

In the condition columns, **open** means glassport forwards the request when
that condition prevents a check; **closed** means it refuses locally before
upstream receipt. Independent checks can still block an otherwise open case.
`n/a` means the path does not perform that check. Transport failures can still
prevent delivery on a passive path; they are not policy blocks.

| Path | Enforced rules | Warned or analyzed only | Missing, stale, unknown declaration | Detector fault | Malformed body | Log failure | Block point | Persisted evidence | `--strict` / `--controllable` | Bypass control |
|---|---|---|---|---|---|---|---|---|---|---|
| `stdio-gate` | Declared-surface exclusion; severity-3 credential in params; taint; schema; retry; params size/depth; malformed or batch frames. `resources/read` reply quarantine. Attestation only through Python `Gate` API. | Egress and lower-severity PII; skipped-check markers. | Open for exclusion/schema after declaration hold; other checks still run. `--strict` closes missing-check cases. | Failed check open with marker; independent checks still run. `--strict` closes. | Closed while enforcing: unreadable line or batch never reaches child. | Block still enforced; failed log entry absent. | Before child stdin write; reply quarantine before client stdout. | Private session JSONL with `gate` blocked/injected/quarantine markers when writes succeed; no decision journal. | Both accepted; controllable override can disable gate. | Same-uid override file via `tui --gate-control`; direct server route also bypasses glassport. |
| `http-gate` | One policy rule: severity-3 fabricated `tools/call` against a current observed surface. Admission also refuses unreadable, oversized, incompatible, or ambiguous requests. | Taint, severity-3 PII, schema, retry, size/depth findings, egress; no reply quarantine. | Open for missing/partial, stale or unknown surface, and unproven modern scope. | Open if `NON_ENFORCEABLE` or diagnostic; other independent candidate findings stay recorded. | Closed by admission before upstream connect (400/413/415 and related refusals). | Open: `http_log_failed` disables policy enforcement, even for an otherwise proved exclusion. | Before `_connect` for policy block and admission refusal. | Per-epoch wire JSONL; journal profile, intent and terminal delivery (`http_gate_blocked`) when writes succeed. | Both flags refused over HTTP in this phase. | No runtime override. Client can bypass by contacting upstream URL directly. |
| `stdio-wrap` | None. | Offline detectors after capture. | n/a: open. | n/a: open. | Open: bytes relay unchanged. | Open; capture can be incomplete. | None. | Best-effort private session JSONL; no journal. | Neither applies. | Routing directly to server skips glassport. |
| `http-wrap` | None. | Offline detectors after capture. | n/a: open. | n/a: open. | No gate admission; forwards when transport framing can be relayed. | Open; capture can be incomplete. | None. | Best-effort session JSONL; no journal. | Neither applies. | Routing directly to upstream skips glassport. |
| `observe` | None; candidate `BLOCK` never enforced. | Incremental analysis and candidate verdict. | Open, including lost or unproven scope. | Open; fault recorded if possible. | No gate admission; forwards when transport framing can be relayed. | Open; journal or wire evidence can be incomplete. | None. | Per-epoch wire JSONL and decision journal intent/delivery, both best effort; `enforce:false`. | Neither applies. | Routing directly to upstream skips observation. |
| `probe` | None; client sends initialize and `tools/list` only. | Offline detectors and HTML report on its handshake. | n/a: no `tools/call` sent. | n/a for forwarding. | Probe constructs its own requests. | Probe may lack a report when no capture survives. | None. | Wrap-mode session JSONL and report if available; no journal. | Neither applies. | `--call` explicitly opts into a call; direct server route skips glassport. |
| `probe-call` | None; specified call uses passive `wrap`. | Offline detector finding for undeclared calls. | Open; declaration never authorizes or blocks this call. | n/a for forwarding. | Probe validates its CLI JSON; wrapper adds no gate. | Open; report may be incomplete. | None. | Wrap-mode session JSONL and report if available; no journal. | Neither applies. | Deliberately unmediated call; direct server route also skips glassport. |
| `direct-server` | None: glassport is absent. | None. | n/a. | n/a. | Server decides. | n/a. | None in glassport. | Nothing in glassport. | Neither applies. | This path itself bypasses glassport. |

## Consequences

- HTTP gate enforces one detector policy rule; stdio gate enforces roughly ten
  request conditions plus reply quarantine. Equal `gate` spelling does not
  imply equal enforcement.
- Logging failure has opposite enforcement effects: stdio keeps blocking;
  HTTP policy forwarding resumes after `http_log_failed`. A journal intent is
  an intended decision, while delivery says what the transport did.
- `probe --call` intentionally reaches the server even for an undeclared tool.
  Probe runs `wrap`; it is an evaluation client, not a gate.
- Stdio attestation enforcement exists only through `Gate(enforce_attestation=True,
  ...)`. CLI `gate --strict` does not enable it.
- A proxy can only mediate traffic routed through it. Neither the gate nor a
  registry result proves caller authorization, capture completeness, or
  upstream execution after delivery.
