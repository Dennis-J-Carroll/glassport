# Security Policy

glassport is a security tool, so this document is load-bearing: it states
what the tool defends against, what it deliberately does not, and how to
report the difference when we get it wrong.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** (Security tab → "Report a
vulnerability") on this repository. Reports go to the maintainer privately;
you should hear back within 72 hours. Please do not open public issues for
suspected vulnerabilities in the detectors, the gate, or the renderers —
a detector bypass is exactly the kind of thing that deserves a quiet fix
and a red-team grill before disclosure.

If the report concerns attacker-controlled bytes escaping into a rendered
surface (HTML report, SARIF, advise block, TUI), include the exact input
bytes. Every fixed escape becomes a permanent row in a
`dogfood/eval_*_redteam.py` grill, and the grills gate merges and releases.

## Threat model

The doctrine — *observe first, enforce later; the relay is sacred; assert
only what the wire proves* — implies a specific trust posture:

**In scope (glassport defends against these):**

- **A hostile MCP server.** Everything on the wire is attacker-controlled:
  tool descriptions, results, error strings, unicode tricks, oversized
  payloads. Detectors, renderers, and the TUI treat every wire byte as
  hostile; renderer poisoning-resistance is grill-tested (P1–P11).
- **A hostile MCP client on the `serve` wire.** The `serve` tools confine
  client-supplied paths: `session_path` to the log directory,
  `audit_server`'s `path` to `--allow-audit-root` (default: cwd,
  default-deny). Symlinks are resolved before containment checks;
  client-supplied `~` is never expanded.
- **Cross-uid and cross-process attackers.** Session logs and the gate
  override file are written with owner-only permissions (0o600, atomic
  replace). The gate's reader is fail-closed: any loosening of
  permissions, malformed JSON, or unicode error leaves enforcement ON.
- **Regex-based denial of service.** Detector patterns scan
  attacker-controlled bytes; PII patterns are ReDoS-bounded (structural
  character-class fixes plus input caps), locked by timing tests.

**Out of scope (deliberately):**

- **A same-uid local attacker.** Anything running as your user can already
  read your session logs, rewrite the override file, or replace the
  glassport binary itself. No same-uid isolation is claimed; the
  `--controllable` gate override file is a same-uid bypass by design
  (it exists so *you* can flip enforcement from the TUI).
- **Adversarial isolation by the gate.** The gate prevents *accidents* —
  calls outside the declared tool surface — and fails open **visibly**
  (synthesized errors carry `{"glassport": "gate_blocked"}`). It is not a
  sandbox; a malicious server that lies in its `tools/list` gets the lie
  recorded, not contained.
- **The content of what a permitted tool call does.** glassport observes
  and judges the wire. It does not execute, sandbox, or patch the server.

**Doctrinal consequence:** "observe first" means the tap never trusts the
wire to be honest — but it does trust it to be *evidence*. The tap logs
raw bytes verbatim; judgment happens offline in detectors that cannot
mutate the record. A detector bug can therefore never corrupt the wire
record, and the record can be re-analyzed as detectors improve.

## Supported versions

Only the latest minor release receives fixes. Zero runtime dependencies
means there is no transitive CVE surface to patch; a `pip install -U
glassport` is always the remediation path.

## What we ask of integrators

- Treat `~/.glassport/sessions/` as sensitive: logs contain full wire
  traffic, which may include whatever your MCP servers saw.
- Run `glassport audit` output through the Security tab (SARIF) rather
  than pasting findings into agent-readable files by hand; `glassport
  advise` exists for that and sanitizes attacker-controlled values.
