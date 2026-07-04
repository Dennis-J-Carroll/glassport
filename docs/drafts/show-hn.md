# Show HN draft — post when the survey (scripts/audit_top_servers.py) has numbers

> **Title:** Show HN: Glassport – see what an MCP server actually does
> before you trust it
>
> (title alternatives, pick one:)
> - Show HN: I taped a wiretap to my MCP servers. Here's what they said
> - Show HN: Zero-dep MITM for MCP – catch fabricated tool calls on the wire

---

MCP has 10k+ community servers now. You install one, hand it your API
keys, and wire it straight into your agent — and there is basically no
tooling that shows you what it *actually does* on the wire, as opposed
to what its README says.

Glassport is a passive stdio man-in-the-middle for MCP. One line in your
client config wraps any server:

    "command": "glassport",
    "args": ["--", "npx", "exa-mcp-server"]

Every JSON-RPC frame lands in an append-only JSONL log, and offline
analysis surfaces the gap between what the server *declared* in
`tools/list` and what it *did* in every `tools/call` after:

- **Fabricated tool calls** — a call to a tool that was never declared
  (this is the demo GIF: `glassport summarize` flagging an undeclared
  `arxiv_lookup` call at severity 3)
- **Credential/PII exfiltration** — 11 categories with checksum
  validators (Luhn, IBAN MOD-97, base58check), homoglyph- and
  zero-width-evasion-resistant
- **Behavioral drift** — the server that quietly starts calling a new
  host on Tuesday

Design choices HN might care about:

- **Zero runtime dependencies.** Stdlib only, Python 3.10+. Runs on
  Termux and air-gapped boxes. A security tool that audits supply-chain
  risk shouldn't ship its own dependency tree.
- **The relay is sacred.** Logging is best-effort and can never alter,
  delay, or kill a live session. The tap is dumb: it records bytes,
  judgment happens offline and is re-runnable as detectors improve.
- **It red-teams itself.** CI runs adversarial grills that attack the
  tool's own renderers (prompt-injection via tool descriptions,
  homoglyph secrets, fence-breakout in generated advisories). A fixed
  bypass becomes a permanent regression gate.
- **Enforcement is opt-in.** `glassport gate` blocks calls outside the
  declared surface, fails open *visibly*, and is deliberately not the
  default. Observe first, enforce later.

Numbers from the static survey of the [N] most-starred MCP servers
(method + repo list in the post): **[X]%** carried hardcoded secrets,
**[Y]%** tool-poisoning patterns in tool descriptions, **[Z]%** shell
injection paths. Full data: [survey link].

It's MIT, on PyPI (`pip install glassport`), ~6.5k LOC, 500+ tests.
I'd particularly value adversarial eyes on the detector evasion surface
— the grills in `dogfood/` document every bypass found so far.

https://github.com/Dennis-J-Carroll/glassport

---

**Posting checklist (from the GQM plan):**
- [ ] Run `scripts/audit_top_servers.py` over the top-100 list; fill [N]/[X]/[Y]/[Z]
- [ ] Publish survey markdown (gist or repo `docs/`) and link it
- [ ] Record the fabricated-call GIF (`glassport tui` on the example session)
- [ ] Post blog + HN the same day; Reddit r/LocalLLaMA + r/cybersecurity next day
- [ ] Have `good-first-issue` tickets open before the post lands
