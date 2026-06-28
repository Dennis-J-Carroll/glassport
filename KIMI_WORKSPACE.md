# Kimi workspace — isolated worktree

This is a **separate git worktree** of glassport, on branch `kimi/eval`
(tracking `origin/kimi/eval`). It shares the repo history with the main
checkout but has its own files, so work here cannot collide with another
agent editing the main checkout. Branched from `main` at v0.4.0.

## Rules (learned the hard way)

- **Commit early and often** to `kimi/eval`. Uncommitted edits live only in the
  working tree and can be destroyed by a `git reset --hard` elsewhere — they are
  not recoverable from git. Committed work always is.
- **Write findings to a session doc** (e.g. `kimi_session_02.md`) as you go and
  commit it. The previous session's doc is what made a full recovery possible.
- **Stay in this directory.** Don't edit the main checkout
  (`../glassport`) — that's the other agent's tree.
- Push when you want a remote backup: `git push` (already tracking).
- When done, open findings as a PR from `kimi/eval` → `main`, or hand the branch
  back for the brainstorm → spec → plan pipeline.

## High-leverage evaluation targets

1. **Real-world dogfooding** — run `glassport audit` + `wrap`/`tap` against
   actual public MCP servers (`@modelcontextprotocol/server-*`, exa, etc.) and
   report what it finds. Synthetic tests prove robustness; real servers prove
   usefulness.
2. **Coverage backfill** — `tui.py` (~50%), CLI/signal paths in `tap.py` /
   `server.py` / `watch.py`.
3. **ReDoS fuzz of all PII patterns** — benchmark every pattern against ~1 MB of
   adversarial text (the email one was already fixed; find the rest).
4. **Batch-detector stress** — measure where the full-in-memory trace model
   strains on huge sessions; informs the streaming-detector roadmap item.

## Round 3 (current)

This worktree was advanced from 0.4.0 to **current `main` (0.5.0 + the PII
plugin-registry / validator-menu work)**. The round-3 testing brief is
[`KIMI_ROUND3_PROMPT.md`](KIMI_ROUND3_PROMPT.md) — the target surface is the new
custom-PII-pattern registry, the 10-name validator menu, the opt-in packs
(`examples/pii-*.json`), and the now-validator-gated `jwt_token`. The mission is
to measure **precision on real traffic** (FP rate against UUIDs/hashes/base64)
and **recall with honeytokens** (not obvious fakes), and to attack the
fail-safe env-autoload path.

Current state: glassport **0.5.0** + PII registry/menu; worktree at `main` HEAD,
314 tests green.
