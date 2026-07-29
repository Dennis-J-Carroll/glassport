# 7-Day Owner Log — Step-by-Step Guide (Gate E, glassport 0.6.10)

**Purpose:** Gate E evidence. Seven calendar days of *normal* use, honestly logged.
V2 (the final verifier) reads this log to decide READY vs READY_LIMITED vs NOT READY.
An empty day is valid evidence. A manufactured session is invalid evidence.

---

## 0. One-time setup (5 minutes, day 0)

1. Use the **published package**, not the checkout — the beta testers will get PyPI, so you dogfood PyPI:
   ```bash
   python3 -m venv ~/.venvs/glassport-0610
   ~/.venvs/glassport-0610/bin/pip install --no-cache-dir glassport==0.6.10
   ~/.venvs/glassport-0610/bin/glassport --help   # sanity: exit 0
   ```
   (Optional: `alias gp610=~/.venvs/glassport-0610/bin/glassport` in your shell rc.)
2. Create the notes directory (already gitignored territory — raw notes never get committed):
   ```bash
   mkdir -p ~/Desktop/projects/GLASSPORT/glassport/dogfood/stabilization/owner-log
   ```
3. Copy the template below into `owner-log/day-0-notes.md` so it's in front of you.

## 1. What "normal use" means

- Wrap MCP servers you'd *actually* use this week with the tap (stdio or HTTP), during real work: Claude Code sessions, tool experiments, whatever you'd do anyway.
- Any client counts (Claude Code, mcp CLI, SDK scripts) — just record which.
- **Do NOT invent sessions to fill quiet days.** "2026-07-19: no MCP use today" is a perfectly good log line and V2 treats it as such.
- Do not use real credentials/secrets as test payloads. Normal traffic that happens to flow is fine — that's the tool's job — but don't plant secrets.

## 2. Per-session record (30 seconds, right after each session)

Append one block per tapped session to that day's notes file. Six fields:

```
### session <n>
date:        2026-07-19
client:      claude-code 2.x        # whatever drove the calls
server:      mcp-server-fetch 2026.7.10   # product + version if known
transport:   stdio | http           # + framing if http and you noticed (direct/sse)
calls:       ~12                    # rough count is fine; `glassport summarize <log>` gives it exactly
anomalies:   none                   # or short description (see §3)
disposition: fine | annoying | broken   # your gut verdict + one clause why
```

Fast call count when you want it exact:
```bash
gp610 summarize <session-log.jsonl>     # counts land in the summary
```

## 3. When something looks wrong (anomaly triage, 2–5 minutes)

1. Write what you *saw* first, in one sentence, before investigating ("summarize hung", "call visible in client but missing from log", "detect flagged X and it looks bogus").
2. Grade it yourself, loosely:
   - traffic corrupted/killed, secret in an artifact → **P0-suspect** — stop, keep everything, tell me immediately;
   - supported path gave wrong/missing observation → **P1-suspect**;
   - worked but fought you → **P2**; cosmetic → **P3**.
3. Preserve the evidence: copy the session log *into* `owner-log/anomalies/` (this dir stays out of git; I sanitize before anything is committed):
   ```bash
   mkdir -p .../owner-log/anomalies && cp <log> .../owner-log/anomalies/day3-s2.jsonl
   ```
4. Note the exact command you ran and glassport's exact output line (copy-paste, don't paraphrase).
5. Keep using the tool normally afterward unless it's P0-suspect.

## 4. Daily close-out (1 minute)

End of day, add one line at the top of the day's file:
```
DAY 3 — sessions: 2, anomalies: 0, days remaining: 4
```
No sessions? Create the file anyway with `DAY 3 — no MCP use today`. That keeps the seven-day record continuous and honest.

## 5. What NOT to do (V2 will check)

- No manufactured traffic, no padding quiet days, no rerunning a session "to make it log cleaner" (rerun is fine for *your* work; just log it as another session).
- No raw logs into git; no secrets/usernames into notes (`~` instead of `/home/<you>`).
- Don't fix defects mid-week — log them; fixes go through the FIX_AND_REVERIFY path after V2, per the handoff.
- Don't convert one good day into a claim ("it's fast now") — observations only; I'll do the aggregation.

## 6. Day 7: hand-off (1 minute)

Tell me the week is done. I will: structure your notes into the ledger, dispatch V2 (final closed-schema verdict over Gates C/D/E + the week), write the §13 final report, and — on READY/READY_LIMITED — assemble the trusted-beta packet for your go-ahead.

---

### Blank day-file template

```markdown
DAY <n> — sessions: <n>, anomalies: <n>, days remaining: <n>

### session 1
date:
client:
server:
transport:
calls:
anomalies:
disposition:
```
