# Runtime-annotation SARIF — design

**Roadmap item:** #1 (STATUS.md Tier 3). **Date:** 2026-06-23.

## Problem

`sarif.py:render_sarif(report)` exports the **static audit** (`Report` of
`Finding`s) to SARIF 2.1.0. The runtime side — detector `Annotation`s over an
`InteractionTrace` — has no SARIF path, so behavioral findings (fabricated
calls, data exfiltration, drift) never reach a SARIF consumer.

The obstacle: SARIF results want a **physical location** = file + line. A
`Finding` has that (`path` + `line` into source). An `Annotation` does not — it
carries `event_id` / `seq`, which address a wire event in a **session `.jsonl`
log**, not a line of source code.

## Decisions

- **Consumer:** generic SARIF file / CI tooling — *not* the GitHub diff-annotation
  Security tab. This frees runtime results to locate honestly into the session
  log rather than faking repo-file URIs (the same dishonesty `render_sarif`
  already refuses).
- **Location model:** real `physicalLocation` into the `.jsonl` — `artifactLocation.uri`
  = session log path, `region.startLine` = the event's line in that log. `seq`
  rides in `partialFingerprints` for stable identity across re-runs.
- **Structure:** two render functions, shared core. Keep `render_sarif` for the
  audit; add `render_session_sarif`. Factor the common SARIF envelope out.
- **CLI:** `glassport summarize <session>.jsonl --sarif`.
- **Gate INFO records** (`gate_blocked`, `gate_injected_response`): **included**
  as `note`-level results — complete, honest record; consumers filter by level.

## Components

### 1. Shared envelope (`sarif.py` refactor)

Extract from the current `render_sarif`:

```
_sarif_document(rules: list[dict], results: list[dict], props: dict) -> str
```

Builds the `$schema` / `version` / `runs[0]` shell with the `glassport` driver.
Both renderers call it. `_sarif_level` is already int+str aware — no change.
This is a targeted tidy of code we're already in, not a speculative refactor.

### 2. Location data (`adapters/mcp_session.py` change)

The adapter already reads the log line by line. While parsing, record each
event's 1-based source line in `event.metadata["line"]`. This is the only new
*data* the feature needs; everything else derives from it.

- `seq` stays as-is (logical ordering); `line` is the physical address.
- If `line` is ever absent (older traces, hand-built), fall back to `startLine: 1`.

### 3. `render_session_sarif(trace, session_path) -> str`

```
render_session_sarif(trace: InteractionTrace, session_path: str = "") -> str
```

- Iterate `trace.annotations`.
- **Rule object** per distinct `subcategory`, mirroring `_rule_object`:
  - `id = glassport/<subcategory>`
  - `shortDescription` from a small `subcategory → text` map, falling back to the
    humanized subcategory (`"fabricated_tool_call"` → `"Fabricated Tool Call"`).
  - `defaultConfiguration.level` = `_sarif_level(severity)`.
  - tags: `["glassport", "runtime", <kind>]` where `kind` is the
    `AnnotationKind` (anomaly / divergence / hallucination / info).
- **Result** per annotation:
  - `ruleId = glassport/<subcategory>`, `level = _sarif_level(a.severity)`
  - `message.text = a.explanation`
  - `physicalLocation`: `uri = session_path`,
    `region.startLine = max(1, event_line(a.event_id))`
  - `partialFingerprints.glassportSeq = "<subcategory>:<seq>"`
  - `properties`: `severity` (int), `kind`, `subcategory`
- Gate INFO annotations included (their int severity already maps to `note`).
- `props` on the run: e.g. `{"session": <log filename>, "annotation_count": N}`.

### 4. CLI (`tap.py`)

`summarize` already routes through `from_mcp_session` + `annotate`. Add a
`--sarif` flag that, when present, prints `render_session_sarif(trace, path)`
instead of the human summary. Mirrors `audit --sarif`.

## Data flow

```
session.jsonl
  → from_mcp_session_file()         # now stamps event.metadata["line"]
  → InteractionTrace (+ annotations via annotate())
  → render_session_sarif(trace, path)
  → SARIF 2.1.0 JSON  (results located into the .jsonl)
```

## Testing (`tests/test_session_sarif.py`)

Drive the **real adapter** (existing doctrine — no hand-built traces):

- valid SARIF 2.1.0 envelope (schema, version, single run, driver name)
- int severities 1/2/3 → `note` / `warning` / `error`
- a result's `region.startLine` equals the annotation's event's real line in the
  `.jsonl`
- `seq` present in `partialFingerprints`
- gate INFO record emitted at `note` level (not dropped)
- distinct `subcategory`s each yield one `reportingDescriptor`
- CLI: `summarize <session> --sarif` prints parseable SARIF

## Out of scope

- GitHub Security-tab upload for runtime SARIF (consumer is generic files).
- Merging runtime + audit findings into one document (two artifacts, two verbs).
- Streaming (detectors still consume a full in-memory trace — roadmap #5).
