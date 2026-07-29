# Glassport 0.6.10 Stabilization — Project Spec (hand-derived)

**Derived:** 2026-07-17 by the General (Fable 5) from the tested commit.
**Tested commit:** `0e2fb9d` (Merge PR #75, `release/0.6.10`) — tag `v0.6.10`.
**Branch:** `stabilization/0610` (harness/doc work only; one focused branch per confirmed production defect).
**Environment:** Linux (Pop!_OS kernel 7.0.11-76070011), Python 3.10.12, zsh.
**Worktree note:** `main` is checked out in `../glassport-kimi`; do not touch it. All work happens in this checkout on `stabilization/0610`.
**Named-SSE fix provenance:** commit `2c90ecb` — adds `_extract_sse_meta()` + `sse_meta` log field in `src/glassport/adapters/mcp_http.py`; regression test `tests/test_http_tap.py:313` (`test_named_sse_frames_are_parsed_and_tool_results_visible`).

---

## 1. Pre-registered outcome grid (verbatim from handoff; may be sharpened, never weakened)

| Outcome ID | Evidence | Interpretation | Required action |
|---|---|---|---|
| `READY` | All readiness gates pass; no unresolved P0/P1; seven-day period clean | Ready for 2–3 trusted testers | Prepare beta packet; request Dennis's go-ahead |
| `READY_LIMITED` | Core gates pass; only documented P2 limitations remain | Trusted beta acceptable with explicit limitations | Document exact limitation; request Dennis's go-ahead |
| `FIX_AND_REVERIFY` | Reproducible supported-path P1 without relay corruption or secret exposure | Not beta-ready; defect bounded | Focused fix task; independently reverify affected gate |
| `STOP_SECURITY` | P0: secret exposure, relay corruption, fabricated evidence w/ security consequence, fail-open safety boundary | Immediate stop | Preserve sanitized repro; notify Dennis; do not broaden |
| `STOP_INFRA` | Environment/package/server cannot be tested reproducibly | No product verdict possible | Report blocker + smallest resolution request |
| `DEMOTE_CLAIM` | Evidence contradicts README/status/compat claim but implementation safe | Product may work; claim too broad | Correct docs; re-run claim-relevant checks only |
| `DEFER_ARCH` | Observation requires streaming-detector or HTTP-enforcement redesign | Valid future work | RFC evidence only; do not implement |

Any result outside the grid pauses downstream work until the General adds a prospective interpretation.

**Severity ladder:** P0 stop / P1 block-beta-fix-narrowly / P2 document+batch / P3 defer.

---

## 2. Task table (DERIVE entries resolved to exact current paths)

| ID | Assignment | Tier | Exact writes | Reads (max 3) | Gate dep |
|---|---|---|---|---|---|
| `T01` | Baseline: full suite once, CI grill inventory, STATUS/README drift | Haiku-class | `dogfood/stabilization/baseline-0610.json`, ledger | `.github/workflows/ci.yml`, `STATUS.md`, `README.md` | none |
| `T02` | Clean PyPI install (`pip install --no-cache-dir glassport==0.6.10` in venv **outside checkout**), metadata, CLI help + one functional command, wheel-content check for named-SSE fix | Haiku-class | `dogfood/stabilization/package-smoke-0610.json`, ledger | `pyproject.toml`, `README.md` | none |
| `T03` | Compatibility harness + matrix schema + harness tests (tests-first, known-answer pinned) | Haiku-class | `dogfood/stabilization/compat_harness.py`, `dogfood/stabilization/test_compat_harness.py`, `dogfood/stabilization/compatibility-0610.json` (schema+empty matrix), ledger | `dogfood/driver.py`, `src/glassport/interaction_trace.py`, `README.md` | none |
| `T04` | Stdio matrix execution (≥3 distinct stdio servers, ≥2 clients incl. driver; clean + abrupt shutdown) | Haiku-class | `dogfood/stabilization/stdio-matrix-0610.json`, sanitized fixtures under `dogfood/stabilization/fixtures/`, checkpoint, ledger | `src/glassport/tap.py`, `dogfood/driver.py`, `dogfood/stabilization/compat_harness.py` | T03 L0 |
| `T05` | HTTP matrix: direct JSON ×1, unnamed SSE ×1, named SSE ×1, ≥3 server configs; clean + abrupt shutdown | Haiku-class | `dogfood/stabilization/http-matrix-0610.json`, sanitized fixtures, checkpoint, ledger | `src/glassport/adapters/mcp_http.py`, `dogfood/stabilization/compat_harness.py`, `dogfood/stabilization/compatibility-0610.json` | T03 L0 |
| `T06` | Canary/artifact safety: synthetic canaries client→server args and server→client results; text/JSON/HTML/advisory/SARIF renders; independent reconstruction check (must NOT reuse production normalization tables) | Haiku-class | `dogfood/stabilization/artifact-safety-0610.json`, `dogfood/stabilization/test_artifact_safety.py`, ledger | `dogfood/stabilization/compat_harness.py`, `dogfood/driver.py`, `dogfood/stabilization/fixtures/` (one named fixture) | T03 L0 |
| `T07` | Durability: detector/log failure isolation, abrupt client+server termination, malformed input bound, extended run 30–60 min or ≥100 calls, memory samples | Haiku-class | `dogfood/stabilization/durability-0610.json`, `dogfood/stabilization/durability-checkpoint.json`, ledger | `src/glassport/tap.py`, `src/glassport/adapters/mcp_http.py`, `dogfood/stabilization/compat_harness.py` | T03 L0 |
| `T08` | README-from-zero in clean venv; record every correction/ambiguity; sanitized publishable example bundle | Haiku-class | `dogfood/stabilization/readme-zero-0610.md`, `dogfood/stabilization/example-session/`, ledger | `README.md`, `src/glassport/tap.py`, `dogfood/stabilization/package-smoke-0610.json` | Gate A |
| `V1` | Independent package+matrix verification (closed schema) | Sonnet-class | `dogfood/stabilization/verify-package-matrix.json` only | aggregate outputs, own recompute script (scratch), this spec | T01–T05 |
| `V2` | Independent safety/durability + final gate (closed schema) | Sonnet-class | `dogfood/stabilization/verify-final.json` only | aggregate outputs, own recompute script (scratch), this spec | T06–T08 + 7-day log |

Parallelizable: {T01, T02, T03} (disjoint writes, no gate deps). T04/T05/T06/T07 after T03 L0; T04‖T05 (disjoint writes), T06‖T07 (disjoint writes). T08 after Gate A. No real credentials ever; a server needing credentials → `not_tested` with reason.

---

## 3. Reused-function manifest (copied verbatim from commit 0e2fb9d)

### Trace loading — `src/glassport/adapters/mcp_session.py`
```python
def from_mcp_session(
    log_lines: Iterable[str],
    server_name: str = "mcp_server",
    client_name: str = "mcp_client",
    user_intent: Optional[str] = None,
) -> InteractionTrace
def from_mcp_session_file(path: str | Path,
                          tail_cap_bytes: int | None = _USE_DEFAULT,
                          **kw) -> InteractionTrace
TAIL_CAP_BYTES = 50_000_000   # traces beyond cap ingest tail-only, metadata["tail_only"]=True
```

### Streaming — `src/glassport/adapters/streaming.py`
```python
class StreamingSession:
    def __init__(self, path: str | Path, tail_cap_bytes: int = TAIL_CAP_BYTES, **adapter_kw) -> None
    def poll(self) -> bool   # True when visible trace changed; rotation/truncation resets
    trace: InteractionTrace
```

### HTTP tap — `src/glassport/adapters/mcp_http.py`
```python
def run_http_tap(remote_url: str, log_dir: Path, bind: str = "127.0.0.1",
                 port: int = 0, *, ready: "threading.Event | None" = None,
                 server_box: "list | None" = None) -> None
def _extract_sse_meta(event: bytes) -> dict[str, str]   # captures event:/id:/retry: only
def _log_sse_event(event: bytes, log: SessionLog, *, partial: bool = False) -> None
def _stream_sse(resp, wfile, log: SessionLog) -> None
```

### Session log — `src/glassport/tap.py`
```python
class SessionLog                              # line 77
def open_session_log(path: Path) -> "SessionLog | None"   # line 179
# CLI verbs (tap.py main dispatch): summarize, detect, advise, serve, watch,
#   audit, tui, prune, health; tap transports: stdio (default) and http
```

### Detection — `src/glassport/detectors.py`
```python
def annotate(trace: InteractionTrace) -> list[Annotation]      # fault-isolated over DETECTORS
def data_exfiltration(trace: InteractionTrace) -> list[Annotation]
def _scan_pii(text: str) -> list[tuple[PIIPattern, str]]       # normalized, validated, deduped
def _redact(value: str, category: str) -> str                  # non-reversible tag
def _normalize_for_scan(text: str) -> str                      # invisible-strip + confusables + NFKC
DETECTORS = [fabricated_calls, context_violations, gate_actions, data_exfiltration, ...]
```

### Rendering
```python
# src/glassport/sarif.py
def render_sarif(report: Report, base: str = "") -> str
def render_session_sarif(trace, session_path: str = "", base: str = "") -> str
# src/glassport/advise.py
def render_advisory(report, annotations, *, min_severity: int = 2, base: str = "") -> str
def wrap_block(content: str) -> str
def splice_block(existing: str, content: str) -> str
# src/glassport/report.py
def render_html(trace: InteractionTrace, source_name: str = "") -> str
def report(log_path: str | Path, out_path: Optional[str | Path] = None, ...)
```

### Dogfood driver — `dogfood/driver.py`
```python
def run_session(
    name: str,
    cmd: list[str],
    calls: list[dict] | None = None,       # [{"name": str, "arguments": dict}]
    log_dir: Path = LOG_DIR,
    timeout: float = 30.0,
    env: dict[str, str] | None = None,
    protocol_version: str = "2025-06-18",
) -> SessionResult
@dataclass SessionResult: name, cmd, requests, responses, log_path, returncode, stderr, error
def summarize_log(log_path: Path) -> dict
def detect_log(log_path: Path) -> dict
def _rpc(rid: int | None, method: str, params: dict[str, Any] | None = None) -> dict
```

### Findings ledger — `dogfood/stabilization/ledger.py` (Phase-0 helper, tested)
```python
def upsert_finding(ledger_path: Path, finding: dict) -> None   # atomic tmp+rename, validate-before-write, idempotent by id
def load_ledger(ledger_path: Path) -> dict                     # validates schema, raises ValueError on corruption
REQUIRED_FIELDS = ("id", "title", "status", "severity", "metrics",
                   "provenance", "depends_on", "explanation")   # optional: chart_data
# status ∈ {"provisional", "verified"}; only the General flips to "verified"
```

---

## 4. Known-answer cases for verdict-feeding helpers

| Helper | Known-answer test | Status |
|---|---|---|
| `_extract_sse_meta` / named-SSE framing | `tests/test_http_tap.py:313` named-event frames → parsed JSON-RPC + tool-result correlation | **exists** (shipped with fix 2c90ecb) |
| `_redact` non-reversibility | `tests/test_detectors.py::test_redaction_is_non_reversible` | **exists** |
| `_scan_pii` validators (Luhn/SSN/entropy/IBAN/base58/jwt) | `tests/test_checksums.py`, `tests/test_crypto_tokens.py` (hand-computed vectors) | **exists** |
| `splice_block` idempotence/malformed markers | `tests/test_advise.py` | **exists** |
| `run_session` request/result correlation | none (driver exercised only via eval scripts) | **OPEN RISK** → T03 must pin known-answer harness tests before any gate relies on driver output |
| ledger `upsert_finding` | `dogfood/stabilization/test_ledger.py` (hand-computed upsert/idempotence/corruption cases) | created in Phase 0 |

Inline known-answer for T03 (verbatim expectations):
- `_extract_sse_meta(b"event: message\nid: 7\ndata: {\"jsonrpc\":\"2.0\"}")` → `{"event": "message", "id": "7"}`.
- A `tools/call` with `id=6` must correlate to the response frame with `id=6`; harness must assert count(requests with method=tools/call) == count(correlated results) on the happy path.

---

## 5. Verification gates (junctures, oracle rules)

- **Gate A** (after T01+T02, L0/L1 by General): full suite pass count recorded; all 9 CI grills pass; PyPI metadata == `0.6.10`; CLI help + one functional command in clean venv; installed wheel's `adapters/mcp_http.py` contains `_extract_sse_meta` and `sse_meta` (content, not version string). Fail → `STOP_INFRA` / `FIX_AND_REVERIFY` / `DEMOTE_CLAIM`.
- **Gate B** (after T03–T05, L2 = V1): coverage minimums — 2 clients, 3 stdio servers, 3 HTTP configs, direct JSON 1, unnamed SSE 1, named SSE 1, clean+abrupt shutdown both transports. Per-run record: version, transport, framing, call count, lifecycle, sanitized result. V1 recomputes completeness+correlation from aggregates/fixtures **without production expectations as oracle** (hand-parses fixture JSONL itself).
- **Gate C** (T06, feeds V2): canaries both directions; expected findings occur; no rendered artifact (text/JSON/HTML/advisory/SARIF) contains a reconstructable canary. Independent reconstruction check must not import production normalization/redaction tables — it builds its own recombination attempts (concatenation of adjacent rendered fragments, entity-decode, zero-width strip written from spec). Supported-path reconstructable leak = P0 `STOP_SECURITY`.
- **Gate D** (T07, feeds V2): kill-detector/kill-logger cannot kill healthy traffic; abrupt termination leaves earlier complete records parseable; malformed input bounded; extended run completes; memory samples recorded as observations only.
- **Gate E** (T08 + 7-day owner log, L2 = V2): README followed literally in clean env; every friction recorded; sanitized example bundle publishable; Dennis logs 7 calendar days of normal use (date, client/server, transport, rough call count, anomalies, disposition — no manufactured activity). V2 emits final closed-schema verdict.

Verifier closed schema (both V1, V2): exactly the JSON object from handoff §11; guards `independent_oracle, supported_path, relay_invariant, artifact_safety, ledger_valid, known_answer_tests`. Any failed guard demotes the headline; General cannot override without signed caveat finding + Dennis's direction.

---

## 6. Budgets and checkpoints

| Item | Budget |
|---|---|
| Package smoke (T02) | 15 min |
| Harness creation (T03) | 30 min |
| Each compatibility configuration (T04/T05) | 10 min or 25 calls |
| Abrupt-shutdown case | 5 min |
| Extended run (T07) | 30–60 min or ≥100 calls; checkpoint every 25 calls to `durability-checkpoint.json` |
| New executor test file | run once before impl, once after |
| Full suite | once per phase end (General), never per task |
| Retry | max 1 automated retry, then classify failure |

Checkpoints: after every server/configuration and every 25 calls; resume must not duplicate ledger findings (upsert by id guarantees this).

---

## 7. Premortem — named mitigations

| Risk | Mitigation |
|---|---|
| Package/index version conflict | T02 uses fresh venv + `--no-cache-dir` + `pip show` exact-version assert before anything else |
| Local checkout shadowing PyPI install | T02 venv created in `/tmp/claude-1000/...scratchpad/venv-0610`, cwd set outside checkout, `python -c "import glassport, inspect; print(inspect.getfile(glassport))"` asserted to point at site-packages |
| Client/server version drift | Every matrix row records client+server exact versions; `protocol_version` pinned "2025-06-18" in driver |
| SSE framing differences | Three framings tested separately (direct JSON / unnamed SSE / named SSE); fixture per framing; known-answer `_extract_sse_meta` case inline |
| Request/result correlation mismatch | T03 pins correlation known-answer test before matrix runs (closes the OPEN RISK above) |
| Unbounded result-set/log growth | Extended run caps at 60 min/100 calls; log size sampled at checkpoints; `TAIL_CAP_BYTES` documented behavior, not re-tested |
| Threshold/time flakiness | No wall-clock assertions in harness tests; lifecycle asserted on events, not timing; single retry rule |
| Raw-log/canary exposure | Only sanitized fixtures enter git; canaries are synthetic (`GLASSPORT-CANARY-...` style, accepted by existing test conventions); chat summaries carry aggregates only |
| Findings-ledger corruption | `ledger.py`: atomic tmp+rename, validate-before-write, idempotent upsert; tested Phase 0 |
| Shared helper fooling producer and verifier | V1/V2 hand-parse raw fixtures; forbidden from importing production normalization/redaction/correlation code as oracle |
| Executor needs 4th read file | Executor reports `SPEC_INCOMPLETE`, stops; General fixes dispatch |
| Real-server access needing credentials | Marked `not_tested` + reason; never obtain credentials |
| Task mutating production source during observation work | Write lists exclude `src/`; any `src/` diff in an executor's task = write-list violation = stop condition |

---

## 8. Cache-stable executor block

Byte-identical preamble for every executor dispatch this phase (handoff §7 text), followed by the full §3 manifest, then task-specific block. Stored canonically here; General copies verbatim.

```text
You are an executor under the general-orchestration protocol.
Use only the exact write list and at most the three listed read files.
If a fourth read is required, stop and report SPEC_INCOMPLETE.
Write tests first. Run only the new test file during this task.
Do not run the full suite; the General runs it once at phase end.
Do not explore unrelated code, issues, Unicode blocks, or protocols.
Do not use real secrets or commit raw real-session logs.
Preserve relay byte fidelity, ordering, liveness, and failure isolation.
Use the shared manifest signatures exactly as supplied.
Checkpoint long runs and obey the stated call/time budget.
Append findings atomically and return only a 5–10-line summary.
```

Required end-summary format: TASK / COMMIT-ENV / TESTS / CASES / KEY NUMBERS / FINDINGS / FILES WRITTEN / BLOCKER-NEXT (handoff §8).

---

## 9. Stop conditions (verbatim ladder)

P0; credential need; merge/release/tag/deletion/invite needs Dennis; write-list violation; ledger validation failure; verifier guard failure; missing test environment without safe substitute; two failed escalations; scope creep into streaming implementation, broad Unicode hunting, or unsupported protocols. Otherwise continue autonomously to next registered gate.
