"""
watch.py — M4: behavioral drift across sessions.

One session tells you what a server did; a run of sessions tells you
when it changed. fingerprint() reduces a trace to the facts worth
comparing — declared surface, schema hashes, called tools, hosts seen
in wire traffic, server-initiated request methods, server identity.
drift() compares a new fingerprint against the merged baseline of every
prior session and reports only novelty: "this server started calling a
new domain on Tuesday."

Deliberately stateless: there is no fingerprint store to corrupt or
invalidate. The baseline is rebuilt from the session logs on every run,
so every drift claim is traceable to a .jsonl file on disk.

Layering: fingerprints derive from the trace alone and never run
detectors. Detectors judge one session against its own handshake; watch
judges a session against the server's own history. A call can be clean
per-session and still be drift.

Severity reuses the detector scale: 1 = worth a look, 2 = should not
happen, 3 = hostile or hallucinated unless proven otherwise.

    python3 watch.py [~/.glassport/sessions] [--json]

Exit code 1 when drift of severity >= 2 is present (cron-friendly).

PLAY-BY-PLAY
------------
The shape of the file is a pipeline, and the order of its stages is the
argument:

1. `fingerprint()` turns one session into a flat, JSON-able summary: which
tools were declared, hashes of their input schemas, which were called and
how often, which hosts appear in the traffic, which requests the server
started, and who the server says it is.
2. `watch_paths()` reads every log, groups the fingerprints per server, sorts
   each group by time, then replays them.
3. `drift()` answers one question per session: what is here that has never
   been here before? `merge()` then folds the session into the baseline.
   That order is deliberate -- compare against history, *then* become
history, so a session is never its own evidence.
4. `main()` renders and exits 1 on any severity-2 drift.

The vocabulary to learn before the findings make sense:

* A *baseline* is the union of everything this server has ever been observed
doing. It lives in memory, rebuilt from the logs each run, with nothing to
corrupt and nothing to expire.
* *Drift* is novelty relative to that baseline, not misbehavior. A new host
is not an attack; it is a change that someone should look at.
* Jensen-Shannon divergence (`_jsd`) compares the *shape* of tool-call
usage, so a session that suddenly pivots from reading files to posting data
reads as a change even though every individual call is familiar.

WHAT THIS FILE DOES NOT DO
--------------------------
It never runs detectors and never judges a session on its own. It also
never stores a baseline on disk: if a log is deleted, the drift it produced
is gone with it.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from glassport.interaction_trace import InteractionTrace, PartKind

FINGERPRINT_VERSION = "0.1"
DEFAULT_LOG_DIR = Path.home() / ".glassport" / "sessions"

# hostnames inside URLs anywhere in tool-call arguments or results
_URL_HOST = re.compile(r"https?://([^/\s\"'<>\\]+)", re.IGNORECASE)


@dataclass
class Drift:
    session: str        # source log file name
    kind: str
    severity: int
    explanation: str
    detail: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────
# Fingerprint — one session reduced to its comparable facts.
# ─────────────────────────────────────────────────────────────────
# PLAY: Hashing the schema is what makes schema comparison possible at all;
# two JSON objects with the same meaning but different key order must not
# read as a change. sort_keys and the tightest separators give one canonical
# byte string, and 12 hex characters is plenty to distinguish real edits.
def _schema_hash(schema) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"),
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _hosts_in(content) -> set[str]:
    """Hostnames of URLs appearing anywhere inside a JSON-able value."""
    # PLAY: This is deliberately a blunt regex over the serialized value and
    # not a parser. The goal is not to understand the traffic, it is to
    # notice a hostname that has never appeared before -- and an attacker
    # choosing the argument shape should not be able to hide a URL from a
    # walk that does not care about shape.
    blob = json.dumps(content, ensure_ascii=False, default=str) \
        if not isinstance(content, str) else content
    hosts = set()
    for netloc in _URL_HOST.findall(blob):
        host = netloc.rsplit("@", 1)[-1]          # strip userinfo
        host = host.rstrip(".,;:)]}\"'")          # strip trailing punctuation
        if host:
            hosts.add(host.lower())
    return hosts


def _jsd(p_counts: dict[str, int], q_counts: dict[str, int]) -> float:
    """Jensen-Shannon Divergence, base 2, bounded [0, 1]. See
    APPENDIX.md §6 for the derivation. 0.0 = identical distributions,
    1.0 = disjoint support."""
    # PLAY: JSD rather than a plain histogram diff because it is symmetric,
    # bounded, and does not blow up when a tool name appears in one side and
    # not the other (KL would go to infinity). One thin helper `kl()` does the
    # real work; the rest is normalising two count maps onto a shared
    # vocabulary and averaging against the midpoint distribution.
    vocab = sorted(set(p_counts) | set(q_counts))
    if not vocab:
        return 0.0
    p_total = sum(p_counts.values()) or 1
    q_total = sum(q_counts.values()) or 1
    p = [p_counts.get(k, 0) / p_total for k in vocab]
    q = [q_counts.get(k, 0) / q_total for k in vocab]
    m = [(pi + qi) / 2 for pi, qi in zip(p, q)]

    def kl(a: list[float], b: list[float]) -> float:
        total = 0.0
        for ai, bi in zip(a, b):
            if ai <= 0.0 or bi <= 0.0:
                continue
            total += ai * math.log2(ai / bi)
        return total

    return (kl(p, m) + kl(q, m)) / 2.0


# PLAY: The threshold is a judgment call held in one place, next to its
# explanation. JSD_MIN_CALLS keeps short sessions from scoring: five calls on
# each side is the minimum where a distribution means anything at all.
JSD_DRIFT_THRESHOLD = 0.15
JSD_MIN_CALLS = 5   # minimum total calls on both sides before scoring


def _event_time(value) -> datetime | None:
    """Parse a log timestamp without trusting its JSON type or format."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _premature_list_changed(trace: InteractionTrace) -> bool:
    """Compare each server notification with its preceding declaration.

    Replay in wire order: later refreshes cannot erase an earlier finding,
    and omitted/invalid TTLs replace, rather than inherit, the old window.
    Only responses paired with tools/list establish a cache window.
    """
    # PLAY: The MCP cache contract, in one sentence: a tools/list response may
    # carry a ttlMs telling clients how long they may reuse the list, and a
    # list_changed notification tells them to refresh. A server that fires
    # list_changed *before* its own TTL expires is either confused about its
    # own cache or trying to force clients to re-read a surface early. This
    # walk tracks the last valid window and flags the first premature fire.
    base, ttl_ms = None, None
    for e in trace.events:
        if e.metadata.get("method_replied_to") == "<tools/list>":
            for part in e.parts:
                if part.kind != PartKind.JSON or not isinstance(part.content, dict):
                    continue
                result = part.content.get("result")
                if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                    continue
                candidate = result.get("ttlMs")
                valid = (isinstance(candidate, (int, float))
                         and not isinstance(candidate, bool) and candidate > 0
                         and (not isinstance(candidate, float) or math.isfinite(candidate)))
                base = _event_time(e.timestamp)
                ttl_ms = candidate if valid else None
                break
        if (e.metadata.get("method") != "notifications/tools/list_changed"
                or not e.metadata.get("server_initiated")
                or not e.metadata.get("notification")):
            continue
        fired = _event_time(e.timestamp)
        if base is None or ttl_ms is None or fired is None:
            continue
        try:
            elapsed_ms = (fired - base).total_seconds() * 1000
        except TypeError:
            # Mixed offset-aware/naive timestamps do not prove elapsed time.
            continue
        if 0 <= elapsed_ms < ttl_ms:
            return True
    return False


def _schema_fields(schema: dict) -> tuple[dict, list] | None:
    """(properties, required) with null treated as absent, or None if malformed."""
    props = schema.get("properties")
    required = schema.get("required")
    props = {} if props is None else props
    required = [] if required is None else required
    if not isinstance(props, dict) or not all(
            isinstance(spec, (dict, bool)) for spec in props.values()):
        return None
    if not isinstance(required, list) or not all(
            isinstance(name, str) for name in required):
        return None
    return props, required


def _classify_schema_change(old: dict | None, new: dict | None) -> str:
    """additive: new optional properties, nothing removed or narrowed.
    mutative: a property removed, an existing property's declared type
    or boolean schema changed, a new required field appeared, or the new
    schema's properties/required fields are malformed (so malformation
    cannot lower a change's severity).
    unknown: a malformed baseline or not enough information."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return "unknown"
    old_fields = _schema_fields(old)
    if old_fields is None:
        return "unknown"
    new_fields = _schema_fields(new)
    if new_fields is None:
        return "mutative"
    (old_props, old_required), (new_props, new_required) = old_fields, new_fields
    if set(old_props) - set(new_props):
        return "mutative"
    for key, old_spec in old_props.items():
        new_spec = new_props[key]
        if isinstance(old_spec, bool) or isinstance(new_spec, bool):
            if old_spec != new_spec:
                return "mutative"
        elif old_spec.get("type") != new_spec.get("type"):
            return "mutative"
    if set(new_required) - set(old_required):
        return "mutative"
    if set(new_props) - set(old_props):
        return "additive"
    return "unknown"


def fingerprint(trace: InteractionTrace, source_name: str = "") -> dict:
    """Reduce a trace to a JSON-serializable, order-independent summary."""
    # PLAY: Everything compared later is computed here, once, from the trace.
    # Note the deliberate omissions: no timings, no event ids, no message
    # bodies. A fingerprint that carried message text would change on every
    # session for innocent reasons and drown the real novelty.
    server_meta: dict = {}
    declared_defs: list[dict] = []
    for a in trace.actors:
        if a.metadata.get("role") == "mcp_server":
            server_meta = a.metadata
            declared_defs = a.metadata.get("tools") or []

    schema_hashes = {t["name"]: _schema_hash(t.get("inputSchema"))
                     for t in declared_defs
                     if isinstance(t, dict) and "name" in t}

    hosts: set[str] = set()
    server_requests: set[str] = set()
    for e in trace.events:
        md = e.metadata
        if md.get("server_initiated") and not md.get("notification"):
            if md.get("method"):
                server_requests.add(md["method"])
        for p in e.parts:
            if p.kind == PartKind.TOOL_USE:
                hosts |= _hosts_in(p.content.get("arguments"))
            elif p.kind == PartKind.TOOL_RESULT:
                hosts |= _hosts_in(p.content.get("output"))

    server_info = server_meta.get("server_info") or {}
    tool_call_counts = dict(Counter(n for _, n in trace.called_tools()))
    ttl_ms = server_meta.get("tools_list_ttl_ms")
    cache_scope = server_meta.get("tools_list_cache_scope")
    timestamps = [e.timestamp for e in trace.events if e.timestamp]
    return {
        "fingerprint_version": FINGERPRINT_VERSION,
        "source": source_name,
        "first_ts": timestamps[0] if timestamps else "",
        "last_ts": timestamps[-1] if timestamps else "",
        "server_name": server_info.get("name"),
        "server_version": server_info.get("version"),
        "protocol_version": server_meta.get("protocol_version"),
        "capabilities": sorted(server_meta.get("capabilities") or {}),
        "declared_tools": sorted(trace.declared_tools()),
        "declaration_known": trace.declared_surface() is not None,
        "schema_hashes": schema_hashes,
        "called_tools": sorted({n for _, n in trace.called_tools()}),
        "fabricated_tools": sorted({n for _, n
                                    in trace.fabricated_tool_calls()}),
        "server_requests": sorted(server_requests),
        "hosts": sorted(hosts),
        "event_count": len(trace.events),
        "tool_call_counts": tool_call_counts,
        "tools_list_ttl_ms": ttl_ms,
        "tools_list_cache_scope": cache_scope,
        "schemas": {t["name"]: t.get("inputSchema") for t in declared_defs
                    if isinstance(t, dict) and "name" in t},
        "premature_list_changed": _premature_list_changed(trace),
        # a tail-only ingest dropped the head of the log; drift derived
        # from it is low-confidence and drift() prints a notice saying so
        "tail_only": bool(trace.metadata.get("tail_only")),
    }


# ─────────────────────────────────────────────────────────────────
# Baseline — the union of everything this server has been seen doing.
# ─────────────────────────────────────────────────────────────────
# PLAY: The baseline is a plain dict of sets, every key ending in `_ever`
# except the three that describe "last time". Sets mean no ordering and no
# duplicates to reason about; the `_ever` suffix is the reminder that these
# answers are cumulative across the whole history, not just the last session.
def new_baseline() -> dict:
    return {
        "sessions": 0,
        "declared_ever": set(),
        "called_ever": set(),
        "fabricated_ever": set(),
        "server_requests_ever": set(),
        "hosts_ever": set(),
        "capabilities_ever": set(),
        "schema_hashes_seen": {},     # tool name -> set of hashes
        "server_names": set(),
        "server_versions": {},        # server name -> set of versions
        "last_declared": set(),       # most recent session's surface
        "tool_call_counts_ever": {},   # tool name -> cumulative call count
        "last_schemas": {},           # tool name -> most recent full schema
    }


def merge(baseline: dict, fp: dict) -> dict:
    """Fold one fingerprint into the baseline (mutates and returns it)."""
    # PLAY: `last_declared` is overwritten, never unioned -- "removed tools"
    # only means something against the most recent surface. The guard right
    # below it matters for the same reason: a session that never produced a
    # tools/list (server died during the handshake) must not erase the known
    # surface, or every following session would look like it removed tools.
    baseline["sessions"] += 1
    baseline["declared_ever"] |= set(fp["declared_tools"])
    baseline["called_ever"] |= set(fp["called_tools"])
    for tname, c in fp["tool_call_counts"].items():
        baseline["tool_call_counts_ever"][tname] = \
            baseline["tool_call_counts_ever"].get(tname, 0) + c
    baseline["fabricated_ever"] |= set(fp["fabricated_tools"])
    baseline["server_requests_ever"] |= set(fp["server_requests"])
    baseline["hosts_ever"] |= set(fp["hosts"])
    baseline["capabilities_ever"] |= set(fp["capabilities"])
    for name, h in fp["schema_hashes"].items():
        baseline["schema_hashes_seen"].setdefault(name, set()).add(h)
    if fp["server_name"]:
        baseline["server_names"].add(fp["server_name"])
        if fp["server_version"]:
            baseline["server_versions"].setdefault(
                fp["server_name"], set()).add(fp["server_version"])
    if fp.get("declaration_known", bool(fp["declared_tools"])):
        baseline["last_declared"] = set(fp["declared_tools"])
    baseline["last_schemas"].update(fp["schemas"])
    return baseline


def drift(baseline: dict, fp: dict) -> list[Drift]:
    """Novelty in this fingerprint relative to the merged baseline."""
    # PLAY: The first session returns nothing, by construction. That is not a
    # special case to route around; it is the definition. On day one there is
    # no history to differ from, and inventing findings from a first look is
    # exactly the noise that teaches people to ignore a tool.
    if baseline["sessions"] == 0:
        return []   # first session IS the baseline; nothing to compare

    src = fp["source"]
    out: list[Drift] = []

    # PLAY: One constructor, `d()`, for every finding below. Note that each
    # finding carries the session it came from and a sentence a human can act
    # on -- never just a diff. The severity scale is the detector one: 1 worth
    # a look, 2 should not happen, 3 hostile or hallucinated unless proven
    # otherwise.
    def d(kind, severity, explanation, **detail):
        out.append(Drift(session=src, kind=kind, severity=severity,
                         explanation=explanation, detail=detail))

    # surfaced first, never suppressing: the findings below still stand
    # (a partial log can only under-report novelty, not invent it), but
    # the reader must know the comparison ran against a headless log
    if fp.get("tail_only"):
        d("tail_only_partial", 1,
          "session was ingested tail-only (head dropped at the ingest "
          "cap) — drift comparison is low-confidence")

    for name in sorted(set(fp["declared_tools"])
                       - baseline["declared_ever"]):
        d("new_declared_tool", 2,
          f"server now declares '{name}' — never in its surface before",
          tool=name)

    # only meaningful when this session actually produced a tools/list;
    # PLAY: The mirror-image guard to merge(). Removal is only asserted when
    # this session actually produced a tools/list; a trace that lost its head
    # would otherwise make every declared tool look like it vanished.
    # a session with no handshake proves nothing about removal
    if fp.get("declaration_known", bool(fp["declared_tools"])):
        for name in sorted(baseline["last_declared"]
                           - set(fp["declared_tools"])):
            d("removed_declared_tool", 1,
              f"'{name}' disappeared from the declared surface", tool=name)

    # PLAY: The distributional signal, and the only finding that needs
    # arithmetic rather than set membership. Scaling severity with the score
    # keeps a mild rebalance (1) apart from a wholesale pivot (3).
    baseline_calls = baseline["tool_call_counts_ever"]
    session_calls = fp["tool_call_counts"]
    if sum(baseline_calls.values()) >= JSD_MIN_CALLS and \
            sum(session_calls.values()) >= JSD_MIN_CALLS:
        jsd_score = _jsd(baseline_calls, session_calls)
        if jsd_score > JSD_DRIFT_THRESHOLD:
            severity = 3 if jsd_score > 0.5 else 2 if jsd_score > 0.3 else 1
            d("jsd_drift", severity,
              f"tool-call vocabulary distribution diverged from history "
              f"(JSD={jsd_score:.3f}, threshold={JSD_DRIFT_THRESHOLD})",
              jsd=round(jsd_score, 4))

    for name, h in sorted(fp["schema_hashes"].items()):
        seen = baseline["schema_hashes_seen"].get(name)
        if seen and h not in seen:
            change_kind = _classify_schema_change(
                baseline["last_schemas"].get(name), fp["schemas"].get(name))
            severity = 3 if change_kind == "mutative" else 2
            d("schema_changed", severity,
              f"inputSchema for '{name}' changed since it was first "
              f"declared ({change_kind})",
              tool=name, hash=h, change_kind=change_kind)

    if fp.get("premature_list_changed") and not fp.get("tail_only"):
        d("premature_list_changed", 2,
          "notifications/tools/list_changed fired before its preceding "
          "tools/list declaration's ttlMs would have expired")

    for name in sorted(set(fp["fabricated_tools"])
                       - baseline["fabricated_ever"]):
        d("new_fabricated_tool", 3,
          f"tools/call '{name}' outside any declared surface, "
          f"first time in this server's history", tool=name)

    fabricated = set(fp["fabricated_tools"])
    for name in sorted(set(fp["called_tools"])
                       - baseline["called_ever"] - fabricated):
        d("new_called_tool", 1,
          f"'{name}' called for the first time across all sessions",
          tool=name)

    for method in sorted(set(fp["server_requests"])
                         - baseline["server_requests_ever"]):
        d("new_server_request", 2,
          f"server-initiated request '{method}' never seen before",
          method=method)

    for host in sorted(set(fp["hosts"]) - baseline["hosts_ever"]):
        d("new_host", 2,
          f"new host in wire traffic: {host}", host=host)

    for cap in sorted(set(fp["capabilities"])
                      - baseline["capabilities_ever"]):
        d("new_capability", 1,
          f"server now advertises the '{cap}' capability", capability=cap)

    name, version = fp["server_name"], fp["server_version"]
    if name and baseline["server_names"] and \
            name not in baseline["server_names"]:
        d("server_identity_changed", 2,
          f"serverInfo.name changed to '{name}' "
          f"(was {sorted(baseline['server_names'])})", name=name)
    elif name and version and \
            version not in baseline["server_versions"].get(name, {version}):
        d("server_version_changed", 1,
          f"'{name}' version changed to {version}", version=version)

    return out


# ─────────────────────────────────────────────────────────────────
# Pipeline — directory of tap logs -> per-server drift history.
# ─────────────────────────────────────────────────────────────────
# PLAY: Drift is only meaningful within one server's own history, so the
# grouping key has to be right. serverInfo.name is the honest answer when the
# server gave one; the fallback reads the tap's filename convention, and the
# last resort is the file stem. Wrong key, wrong baseline, wrong findings.
def _server_key(fp: dict, path: Path) -> str:
    """Server identity: serverInfo.name, else the name baked into the
    tap's log filename (<stamp>_<name>_<pid>.jsonl), else the stem."""
    if fp["server_name"]:
        return fp["server_name"]
    parts = path.stem.split("_")
    return "_".join(parts[1:-1]) if len(parts) >= 3 else path.stem


def watch_paths(paths: Iterable[str | Path]) -> dict[str, list[dict]]:
    """Fingerprint every log, group by server, replay chronologically.

    Returns {server_key: [{source, fingerprint, findings}, ...]} with
    each server's sessions in time order; the first session of a server
    is its baseline and carries no findings by construction.
    """
    # PLAY: The three lines in the loop below are the core of the module and
    # their order is load bearing: compare against the baseline, *then* merge
    # the session into it. Flip them and every session becomes its own
    # baseline, which is the same as having no drift detection at all.
    from glassport.adapters.mcp_session import from_mcp_session_file

    fps: list[tuple[Path, dict]] = []
    for p in sorted(Path(p) for p in paths):
        trace = from_mcp_session_file(p)
        fps.append((p, fingerprint(trace, source_name=p.name)))

    groups: dict[str, list[tuple[Path, dict]]] = {}
    for p, f in fps:
        groups.setdefault(_server_key(f, p), []).append((p, f))

    out: dict[str, list[dict]] = {}
    for key, items in groups.items():
        items.sort(key=lambda t: (t[1]["first_ts"], t[0].name))
        baseline = new_baseline()
        rows = []
        for _, f in items:
            findings = drift(baseline, f)
            merge(baseline, f)
            rows.append({"source": f["source"], "fingerprint": f,
                         "findings": findings})
        out[key] = rows
    return out


def watch_dir(log_dir: str | Path) -> dict[str, list[dict]]:
    return watch_paths(Path(log_dir).glob("*.jsonl"))


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
def _print_text(groups: dict[str, list[dict]]) -> None:
    for key in sorted(groups):
        rows = groups[key]
        print(f"{key} — {len(rows)} session(s)")
        for i, row in enumerate(rows):
            fp = row["fingerprint"]
            if i == 0:
                print(f"  {row['source']}  baseline established · "
                      f"{len(fp['declared_tools'])} declared tool(s) · "
                      f"hosts: {', '.join(fp['hosts']) or '—'}")
            elif not row["findings"]:
                print(f"  {row['source']}  no drift")
            else:
                print(f"  {row['source']}")
                for f in sorted(row["findings"], key=lambda f: -f.severity):
                    print(f"    [sev {f.severity}] {f.kind}: {f.explanation}")
        print()


def main(argv: list[str]) -> int:
    args = list(argv)
    as_json = "--json" in args
    if as_json:
        args.remove("--json")
    if len(args) > 1 or (args and args[0] in ("-h", "--help")):
        print("usage: watch.py [log-dir] [--json]", file=sys.stderr)
        return 2

    log_dir = Path(args[0]) if args else DEFAULT_LOG_DIR
    if not log_dir.is_dir():
        print(f"[glassport] not a directory: {log_dir}", file=sys.stderr)
        return 2

    groups = watch_dir(log_dir)
    if not groups:
        print(f"[glassport] no session logs in {log_dir}", file=sys.stderr)
        return 0

    if as_json:
        print(json.dumps(
            {k: [{**row, "findings": [asdict(f) for f in row["findings"]]}
                 for row in rows]
             for k, rows in groups.items()},
            indent=2, ensure_ascii=False))
    else:
        _print_text(groups)

    worst = max((f.severity for rows in groups.values()
                 for row in rows for f in row["findings"]), default=0)
    return 1 if worst >= 2 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
