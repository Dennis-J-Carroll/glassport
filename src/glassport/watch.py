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
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
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
def _schema_hash(schema) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"),
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _hosts_in(content) -> set[str]:
    """Hostnames of URLs appearing anywhere inside a JSON-able value."""
    blob = json.dumps(content, ensure_ascii=False, default=str) \
        if not isinstance(content, str) else content
    hosts = set()
    for netloc in _URL_HOST.findall(blob):
        host = netloc.rsplit("@", 1)[-1]          # strip userinfo
        host = host.rstrip(".,;:)]}\"'")          # strip trailing punctuation
        if host:
            hosts.add(host.lower())
    return hosts


def fingerprint(trace: InteractionTrace, source_name: str = "") -> dict:
    """Reduce a trace to a JSON-serializable, order-independent summary."""
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
        "schema_hashes": schema_hashes,
        "called_tools": sorted({n for _, n in trace.called_tools()}),
        "fabricated_tools": sorted({n for _, n
                                    in trace.fabricated_tool_calls()}),
        "server_requests": sorted(server_requests),
        "hosts": sorted(hosts),
        "event_count": len(trace.events),
        # a tail-only ingest dropped the head of the log; drift derived
        # from it is low-confidence and drift() prints a notice saying so
        "tail_only": bool(trace.metadata.get("tail_only")),
    }


# ─────────────────────────────────────────────────────────────────
# Baseline — the union of everything this server has been seen doing.
# ─────────────────────────────────────────────────────────────────
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
    }


def merge(baseline: dict, fp: dict) -> dict:
    """Fold one fingerprint into the baseline (mutates and returns it)."""
    baseline["sessions"] += 1
    baseline["declared_ever"] |= set(fp["declared_tools"])
    baseline["called_ever"] |= set(fp["called_tools"])
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
    if fp["declared_tools"]:
        baseline["last_declared"] = set(fp["declared_tools"])
    return baseline


def drift(baseline: dict, fp: dict) -> list[Drift]:
    """Novelty in this fingerprint relative to the merged baseline."""
    if baseline["sessions"] == 0:
        return []   # first session IS the baseline; nothing to compare

    src = fp["source"]
    out: list[Drift] = []

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
    # a session with no handshake proves nothing about removal
    if fp["declared_tools"]:
        for name in sorted(baseline["last_declared"]
                           - set(fp["declared_tools"])):
            d("removed_declared_tool", 1,
              f"'{name}' disappeared from the declared surface", tool=name)

    for name, h in sorted(fp["schema_hashes"].items()):
        seen = baseline["schema_hashes_seen"].get(name)
        if seen and h not in seen:
            d("schema_changed", 2,
              f"inputSchema for '{name}' changed since it was first declared",
              tool=name, hash=h)

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
