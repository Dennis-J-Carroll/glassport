"""
health.py — "is the tap healthy?" over recent sessions (roadmap H1.09).

Aggregates the glassport.metrics self-observation lines the tap writes
at session end, plus offline detector_error counts, across the newest N
session logs. One line of verdict for humans, --json for scripts.

Division of authority (doctrine): the metrics line asserts only what
the tap witnessed on the wire (frames, blocks, duration, bytes). This
command computes analysis-side facts — detector errors, missing metrics
lines — at read time, because the tap must never assert them.

Zero dependencies. Pure stdlib.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

USAGE = "usage: glassport health [--log-dir DIR] [--last N] [--json]"


def _metrics_of(path: Path) -> dict | None:
    """The session's glassport.metrics line (last one wins), or None."""
    found = None
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if '"glassport.metrics"' not in line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("type") == "glassport.metrics":
                    found = entry
    except OSError:
        return None
    return found


def _detector_errors(path: Path) -> int:
    """Offline: how many detectors crashed analyzing this session."""
    try:
        from glassport.adapters.mcp_session import from_mcp_session_file
        from glassport.detectors import annotate
        anns = annotate(from_mcp_session_file(path))
    except Exception:
        return 0        # unreadable log is a prune concern, not a count
    return sum(1 for a in anns if a.subcategory == "detector_error")


def aggregate(log_dir: Path, last: int = 10) -> dict:
    paths = sorted(Path(log_dir).glob("*.jsonl"), reverse=True)[:last]
    agg = {"sessions": len(paths), "frames_seen": 0, "frames_blocked": 0,
           "session_duration_s": 0.0, "log_bytes": 0,
           "sessions_missing_metrics": 0, "detector_errors": 0,
           "tail_only_sessions": 0}
    for p in paths:
        m = _metrics_of(p)
        if m is None:
            agg["sessions_missing_metrics"] += 1
        else:
            agg["frames_seen"] += int(m.get("frames_seen") or 0)
            agg["frames_blocked"] += int(m.get("frames_blocked") or 0)
            agg["session_duration_s"] += float(
                m.get("session_duration_s") or 0.0)
            agg["log_bytes"] += int(m.get("log_bytes") or 0)
        agg["detector_errors"] += _detector_errors(p)
    return agg


def main(argv: list[str]) -> int:
    from glassport.tap import DEFAULT_LOG_DIR

    def _val(flag, default=None):
        if flag in argv:
            i = argv.index(flag) + 1
            return argv[i] if i < len(argv) else default
        return default

    log_dir = Path(_val("--log-dir") or DEFAULT_LOG_DIR)
    last = int(_val("--last") or 10)
    agg = aggregate(log_dir, last=last)

    if "--json" in argv:
        print(json.dumps(agg, indent=2))
        return 0

    if agg["sessions"] == 0:
        print(f"health: no sessions in {log_dir}")
        return 0
    healthy = agg["detector_errors"] == 0
    verdict = "healthy" if healthy else \
        f"DEGRADED — {agg['detector_errors']} detector error(s)"
    print(f"health: {verdict} · last {agg['sessions']} session(s) · "
          f"{agg['frames_seen']} frames · {agg['frames_blocked']} blocked · "
          f"{agg['sessions_missing_metrics']} without metrics "
          f"(pre-metrics or crashed tap)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
