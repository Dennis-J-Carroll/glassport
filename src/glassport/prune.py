"""
prune.py — retention for the session log directory (roadmap H1.10).

Logs grow forever in ~/.glassport/sessions/ by default. `glassport
prune --older-than 30d` reports what would be deleted; `--apply`
deletes. Dry-run is the default because deletion is the one operation
in glassport that destroys wire evidence.

Doctrine guardrail: a log whose analysis produced a detector_error
annotation is *evidence of a glassport bug* — prune refuses to delete
it without --force, because deleting it would destroy the repro.

Cron-friendly: exit 0 normally; exit 1 when the candidate count exceeds
--threshold N (so a cron'd dry-run can page you before disk fills).

Zero dependencies. Pure stdlib.
"""
from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_AGE_RE = re.compile(r"^(\d+)([dh])$")
_UNITS = {"d": 86400, "h": 3600}


def parse_age(text: str) -> int:
    """'30d' / '12h' -> seconds. Anything else raises ValueError."""
    m = _AGE_RE.match(text or "")
    if not m:
        raise ValueError(f"bad age {text!r} — expected e.g. 30d or 12h")
    return int(m.group(1)) * _UNITS[m.group(2)]


def _has_detector_error(path: Path) -> bool:
    """True when analyzing this log crashed a detector — the log is the
    repro for a glassport bug and must survive routine pruning.
    Analysis failure protects too: an unreadable log is not deletable
    evidence either."""
    try:
        from glassport.adapters.mcp_session import from_mcp_session_file
        from glassport.detectors import annotate
        anns = annotate(from_mcp_session_file(path))
    except Exception:
        return True
    return any(a.subcategory == "detector_error" for a in anns)


@dataclass
class PruneResult:
    candidates: list[Path] = field(default_factory=list)  # old enough
    deleted: list[Path] = field(default_factory=list)     # actually removed
    skipped: list[Path] = field(default_factory=list)     # protected


def prune(log_dir: Path, older_than_secs: int, apply: bool = False,
          force: bool = False, now: float | None = None) -> PruneResult:
    """Identify (and with apply=True, delete) sessions older than the
    cutoff. Only *.jsonl at the top level — companion files (.gate) go
    with their session; nothing else in the dir is glassport's to touch."""
    now = time.time() if now is None else now
    res = PruneResult()
    for p in sorted(Path(log_dir).glob("*.jsonl")):
        try:
            if now - p.stat().st_mtime < older_than_secs:
                continue
        except OSError:
            continue
        res.candidates.append(p)
        if not apply:
            continue
        if not force and _has_detector_error(p):
            res.skipped.append(p)
            continue
        gate = p.with_name(p.name + ".gate")
        try:
            p.unlink()
            res.deleted.append(p)
            if gate.exists():
                gate.unlink()
        except OSError:
            res.skipped.append(p)
    return res


USAGE = ("usage: glassport prune --older-than AGE [--log-dir DIR] "
         "[--apply] [--force] [--threshold N]\n"
         "  AGE like 30d or 12h. Dry-run by default; --apply deletes.\n"
         "  Logs with detector_error annotations are kept unless --force.\n"
         "  --threshold N: exit 1 when more than N candidates (for cron).")


def main(argv: list[str]) -> int:
    from glassport.tap import DEFAULT_LOG_DIR

    def _val(flag):
        if flag in argv:
            i = argv.index(flag) + 1
            return argv[i] if i < len(argv) else None
        return None

    age_raw = _val("--older-than")
    if not age_raw:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        older = parse_age(age_raw)
    except ValueError as exc:
        print(f"prune: {exc}", file=sys.stderr)
        return 2
    log_dir = Path(_val("--log-dir") or DEFAULT_LOG_DIR)
    apply = "--apply" in argv
    force = "--force" in argv
    threshold = int(_val("--threshold") or -1)

    res = prune(log_dir, older, apply=apply, force=force)
    mode = "deleted" if apply else "would delete (dry-run)"
    print(f"prune: {mode} {len(res.deleted) if apply else len(res.candidates)}"
          f" session(s) older than {age_raw} in {log_dir}")
    for p in (res.deleted if apply else res.candidates):
        print(f"  {p.name}")
    for p in res.skipped:
        print(f"  kept (detector_error evidence — use --force): {p.name}")
    if 0 <= threshold < len(res.candidates):
        return 1
    return 0
