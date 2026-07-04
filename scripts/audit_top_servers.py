#!/usr/bin/env python3
"""
audit_top_servers.py — the "Auditing 100 MCP Servers" survey engine
(GQM plan 1.3: original research beats marketing copy).

Feeds a list of git repo URLs through `glassport audit --json` (shallow
clone, static read, never executes anything) and aggregates the findings
into the headline numbers: % of servers with hardcoded secrets, % with
tool-poisoning patterns, % with shell-injection paths, score histogram.
Emits a machine JSON and a human markdown summary.

The repo list is an input file, not a baked-in fetch — the survey is
reproducible from the list you publish alongside it, and this script
performs no network access beyond the git clones you asked for.

Usage:
    python scripts/audit_top_servers.py repos.txt [-o outdir]
    # repos.txt: one git URL per line, # comments ok
    # (build one e.g. via:
    #   gh search repos "mcp server" --sort stars -L 100 \
    #      --json url -q '.[].url')

Zero dependencies. Pure stdlib + git.
"""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

HEADLINE_RULES = {
    "hardcoded-secret": "hardcoded secrets",
    "tool-poisoning": "tool-poisoning patterns",
    "shell-injection": "shell-injection paths",
    "runtime-install": "runtime dependency installs",
    "fs-delete": "filesystem delete paths",
}


def audit_one(url: str, workdir: Path) -> dict | None:
    """Shallow-clone + static audit. None when clone or audit failed."""
    from glassport import audit as audit_mod
    dest = workdir / url.rstrip("/").rsplit("/", 1)[-1]
    clone = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True, text=True)
    if clone.returncode != 0:
        print(f"  clone failed: {url}", file=sys.stderr)
        return None
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            audit_mod.main([str(dest), "--json"])
        data = json.loads(buf.getvalue())
    except Exception as exc:                     # noqa: BLE001 — survey row
        print(f"  audit failed: {url} ({type(exc).__name__})",
              file=sys.stderr)
        return None
    data["url"] = url
    return data


def aggregate(rows: list[dict]) -> dict:
    n = len(rows)
    rule_hits = Counter()
    for r in rows:
        seen = {f.get("rule") for f in r.get("findings", [])}
        for rule in seen:
            rule_hits[rule] += 1
    scores = sorted(r.get("score", 0) for r in rows)
    return {
        "servers_audited": n,
        "median_score": scores[n // 2] if n else None,
        "rule_prevalence": {
            rule: {"servers": hits, "pct": round(100 * hits / n, 1)}
            for rule, hits in rule_hits.most_common()},
        "rows": [{"url": r["url"], "score": r.get("score"),
                  "grade": r.get("grade"),
                  "rules": sorted({f.get("rule")
                                   for f in r.get("findings", [])})}
                 for r in rows],
    }


def render_markdown(agg: dict) -> str:
    n = agg["servers_audited"]
    out = [f"# Auditing {n} MCP servers — glassport static survey", "",
           f"Servers audited: **{n}** · median score: "
           f"**{agg['median_score']}**", "", "## Headline prevalence", ""]
    for rule, label in HEADLINE_RULES.items():
        stats = agg["rule_prevalence"].get(rule)
        if stats:
            out.append(f"- **{stats['pct']}%** ({stats['servers']}/{n}) "
                       f"carry {label} (`{rule}`)")
    out += ["", "## Full rule prevalence", "",
            "| rule | servers | % |", "|---|---|---|"]
    for rule, stats in agg["rule_prevalence"].items():
        out.append(f"| {rule} | {stats['servers']} | {stats['pct']} |")
    out += ["", "## Per-server scores", "",
            "| server | score | grade | rules tripped |", "|---|---|---|---|"]
    for row in sorted(agg["rows"], key=lambda r: r["score"] or 0):
        out.append(f"| {row['url']} | {row['score']} | {row['grade']} | "
                   f"{', '.join(r for r in row['rules'] if r) or '—'} |")
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    repo_file = Path(argv[0])
    outdir = Path(argv[argv.index("-o") + 1]) if "-o" in argv else Path(".")
    urls = [ln.strip() for ln in repo_file.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, url in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}] {url}", file=sys.stderr)
            row = audit_one(url, Path(tmp))
            if row is not None:
                rows.append(row)
    agg = aggregate(rows)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "mcp_survey.json").write_text(
        json.dumps(agg, indent=2), encoding="utf-8")
    (outdir / "mcp_survey.md").write_text(
        render_markdown(agg), encoding="utf-8")
    print(f"wrote {outdir / 'mcp_survey.json'} and .md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
