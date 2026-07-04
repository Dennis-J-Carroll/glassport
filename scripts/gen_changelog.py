#!/usr/bin/env python3
"""
gen_changelog.py — generate CHANGELOG.md from git history (roadmap H1.03).

The changelog is generated, not hand-written: each release section is
derived from the conventional-commit subjects between consecutive tags,
mapped onto Keep-a-Changelog categories. Re-running is idempotent for
unchanged history. Zero dependencies; git via subprocess.

Usage:  python scripts/gen_changelog.py [--write]
        (default prints to stdout; --write rewrites CHANGELOG.md)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# conventional-commit prefix -> Keep-a-Changelog section
SECTIONS = [
    ("Added", ("feat",)),
    ("Fixed", ("fix", "hardening")),
    ("Changed", ("refactor", "perf", "build", "release")),
    ("Security", ("security",)),
    ("Documentation", ("docs",)),
    ("Internal", ("test", "ci", "chore", "dogfood")),
]
SUBJECT_RE = re.compile(r"^(?P<type>[a-z]+)(\([^)]*\))?!?:\s*(?P<desc>.+)$")
SKIP_RE = re.compile(r"^Merge (pull request|branch)")


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, check=True,
                          capture_output=True, text=True).stdout


def tags_in_order() -> list[tuple[str, str]]:
    """[(tag, yyyy-mm-dd)] oldest first, semver-sorted."""
    out = []
    for tag in _git("tag", "--sort=v:refname").split():
        date = _git("log", "-1", "--format=%ad", "--date=short",
                    tag).strip()
        out.append((tag, date))
    return out


def subjects(rev_range: str) -> list[str]:
    lines = _git("log", "--format=%s", "--no-merges", rev_range)
    return [ln for ln in lines.splitlines() if ln.strip()]


def classify(subs: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {name: [] for name, _ in SECTIONS}
    for s in subs:
        if SKIP_RE.match(s):
            continue
        m = SUBJECT_RE.match(s)
        if not m:
            grouped["Changed"].append(s)
            continue
        ctype, desc = m.group("type"), m.group("desc")
        for name, prefixes in SECTIONS:
            if ctype in prefixes:
                grouped[name].append(desc)
                break
        else:
            grouped["Changed"].append(desc)
    return grouped


def render() -> str:
    tags = tags_in_order()
    out = [
        "# Changelog",
        "",
        "All notable changes to glassport. Generated from git history by",
        "`scripts/gen_changelog.py` — edit that script, not this file.",
        "Format follows [Keep a Changelog](https://keepachangelog.com/); "
        "versions follow semver.",
        "",
    ]

    def emit(title: str, date: str, rev_range: str) -> None:
        subs = subjects(rev_range)
        if not subs:
            return
        out.append(f"## [{title}]{f' - {date}' if date else ''}")
        out.append("")
        for name, items in classify(subs).items():
            if not items:
                continue
            out.append(f"### {name}")
            out.extend(f"- {i}" for i in items)
            out.append("")

    last_tag = tags[-1][0] if tags else None
    if last_tag:
        emit("Unreleased", "", f"{last_tag}..HEAD")
    for i in range(len(tags) - 1, -1, -1):
        tag, date = tags[i]
        prev = tags[i - 1][0] if i > 0 else None
        emit(tag.lstrip("v"), date, f"{prev}..{tag}" if prev else tag)
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--write" in argv:
        (REPO / "CHANGELOG.md").write_text(text, encoding="utf-8")
        print(f"wrote {REPO / 'CHANGELOG.md'}", file=sys.stderr)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
