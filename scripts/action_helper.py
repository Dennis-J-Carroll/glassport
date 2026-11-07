#!/usr/bin/env python3
"""Stdlib-only support for the repository's composite GitHub Action."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def value(name: str) -> str:
    return os.environ.get(name, "")


def output(name: str, content: str) -> None:
    with open(value("GITHUB_OUTPUT"), "a", encoding="utf-8") as stream:
        stream.write(f"{name}={content}\n")


def validate() -> int:
    workspace = Path(value("GITHUB_WORKSPACE")).resolve()
    audit = value("AUDIT_PATH")
    bundles = value("BUNDLE_PATHS")
    if not audit and not bundles.strip():
        raise ValueError("Set audit-path or bundle (or both).")
    if audit:
        path = Path(audit)
        if path.is_absolute() or ".." in path.parts or "\n" in audit or "\r" in audit:
            raise ValueError("audit-path must be workspace-relative without '..'; SARIF locations need repository-relative paths.")
        if not (workspace / path).resolve().is_relative_to(workspace) or not (workspace / path).exists():
            raise ValueError("audit-path must exist inside GITHUB_WORKSPACE; SARIF locations need repository-relative paths.")
    for name, allowed in (("FAIL_ON_FINDINGS", {"none", "high"}),
                          ("FAIL_ON_BUNDLE", {"none", "contradicted", "unproven"}),
                          ("UPLOAD_SARIF", {"true", "false"}),
                          ("BUNDLE_PUBLIC", {"true", "false"}),
                          ("SETUP_PYTHON", {"true", "false"})):
        if value(name) not in allowed:
            raise ValueError(f"{name.lower().replace('_', '-')} must be one of {', '.join(sorted(allowed))}.")
    for raw in bundles.splitlines():
        path = raw.strip()
        if not path:
            continue
        if not Path(path).is_dir():
            raise ValueError(f"bundle path does not exist as a directory: {path}")
    return 0


def bundles() -> int:
    results = []
    for raw in value("BUNDLE_PATHS").splitlines():
        path = raw.strip()
        if not path:
            continue
        command = [sys.executable, str(Path(value("GITHUB_ACTION_PATH")) / "glassport_tap.py"),
                   "bundle", "verify"]
        if value("BUNDLE_PUBLIC") == "true":
            command.append("--public")
        command.extend([path, "--json"])
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1, 2):
            raise RuntimeError(f"bundle verify failed unexpectedly for {path}: {result.stderr.strip()}")
        document = json.loads(result.stdout)
        status = {0: "proven", 1: "contradicted", 2: "evidence unavailable"}[result.returncode]
        results.append({"path": path, "exit": result.returncode, "status": status,
                        "integrity": document["integrity"]["status"],
                        "analysis": document["analysis_reproduced"]["status"],
                        "delivery": document["delivery_evidence_present"]["status"]})
    worst = 1 if any(row["exit"] == 1 for row in results) else (2 if any(row["exit"] == 2 for row in results) else 0)
    output("bundle-results", json.dumps(results, separators=(",", ":")))
    output("bundle-worst", str(worst))
    return 0


def summary() -> int:
    lines = ["## Glassport Action", "", "| Check | Result |", "| --- | --- |"]
    audit_exit = value("AUDIT_EXIT")
    if audit_exit:
        with open(value("SARIF_FILE"), encoding="utf-8") as stream:
            sarif = json.load(stream)
        counts = {"error": 0, "warning": 0, "note": 0}
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                level = result.get("level", "warning")
                counts[level] = counts.get(level, 0) + 1
        lines.append(f"| Audit (exit {audit_exit}) | error {counts['error']}, warning {counts['warning']}, note {counts['note']} |")
    for row in json.loads(value("BUNDLE_RESULTS") or "[]"):
        safe_path = row["path"].replace("|", "\\|").replace("`", "\\`")
        lines.append(f"| Bundle `{safe_path}` | {row['status']} (exit {row['exit']}) |")
    with open(value("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    return 0


def enforce() -> int:
    if value("AUDIT_EXIT") == "1" and value("FAIL_ON_FINDINGS") == "high":
        raise ValueError("Audit found high or critical findings.")
    worst = value("BUNDLE_WORST")
    policy = value("FAIL_ON_BUNDLE")
    if (worst == "1" and policy != "none") or (worst == "2" and policy == "unproven"):
        raise ValueError(f"Bundle verification yielded {worst} under fail-on-bundle={policy}.")
    if value("UPLOAD_OUTCOME") == "failure":
        if value("FAIL_ON_FINDINGS") == "none":
            print("::warning::SARIF upload failed; file remains at sarif-file output.")
        else:
            raise ValueError("SARIF upload failed.")
    return 0


def main() -> int:
    try:
        return {"validate": validate, "bundles": bundles, "summary": summary,
                "enforce": enforce}[sys.argv[1]]()
    except (ValueError, KeyError, RuntimeError, OSError) as exc:
        print(f"glassport action: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
