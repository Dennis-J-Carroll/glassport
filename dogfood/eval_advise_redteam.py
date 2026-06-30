# dogfood/eval_advise_redteam.py
"""Advise red-team grill. Builds a hostile session + audit fixture, runs the
real `glassport advise --write`, and asserts poisoning invariants on the written
file. Exits non-zero on any FAIL. Run: PYTHONPATH=src python dogfood/eval_advise_redteam.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from glassport.tap import main as glassport_main

from dogfood import oracle, redteam_fixtures as rf

LOG_DIR = "dogfood/logs/advise-redteam"
FINDINGS = "dogfood/findings/advise-redteam.md"


def run() -> int:
    os.makedirs(LOG_DIR, exist_ok=True)
    session = rf.write_hostile_session(os.path.join(LOG_DIR, "session.jsonl"))

    with tempfile.TemporaryDirectory() as tmp:
        audit_dir = rf.write_audit_fixture(tmp)
        target = os.path.join(tmp, "AGENTS.md")
        rc = glassport_main(["advise", "--session", session,
                             "--audit", audit_dir, "--write", target])
        written = open(target).read() if os.path.exists(target) else ""
        # P2 idempotency probe: a second write must not raise / corrupt
        rc2 = glassport_main(["advise", "--session", session,
                              "--audit", audit_dir, "--write", target])
        written2 = open(target).read() if os.path.exists(target) else ""

    checks = [
        ("P1 no-live-directive", oracle.no_live_directive(written)),
        ("P2 single-fence-pair", oracle.single_fence_pair(written)),
        ("P2 idempotent-rewrite", (rc2 == 0 and written2 == written,
                                   f"rc2={rc2}, stable={written2 == written}")),
        ("P3 homoglyph-redacted", oracle.no_substring(written, "obey me")),
        ("P4 no-raw-secret", oracle.no_raw_secret(written, rf.SECRETS)),
        ("P5 no-snippet", oracle.no_substring(written, rf.POISON_SNIPPET)),
    ]

    lines = ["# advise red-team — findings", "",
             f"advise exit: {rc}", "", "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, (ok, detail) in checks:
        all_ok = all_ok and ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")
    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
