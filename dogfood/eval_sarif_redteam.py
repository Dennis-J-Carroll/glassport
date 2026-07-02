# dogfood/eval_sarif_redteam.py
"""SARIF red-team grill. Runs the REAL renderers (audit_path -> render_sarif for
the static path; adapter -> detectors.annotate -> render_session_sarif for the
runtime path) against hostile fixtures and asserts that attacker-controlled
finding fields cannot break the JSON envelope or smuggle a credential into a
document that gets committed and uploaded to the GitHub Security tab. Exits
non-zero on any FAIL.

Run: PYTHONPATH=src python dogfood/eval_sarif_redteam.py

The static-audit fixture places its planted server inside a directory named
with an identifier-shaped fake secret (the advise P11 shape): the finding path
carries the token, so this proves render_sarif redacts secrets from the URI /
fingerprint, not just the message.

Outputs (findings/sarif-redteam.md) are byte-stable; no session artifacts are
persisted.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from glassport import audit, detectors, sarif
from glassport.adapters.mcp_session import from_mcp_session

from dogfood import oracle, redteam_fixtures as rf

FINDINGS = "dogfood/findings/sarif-redteam.md"


def run() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = rf.write_audit_fixture(tmp)           # dir named like the ghp_ token
        static_doc = sarif.render_sarif(audit.audit_path(root), base="srv")

    trace = from_mcp_session(rf.hostile_report_lines())
    detectors.annotate(trace)
    runtime_doc = sarif.render_session_sarif(trace, session_path="s.jsonl", base="srv")

    checks = [
        ("S1 static-json-well-formed", oracle.json_well_formed(static_doc)),
        ("S2 runtime-json-well-formed", oracle.json_well_formed(runtime_doc)),
        ("S3 static-no-raw-secret", oracle.no_raw_secret(static_doc, rf.SECRETS)),
        ("S4 runtime-no-raw-secret", oracle.no_raw_secret(runtime_doc, rf.SECRETS)),
    ]

    lines = ["# sarif red-team — findings", "",
             "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, (ok, detail) in checks:
        all_ok = all_ok and ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")

    lines += ["", "## Threat & method", "",
              "`json.dumps` makes the SARIF envelope structurally injection-proof "
              "(quotes, backslashes and C0 controls are all escaped) and "
              "`message.text` is a plain-text field GitHub never renders as HTML, "
              "so the JSON-break / markup-smuggle threats are closed by format "
              "(S1/S2 lock that). The real finding is credential leakage: a "
              "hostile server can name a directory like a secret, and the audit "
              "finding's path flowed into the SARIF URI / fingerprint verbatim. "
              "`render_sarif` now scrubs the message, URI and fingerprint with "
              "`detectors.redact_secrets` (S3). A poisoning *directive* the audit "
              "quotes in a finding is NOT redacted — that is the tool faithfully "
              "reporting the attack it found, not a leak.", ""]

    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
