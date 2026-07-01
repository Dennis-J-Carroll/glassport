# dogfood/eval_advise_redteam.py
"""Advise red-team grill. Builds a hostile session + audit fixture, runs the
real `glassport advise --write`, and asserts poisoning invariants on the written
file. Exits non-zero on any FAIL. Run: PYTHONPATH=src python dogfood/eval_advise_redteam.py

Outputs (session.jsonl, findings/advise-redteam.md) are regenerated deterministically
(byte-stable), so re-running does not dirty the git tree.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

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
        written = Path(target).read_text() if os.path.exists(target) else ""
        # P2 idempotency probe: a second write must not raise / corrupt
        rc2 = glassport_main(["advise", "--session", session,
                              "--audit", audit_dir, "--write", target])
        written2 = Path(target).read_text() if os.path.exists(target) else ""

    checks = [
        ("P1 no-live-directive", oracle.no_live_directive(written)),
        ("P2 single-fence-pair", oracle.single_fence_pair(written)),
        ("P2 idempotent-rewrite", (rc2 == 0 and written2 == written,
                                   f"rc2={rc2}, stable={written2 == written}")),
        ("P3 homoglyph-redacted", oracle.no_substring(written, "obey me")),
        ("P4 no-raw-secret", oracle.no_raw_secret(written, rf.SECRETS)),
        ("P5 no-snippet", oracle.no_substring(written, rf.POISON_SNIPPET)),
        ("P6 no-markdown-link", oracle.no_substring(written, "](http")),
        ("P7 armenian-homoglyph", oracle.no_armenian_homoglyph(written)),
        ("P8 hangul-filler", oracle.no_hangul_filler(written)),
        ("P9 secret-tool-name", oracle.no_substring(written, rf.SECRET_TOOL_NAME)),
        ("P10 modifier-grave", oracle.no_modifier_grave(written)),
        ("P11 audit-path-secret", oracle.no_substring(written, rf.SECRET_FILENAME[:-3])),
    ]

    lines = ["# advise red-team — findings", "",
             f"advise exit: {rc}", "", "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, (ok, detail) in checks:
        all_ok = all_ok and ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")

    lines += ["", "## New breaks found and fixed", "",
                "The rows below document the payloads that were added to "
                "`dogfood/redteam_fixtures.py`, the exact bytes that escaped "
                "into the written advisory before the fix, and the source change "
                "that now contains them.", ""]

    def _hex(u: str) -> str:
        return " ".join(f"{b:02x}" for b in u.encode("utf-8"))

    lines += [
        "### P7 — Armenian homoglyph bypass",
        "",
        "`_normalize_for_scan` did not fold Armenian letters that are visual twins "
        "of Latin. The payload tool name was `ob\u0565y_me` (U+0565 ARMENIAN SMALL "
        "LETTER ECH, UTF-8 `d5 a5`). Before the fix, the advisory rendered it as a "
        "live-looking inline-code span:",
        "",
        "```",
        f"- **[warning] Undeclared egress** \u2014 tool `ob\u0565y_me` reached `armenian.exfil.net` (undeclared).",
        "```",
        "",
        f"Exact bytes of the tool-name portion: `{_hex(rf.ARMENIAN_DIRECTIVE)}`.",
        "",
        "Fix: added Armenian letter homoglyphs to `_CONFUSABLES` in "
        "`src/glassport/detectors.py`. After normalization the value becomes the "
        "identifier-shaped `obey_me` and is rendered safely inside backticks.",
        "",
        "### P8 — Hangul Choseong Filler invisible bypass",
        "",
        "`_INVISIBLE_RE` missed U+115F HANGUL CHOSEONG FILLER and U+1160 HANGUL "
        "JUNGSEONG FILLER. These are invisible but classify as word characters, so "
        "they passed `_SAFE_VALUE`. The payload was `ob\u115fey`. Before the fix:",
        "",
        "```",
        f"- **[warning] Undeclared egress** \u2014 tool `ob\u115fey` reached `hangul.exfil.net` (undeclared).",
        "```",
        "",
        f"Exact bytes of the tool-name portion: `{_hex(rf.HANGUL_FILLER_DIRECTIVE)}`.",
        "",
        "Fix: added U+115F and U+1160 to `_INVISIBLE_RE` in "
        "`src/glassport/detectors.py`.",
        "",
        "### P9 — Identifier-shaped secret leaked as a tool name",
        "",
        "`_SAFE_VALUE` allowed any `\\w.\\-/:@` string, so a real-looking secret "
        "used as a tool name was printed verbatim inside an inline-code span. "
        "Payload:",
        "",
        "```",
        rf.SECRET_TOOL_NAME,
        "```",
        "",
        "Before the fix the advisory contained that exact 40-character token as a "
        "quoted tool name, leaking the credential.",
        "",
        "Fix: `_sanitize_inline` now calls `looks_like_secret()` (exposed from "
        "`src/glassport/detectors.py`) and redacts any identifier-shaped value that "
        "matches a severity-3 PII pattern.",
        "",
        "### P10 — Modifier-letter grave accent (backtick homoglyph)",
        "",
        "U+02CB MODIFIER LETTER GRAVE ACCENT is a visual twin of the markdown "
        "backtick (U+0060). It survived `_normalize_for_scan` and passed "
        "`_SAFE_VALUE`, so an attacker could plant what looks like a closing "
        "backtick inside an inline-code span. Payload: `evil\u02cb`. Before the fix:",
        "",
        "```",
        f"- **[warning] Undeclared egress** \u2014 tool `evil\u02cb` reached `mgrave.exfil.net` (undeclared).",
        "```",
        "",
        f"Exact bytes of the tool-name portion: `{_hex(rf.MODIFIER_GRAVE_FENCE)}`.",
        "",
        "Fix: `_sanitize_inline` in `src/glassport/advise.py` explicitly redacts any "
        "value containing U+02CB.",
        "",
        "### P11 — Secret leaked through the --audit / merged path",
        "",
        "The static finding location is `base + '/' + relative_path`. The audit "
        "fixture now places `planted_server.py` inside a directory named with the "
        "same fake GitHub token, so the full path rendered in the advisory was:",
        "",
        "```",
        "<audit_dir>/ghp_123456789012345678901234567890123456/planted_server.py:3",
        "```",
        "",
        "Before the fix this entire path matched `_SAFE_VALUE` and was printed "
        "verbatim, leaking the token through the `--audit` path (and the merged "
        "`--session + --audit` path).",
        "",
        "Fix: same secret-scan redaction as P9; identifier-shaped paths are also "
        "checked with `looks_like_secret()` before being rendered.",
        "",
    ]

    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
