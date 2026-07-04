# dogfood/eval_report_redteam.py
"""Report red-team grill. Builds a hostile tap session, runs the REAL HTML
renderer (adapter -> detectors.annotate -> report.render_html) and asserts
XSS / Unicode-deception invariants on the produced session.html. Exits
non-zero on any FAIL.

Run: PYTHONPATH=src python dogfood/eval_report_redteam.py

Threat: a malicious MCP server controls tool names, arguments and result text.
Those bytes flow into an HTML report a human opens in a browser from file://
(where injected script runs with local-file reach). The report must render
every such byte inert AND must not let invisible/bidi characters silently
deceive the analyst reading it.

Output (logs/report-redteam/session.html, findings/report-redteam.md) is
regenerated deterministically, so re-running does not dirty the git tree.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")

from glassport import detectors
from glassport.adapters.mcp_session import from_mcp_session, from_mcp_session_file
from glassport.report import render_html

from dogfood import oracle, redteam_fixtures as rf

# A hostile 2 MB field must not inflate the report past this; the largest legit
# session is far smaller. Generous enough that no honest report is truncated.
MAX_REPORT_BYTES = 2_000_000
MAX_COMBINING_RUN = 4


def _combine(a: tuple[bool, str], b: tuple[bool, str]) -> tuple[bool, str]:
    ok = a[0] and b[0]
    detail = "; ".join(x[1] for x in (a, b) if not x[0]) or f"{a[1]}; {b[1]}"
    return (ok, detail)


def _render(lines) -> str:
    trace = from_mcp_session(lines)
    detectors.annotate(trace)
    return render_html(trace, source_name="session.jsonl")

LOG_DIR = "dogfood/logs/report-redteam"
FINDINGS = "dogfood/findings/report-redteam.md"

# The attacker-controlled tool names / result text that must be neutralized.
MARKUP_PAYLOADS = [rf.MARKUP_NAME_PAYLOAD, rf.SCRIPT_RESULT_PAYLOAD]
ESCAPE_VALUES = [rf.MARKUP_NAME_PAYLOAD, rf.SCRIPT_RESULT_PAYLOAD,
                 rf.END_MARKER_PAYLOAD]


def run() -> int:
    os.makedirs(LOG_DIR, exist_ok=True)
    session = rf.write_hostile_report_session(os.path.join(LOG_DIR, "session.jsonl"))

    trace = from_mcp_session_file(session, server_name="mcp_server")
    detectors.annotate(trace)
    html = render_html(trace, source_name="session.jsonl")
    # session.html carries a generation timestamp (not byte-stable), so it is
    # written to a tempdir for the writability smoke check only — never into the
    # tracked logs dir, where it would dirty the tree on every run. The fixture
    # session.jsonl IS deterministic and stays tracked.
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "session.html").write_text(html, encoding="utf-8")

    checks = [
        ("R1 no-live-markup", oracle.no_live_markup(html, MARKUP_PAYLOADS)),
        ("R2 no-bidi-control", oracle.no_bidi_control(html)),
        ("R3 no-invisible-char", oracle.no_invisible_char(html)),
        ("R4 no-armenian-homoglyph", oracle.no_armenian_homoglyph(html)),
        ("R5 no-modifier-grave", oracle.no_modifier_grave(html)),
        ("R6 markup-name-escaped", oracle.value_escaped(html, rf.MARKUP_NAME_PAYLOAD)),
        ("R7 script-result-escaped", oracle.value_escaped(html, rf.SCRIPT_RESULT_PAYLOAD)),
        ("R8 no-raw-secret", oracle.no_raw_secret(html, rf.SECRETS)),
        ("R9 dos-output-bounded",
         oracle.bounded_output(_render(rf.dos_report_lines()), MAX_REPORT_BYTES)),
        ("R10 no-zalgo-run",
         oracle.no_zalgo_run(_render(rf.zalgo_report_lines()), MAX_COMBINING_RUN)),
        ("R11 no-nfkc-homoglyph", _combine(
            oracle.no_fullwidth_homoglyph(html),
            oracle.no_math_homoglyph(html))),
        ("R12 no-exotic-whitespace", oracle.no_exotic_whitespace(html)),
        ("R13 no-zalgo-interleave",
         oracle.no_excessive_combining_marks(
             _render(rf.zalgo_interleave_report_lines()), 25)),
        ("R14 no-novel-secret", oracle.no_raw_secret(html, rf.SECRETS)),
    ]

    lines = ["# report red-team — findings", "",
             "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, (ok, detail) in checks:
        all_ok = all_ok and ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")

    lines += ["", "## Threat & method", "",
              "The renderer draws attacker-controlled tool names, arguments and "
              "result text into an HTML page a human opens in a browser. "
              "`html.escape` neutralizes markup (`< > & \" '`) but is blind to "
              "Unicode deception — bidi overrides, zero-width joiners and "
              "cross-script homoglyphs render as inert-but-misleading text. "
              "R2–R5 lock that gap; R1/R6/R7 regression-lock the markup escaping "
              "that already held. R9 bounds output against a multi-megabyte "
              "field (a resource/DoS shape — the renderer amplified a 5 MB name "
              "4× before the per-field clamp); R10 collapses Zalgo combining-mark "
              "runs that an escape-only renderer let overflow the row.",
              "",
              "R11 extends the homoglyph hunt to NFKC compatibility variants: "
              "fullwidth Latin (U+FF00 block) and mathematical alphanumerics "
              "(U+1D400–U+1D7FF) fold to ASCII under NFKC but were outside the "
              "curated _HOMOGLYPHS set, so a hostile tool name could visually "
              "impersonate a declared one. The neutralizer now reveals any "
              "character whose NFKC form is ASCII alphanumeric.",
              "",
              "R12 closes exotic whitespace: NBSP (U+00A0), ideographic space "
              "(U+3000), line separator (U+2028) and paragraph separator "
              "(U+2029) are not _SAFE_WS and can misalign rows or hide breaks; "
              "they are now revealed as sentinels.",
              "",
              "R13 defeats the Zalgo run-counter reset: interleaving each "
              "combining mark with a zero-width joiner made the old counter "
              "reset to 0 after every mark, so 60 marks survived individually. "
              "The neutralizer now collapses combining-mark runs across "
              "transparent interleaves, bounding both the longest consecutive "
              "run (R10) and the total number of marks that escape collapse.",
              "",
              "R14 adds a novel credential shape — Stripe API keys "
              "(`sk_live_`, `pk_test_`, etc.) — to the redaction catalog. "
              "Before the pattern the key reached session.html verbatim; after, "
              "it is replaced with `[stripe_key redacted · N chars]`.",
              ""]

    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
