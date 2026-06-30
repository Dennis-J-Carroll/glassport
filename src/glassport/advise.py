"""Agent-facing advisory: render glassport findings into a markdown block
suitable for an agent-instruction file (CLAUDE.md / AGENTS.md / GEMINI.md).

Load-bearing invariant: the output lands in an instruction surface, so this
module renders from STRUCTURED fields only and never consumes the free-text
Annotation.explanation / Finding.detail (which embed attacker-controlled
tool names, hosts, and matched source). The few attacker-controlled values
that are surfaced (host, tool, path) pass through _sanitize_inline first.
"""
from __future__ import annotations

import re

from glassport.detectors import _normalize_for_scan
from glassport.sarif import _sarif_level

_LEVEL_INT = {"error": 3, "warning": 2, "note": 1}
_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _severity_int(severity: str | int) -> int:
    """Fold both severity scales onto 1/2/3 via sarif's mapping, so advise
    and SARIF can never disagree about what counts as critical."""
    return _LEVEL_INT[_sarif_level(severity)]


def _sanitize_inline(s: object, *, cap: int = 64) -> str:
    """Render an attacker-controlled value as an inert inline-code span.

    Stages: normalize away invisible/homoglyph obfuscation (reusing the
    scanner's own defense), collapse all whitespace to single spaces, strip
    residual control bytes, neutralize backticks so the span cannot be
    closed early, cap length, wrap in inline code so any survivor is inert.
    """
    norm = _normalize_for_scan(str(s))
    flat = _WS_RE.sub(" ", norm)
    flat = _CTRL_RE.sub("", flat).strip()
    if len(flat) > cap:
        flat = flat[: cap - 1] + "…"
    flat = flat.replace("`", "ˋ")  # modifier grave: visible, never closes the span
    return f"`{flat}`"
