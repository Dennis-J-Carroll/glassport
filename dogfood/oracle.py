"""Pure invariant checkers over the written advisory text. Each returns
(ok, detail). A False is a real glassport finding."""
from __future__ import annotations

import html as _html
import json as _json

from glassport.advise import BEGIN, END
from glassport.detectors import _normalize_for_scan

# Directive shapes an attacker would inject and an agent would obey.
_DIRECTIVE_STARTS = ("#", ">", "- [", "1.", "[INST]", "SYSTEM:", "<!--")

# Homoglyph / invisible classes _normalize_for_scan must fold away before a
# value is considered safe to print.
_ARMENIAN_E = "\u0565"          # visually identical to Latin 'e'
_HANGUL_FILLERS = "\u115f\u1160"  # invisible, but word-character-shaped
_MODIFIER_GRAVE = "\u02cb"      # looks like a closing backtick


def single_fence_pair(text: str) -> tuple[bool, str]:
    nb, ne = text.count(BEGIN), text.count(END)
    return (nb == 1 and ne == 1,
            f"BEGIN×{nb}, END×{ne} (expected 1/1)")


def no_live_directive(text: str) -> tuple[bool, str]:
    for i, line in enumerate(text.splitlines()):
        s = line.lstrip()
        if line in (BEGIN, END):          # glassport's own fence wrapper
            continue
        # glassport's own headings start with '## ⚠️' / '### ' / '## ✓' — allow those
        if s.startswith(("## ⚠️", "## ✓", "### Runtime", "### Static")):
            continue
        if s.startswith(_DIRECTIVE_STARTS):
            return (False, f"line {i} begins with a directive: {line[:48]!r}")
    return (True, "no injected directive starts a line")


def no_raw_secret(text: str, secrets: dict) -> tuple[bool, str]:
    for name, value in secrets.items():
        if value and (value in text or value[:12] in text):
            return (False, f"raw secret {name!r} (or 12-char prefix) leaked")
    return (True, "no raw secret present")


def no_substring(text: str, needle: str) -> tuple[bool, str]:
    return (needle not in text, f"{needle!r} present" if needle in text else "absent")


def no_armenian_homoglyph(text: str) -> tuple[bool, str]:
    if _ARMENIAN_E in text:
        return (False, "Armenian homoglyph U+0565 present")
    return (True, "no Armenian homoglyph present")


def no_hangul_filler(text: str) -> tuple[bool, str]:
    for ch in _HANGUL_FILLERS:
        if ch in text:
            return (False, f"Hangul filler U+{ord(ch):04X} present")
    return (True, "no Hangul filler present")


def no_modifier_grave(text: str) -> tuple[bool, str]:
    if _MODIFIER_GRAVE in text:
        return (False, "modifier grave U+02CB (backtick homoglyph) present")
    return (True, "no modifier grave present")


# ---------------------------------------------------------------------------
# report.py (session.html) HTML-renderer invariants. Defined independently of
# the renderer's own neutralizer so the check can never be circular: these sets
# describe the raw attacker bytes that must NOT survive into the rendered page.
# ---------------------------------------------------------------------------

# Bidi / directional-formatting controls: reorder rendered glyphs without
# changing bytes, so a hostile name can visually masquerade as a benign one.
_BIDI_CONTROLS = frozenset(
    "‪‫‬‭‮⁦⁧⁨⁩"
    "‎‏؜")
# Zero-width / invisible characters that are word-shaped or paste-invisible.
_INVISIBLE_CHARS = frozenset(
    "​‌‍⁠⁡⁢⁣⁤﻿"
    "ᅟᅠ᠎­ˋ")


def _present(text: str, chars: frozenset) -> list[str]:
    return sorted({f"U+{ord(c):04X}" for c in text if c in chars})


def no_bidi_control(text: str) -> tuple[bool, str]:
    hit = _present(text, _BIDI_CONTROLS)
    return (not hit, f"bidi controls present: {hit}" if hit
            else "no bidi/directional control survived")


def no_invisible_char(text: str) -> tuple[bool, str]:
    hit = _present(text, _INVISIBLE_CHARS)
    return (not hit, f"invisible chars present: {hit}" if hit
            else "no invisible/zero-width char survived")


def no_live_markup(text: str, payloads) -> tuple[bool, str]:
    """No attacker markup payload may appear verbatim (i.e. unescaped) in the
    rendered HTML. If the raw '<...>' bytes are present, escaping failed."""
    for p in payloads:
        if "<" in p and p in text:
            return (False, f"raw markup payload survived unescaped: {p[:48]!r}")
    return (True, "no attacker markup payload survived unescaped")


def value_escaped(text: str, raw_value: str) -> tuple[bool, str]:
    """An attacker value that contains HTML-special bytes must appear only in
    its html.escape'd form, never verbatim."""
    esc = _html.escape(raw_value, quote=True)
    if raw_value != esc and raw_value in text:
        return (False, f"attacker value present unescaped: {raw_value[:48]!r}")
    return (True, "attacker value not present unescaped")


def json_well_formed(text: str) -> tuple[bool, str]:
    """Attacker bytes in any finding field must not break the SARIF envelope:
    the document must still parse as JSON."""
    try:
        doc = _json.loads(text)
    except ValueError as e:
        return (False, f"SARIF is not valid JSON: {e}")
    runs = doc.get("runs") if isinstance(doc, dict) else None
    if not runs:
        return (False, "SARIF has no runs")
    return (True, f"valid JSON, {len(runs[0].get('results', []))} results")


def no_normalized_directive(text: str, payload: str) -> tuple[bool, str]:
    """A payload split with invisible/homoglyph obfuscation must not survive
    into the rendered advisory in any form an LLM could read as a directive."""
    norm_payload = _normalize_for_scan(payload)
    norm_text = _normalize_for_scan(text)
    if norm_payload in norm_text:
        return (False, f"normalized payload {norm_payload!r} leaked")
    return (True, f"normalized payload {norm_payload!r} absent")
