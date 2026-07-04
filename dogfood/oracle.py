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


def no_fullwidth_homoglyph(text: str) -> tuple[bool, str]:
    """Fullwidth Latin letters (U+FF00 block) NFKC-fold to ASCII but are not
    in the renderer's curated _HOMOGLYPHS set, so they can impersonate a
    declared tool name unless the neutralizer applies NFKC."""
    for ch in text:
        o = ord(ch)
        if 0xFF00 <= o <= 0xFFEF:
            return (False, f"fullwidth char U+{o:04X} present")
    return (True, "no fullwidth homoglyph present")


def no_math_homoglyph(text: str) -> tuple[bool, str]:
    """Mathematical alphanumeric symbols (U+1D400–U+1D7FF) NFKC-fold to ASCII
    letters/digits and can impersonate a benign identifier."""
    for ch in text:
        o = ord(ch)
        if 0x1D400 <= o <= 0x1D7FF:
            return (False, f"mathematical alphanumeric U+{o:04X} present")
    return (True, "no mathematical-alphanumeric homoglyph present")


def no_exotic_whitespace(text: str) -> tuple[bool, str]:
    """NBSP, ideographic space, line/paragraph separators are not _SAFE_WS and
    can misalign rows or hide breaks in the rendered report."""
    for ch in text:
        if ch in "\u00a0\u3000\u2028\u2029":
            return (False, f"exotic whitespace U+{ord(ch):04X} present")
    return (True, "no exotic whitespace present")


def no_excessive_combining_marks(text: str, limit: int) -> tuple[bool, str]:
    """A Zalgo stack interleaved with zero-width joiners defeats a naive
    consecutive-run counter: the total number of combining marks that survive
    (not just the longest consecutive run) must be bounded."""
    import unicodedata
    total = sum(1 for ch in text if unicodedata.category(ch) in ("Mn", "Mc", "Me"))
    return (total <= limit, f"{total} combining marks survived (limit {limit})")


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


def bounded_output(text: str, max_bytes: int) -> tuple[bool, str]:
    """A renderer must bound its output: a hostile multi-megabyte field cannot
    inflate the artifact without limit (a resource/DoS shape). Deterministic —
    asserts on the produced size, not wall-clock time."""
    n = len(text.encode("utf-8"))
    return (n <= max_bytes,
            f"output {n} bytes (limit {max_bytes})")


def no_zalgo_run(text: str, limit: int) -> tuple[bool, str]:
    """No run of more than `limit` consecutive combining marks may survive — a
    Zalgo stack overflows and obscures the report; legit diacritics (1-2 marks)
    are fine."""
    import unicodedata
    run = worst = 0
    for ch in text:
        if unicodedata.category(ch) in ("Mn", "Mc", "Me"):
            run += 1
            worst = max(worst, run)
        else:
            run = 0
    return (worst <= limit,
            f"longest combining-mark run = {worst} (limit {limit})")


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


def _sarif_messages(text: str) -> list[str]:
    """Extract every message.text from a SARIF document."""
    try:
        doc = _json.loads(text)
    except ValueError:
        return []
    messages: list[str] = []
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            msg = result.get("message", {})
            if isinstance(msg, dict) and "text" in msg:
                messages.append(msg["text"])
    return messages


def sarif_no_bidi_control(text: str) -> tuple[bool, str]:
    """Bidi overrides in SARIF message.text can reorder a finding's display
    in a Security UI that does not neutralize Unicode itself."""
    for msg in _sarif_messages(text):
        hit = _present(msg, _BIDI_CONTROLS)
        if hit:
            return (False, f"bidi controls in message.text: {hit}")
    return (True, "no bidi control in SARIF message.text")


def sarif_no_zwj(text: str) -> tuple[bool, str]:
    """Zero-width joiners in message.text are invisible and can splice a
    hostile tool name so it reads as a benign one."""
    for msg in _sarif_messages(text):
        if "\u200d" in msg:
            return (False, "zero-width joiner U+200D in message.text")
    return (True, "no zero-width joiner in SARIF message.text")


def no_normalized_directive(text: str, payload: str) -> tuple[bool, str]:
    """A payload split with invisible/homoglyph obfuscation must not survive
    into the rendered advisory in any form an LLM could read as a directive."""
    norm_payload = _normalize_for_scan(payload)
    norm_text = _normalize_for_scan(text)
    if norm_payload in norm_text:
        return (False, f"normalized payload {norm_payload!r} leaked")
    return (True, f"normalized payload {norm_payload!r} absent")
