"""Pure invariant checkers over the written advisory text. Each returns
(ok, detail). A False is a real glassport finding."""
from __future__ import annotations

from glassport.advise import BEGIN, END

# Directive shapes an attacker would inject and an agent would obey.
_DIRECTIVE_STARTS = ("#", ">", "- [", "1.", "[INST]", "SYSTEM:", "<!--")


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
