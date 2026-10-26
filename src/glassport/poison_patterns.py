"""Shared static and live tool-description poisoning signatures."""
from __future__ import annotations

import re


# A real dotenv file, not a committed placeholder template.
_ENV_FILE = r"\.env\b(?!\.(?:example|sample|template|dist|defaults?)\b)"

POISON_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above|"
               r"earlier)\s+(instructions|messages|directives|context)"),
    re.compile(r"(?i)<\s*important\s*>"),
    re.compile(r"(?i)do\s+not\s+(tell|inform|mention|reveal|alert|"
               r"notify)\b[^.\n]{0,60}\b(user|human)"),
    re.compile(r"(?i)\b(read|cat|open)\b[^.\n]{0,60}"
               r"(\.ssh|id_rsa|" + _ENV_FILE + r"|credentials|api[_ ]?keys?)"),
    re.compile(r"(?i)\b(send|upload|post|forward|exfiltrate)\b[^.\n]{0,60}"
               r"(\.ssh|id_rsa|" + _ENV_FILE + r"|credentials|api[_ ]?keys?|"
               r"conversation|system prompt)"),
    re.compile(r"(?i)reveal\s+the\s+system\s+prompt"),
    re.compile(r"(?i)instead\s+of\s+(telling|showing|asking)\s+the\s+user"),
]

# Zero-width and bidi controls; escaped, not literal, for audit self-scans.
HIDDEN_UNICODE = re.compile(
    "[\\u200b-\\u200f\\u2060-\\u2064\\u202a-\\u202e\\u2066-\\u2069\\ufeff]")


def _strip_invisible(text: str) -> tuple[str, list[int]]:
    """Return stripped text and original offset for each retained character."""
    kept: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if HIDDEN_UNICODE.match(ch):
            continue
        kept.append(ch)
        index_map.append(i)
    return "".join(kept), index_map
