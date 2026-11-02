"""Independent pre-optimization oracle for scan text and redaction origins."""
from __future__ import annotations

import random
import string
import unicodedata
import unittest

from glassport import detectors
from glassport.detectors import _CONFUSABLES, _INVISIBLE_RE, _MARK_CATEGORIES


# Copy of detectors._normalize_with_map at main 2da02c7, before optimization.
def _oracle_normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Normalize like _normalize_for_scan, but char-by-char, recording for
    each emitted normalized char the index in the ORIGINAL string it came
    from. invisible -> dropped (no entry); standalone mark char (Mn/Mc/Me) ->
    dropped (no entry, same treatment as invisible); confusable -> 1:1; NFKC
    per char -> 0..N chars, all tagged to that one origin index. The map lets
    a match found in normalized space be redacted back in the original bytes.

    Dropping mark-category chars (issue #64) defeats a secret with a
    synthetic mark stapled to every character (e.g. U+0332 COMBINING LOW
    LINE, or a Tamil/Devanagari spacing-combining vowel sign used the same
    way) — NFKC does not strip these (there is no compatibility mapping for
    an artificial base+mark pair that isn't a real precomposed character), so
    only an explicit drop, structured exactly like the invisible-char case,
    closes it.

    Per-char NFKC differs from whole-string NFKC only for cross-char
    combining sequences (irrelevant to ASCII-ish credentials); the
    fail-closed backstop in redact_secrets_strict proves any drift is safe."""
    out: list[str] = []
    origin: list[int] = []
    for i, ch in enumerate(text):
        if _INVISIBLE_RE.match(ch) or unicodedata.category(ch) in _MARK_CATEGORIES:
            continue
        for nc in unicodedata.normalize("NFKC", ch.translate(_CONFUSABLES)):
            out.append(nc)
            origin.append(i)
    return "".join(out), origin


SEED = 0x09A11CE
RANDOM_CASES = 20_000


def _cases():
    rng = random.Random(SEED)
    invisible = [chr(cp) for cp in range(0x110000) if _INVISIBLE_RE.fullmatch(chr(cp))]
    marks = ["\u0301", "\u0332", "\u0903", "\u0bc1", "\u20dd"]
    expanders = ["ﬁ", "①", "㎏", "ｦ"] + [chr(cp) for cp in range(0xff21, 0xff3b)]
    special = invisible + marks + [chr(cp) for cp in _CONFUSABLES] + expanders + ["\ud800"]
    for ch in special:
        yield "A" + ch + "z", "boundary"
        yield ch, "isolated"
    yield "A" * 2_000, "long-ascii"
    yield "A\u0301B", "cross-character-composition"
    alphabet = string.ascii_letters + string.digits + " -_./"
    for i in range(RANDOM_CASES):
        size = rng.randrange(0, 2_001) if i % 40 == 0 else rng.randrange(0, 121)
        if i % 11 == 0:
            text = "".join(rng.choice(alphabet) for _ in range(size))
        else:
            chunks = []
            while len("".join(chunks)) < size:
                chunks.append("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 24))))
                chunks.append(rng.choice(special))
            text = "".join(chunks)[:size]
        yield text, f"random-{i}"


class TestNormalizeEquivalence(unittest.TestCase):
    def test_scan_and_origin_map_match_main_oracle(self):
        count = 0
        for text, label in _cases():
            expected = _oracle_normalize_with_map(text)
            self.assertEqual(detectors._normalize_for_scan(text), expected[0], label)
            self.assertEqual(detectors._normalize_with_map(text), expected, label)
            count += 1
        self.assertGreaterEqual(count, RANDOM_CASES)
        print(f"NORMALIZE_ORACLE seed={SEED} cases={count}")
