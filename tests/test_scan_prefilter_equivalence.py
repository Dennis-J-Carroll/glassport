"""Built-in literal skips must preserve scan hits, spans, and ordering."""
from __future__ import annotations

import random
import re
import unittest

from glassport import detectors


def _signature(hits):
    return [(pat.category, value, start, end) for pat, value, start, end in hits]


class TestScanPrefilterEquivalence(unittest.TestCase):
    def test_builtins_match_same_patterns_without_prefilters(self):
        # Cloned PIIPattern tuples keep the same regexes and validators but
        # bypass identity-keyed built-in skips. No second scanner to drift.
        plain = tuple(detectors.PIIPattern(*pat) for pat in detectors.PII_PATTERNS)
        optimized = tuple(detectors.PII_PATTERNS)
        rng = random.Random(0x09F17E)
        pieces = ["ordinary prose ", "x" * 120, "test.person@example.org ",
                  "AKIA" + "A" * 16 + " ", "sk-ant-api03-" + "A" * 50 + " ",
                  "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2lnbmF0dXJl ",
                  "192.168.1.1 ", "4111111111111111 ", "api_key='" + "A" * 30 + "' ",
                  "postgres://u:p@example.org/db ", "-----BEGIN PGP PRIVATE KEY BLOCK-----"
                  + "A" * 30 + "-----END PGP PRIVATE KEY BLOCK----- "]
        cases = pieces + ["".join(rng.choice(pieces) for _ in range(rng.randrange(1, 12)))
                          for _ in range(200)]
        for text in cases:
            self.assertEqual(_signature(detectors._scan_normalized(text, optimized)),
                             _signature(detectors._scan_normalized(text, plain)), text[:80])

    def test_custom_pattern_with_builtin_category_is_never_skipped(self):
        custom = detectors.PIIPattern("email_address", 2, re.compile(r"(NO_AT_SIGN)"),
                                      None, "custom")
        self.assertEqual(_signature(detectors._scan_normalized("NO_AT_SIGN", (custom,))),
                         [("email_address", "NO_AT_SIGN", 0, 10)])
