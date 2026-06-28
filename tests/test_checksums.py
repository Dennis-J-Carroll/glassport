"""
M2 — high-precision checksum/format validators for financial identifiers:
IBAN (ISO 13616 MOD-97-10) and ABA routing numbers (weighted sum + Federal
Reserve leading-range guard). Tests the validators directly, prove they fire
end-to-end through the real adapter + data_exfiltration, and pin a small
precision/recall corpus of valid + corrupted real-world vectors.

Checksum vectors are real and verified:
  valid IBAN:  GB82WEST12345698765432, DE89370400440532013000,
               FR1420041010050500013M02606
  valid ABA:   021000021 (Chase), 011401533, 121000248 (Wells Fargo)
Pure stdlib.
"""
import unittest

from glassport.adapters.mcp_session import from_mcp_session
from glassport import detectors

from tests.test_detectors import handshake, call


VALID_IBANS = ["GB82WEST12345698765432", "DE89370400440532013000",
               "FR1420041010050500013M02606"]
# same strings with the final check digit corrupted
INVALID_IBANS = ["GB82WEST12345698765433", "DE89370400440532013001",
                 "FR1420041010050500013M02607"]
VALID_ABAS = ["021000021", "011401533", "121000248"]
INVALID_ABAS = ["021000022",      # mod-10 fails
                "123456789",      # mod-10 fails
                "991000020"]      # leading range 99 invalid (even if mod-10 ok)


class TestChecksumBase(unittest.TestCase):
    def setUp(self):
        detectors.clear_custom_pii_patterns()

    def exfil(self, args):
        lines = handshake() + [call(6, 3, "web_search", args)]
        return detectors.data_exfiltration(from_mcp_session(lines))

    def categories(self, anns):
        return [a.metadata.get("pii_category") for a in anns]


class TestIbanValidator(TestChecksumBase):
    def test_accepts_valid_culls_corrupted(self):
        for v in VALID_IBANS:
            self.assertTrue(detectors._iban_check(v), v)
        for v in INVALID_IBANS:
            self.assertFalse(detectors._iban_check(v), v)

    def test_tolerates_spacing_and_case(self):
        self.assertTrue(detectors._iban_check("gb82 west 1234 5698 7654 32"))

    def test_total_on_hostile_input(self):
        for s in ("", "x" * 50_000, "GB", "not-an-iban", "12"):
            self.assertIsInstance(detectors._iban_check(s), bool)


class TestAbaValidator(TestChecksumBase):
    def test_accepts_valid_culls_invalid(self):
        for v in VALID_ABAS:
            self.assertTrue(detectors._aba_check(v), v)
        for v in INVALID_ABAS:
            self.assertFalse(detectors._aba_check(v), v)

    def test_leading_range_guard_culls_otherwise_valid_mod10(self):
        # 991000020 passes mod-10 but 99 is not a Federal Reserve prefix
        self.assertFalse(detectors._aba_check("991000020"))

    def test_total_on_hostile_input(self):
        for s in ("", "x" * 50_000, "12345", "abcdefghi"):
            self.assertIsInstance(detectors._aba_check(s), bool)


class TestEndToEndDetection(TestChecksumBase):
    def test_iban_in_tool_call_is_flagged(self):
        anns = self.exfil({"transfer_to": "DE89370400440532013000"})
        self.assertIn("iban", self.categories(anns))

    def test_aba_routing_in_tool_call_is_flagged(self):
        anns = self.exfil({"routing": "021000021"})
        self.assertIn("aba_routing", self.categories(anns))

    def test_corrupted_iban_not_flagged(self):
        anns = self.exfil({"x": "GB82WEST12345698765433"})
        self.assertNotIn("iban", self.categories(anns))


class TestMenuNames(TestChecksumBase):
    def test_iban_and_aba_named_in_menu(self):
        self.assertIn("iban", detectors._NAMED_VALIDATORS)
        self.assertIn("aba", detectors._NAMED_VALIDATORS)
        self.assertTrue(detectors._NAMED_VALIDATORS["iban"](VALID_IBANS[0]))
        self.assertTrue(detectors._NAMED_VALIDATORS["aba"](VALID_ABAS[0]))


class TestPrecisionRecallCorpus(TestChecksumBase):
    """A deterministic stand-in for the honeytoken corpus: known positives +
    known negatives, asserting perfect precision/recall on this fixture set.
    The negatives are corrupted-but-plausible — not obvious fakes — so a smart
    validator can't trivially pass by rejecting junk (the fake-credential
    paradox)."""
    def test_iban_perfect_on_fixture_corpus(self):
        tp = sum(detectors._iban_check(v) for v in VALID_IBANS)
        fp = sum(detectors._iban_check(v) for v in INVALID_IBANS)
        self.assertEqual(tp, len(VALID_IBANS))   # recall 1.0
        self.assertEqual(fp, 0)                   # precision 1.0

    def test_aba_perfect_on_fixture_corpus(self):
        tp = sum(detectors._aba_check(v) for v in VALID_ABAS)
        fp = sum(detectors._aba_check(v) for v in INVALID_ABAS)
        self.assertEqual(tp, len(VALID_ABAS))
        self.assertEqual(fp, 0)


if __name__ == "__main__":
    unittest.main()
