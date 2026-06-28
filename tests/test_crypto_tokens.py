"""
M2 (continued) — format/checksum validators for crypto + token material:
base58check (Bitcoin/Solana addresses, SHA-256d checksum), JWT structural
(three base64url segments whose header decodes to JSON), and UUIDv4 (version +
variant bits). Same recipe as IBAN/ABA: deterministic, ~0 false positives.

Placement, by false-positive risk:
- base58 — opt-in (examples/pii-crypto.json); its regex is broad.
- jwt    — the existing default jwt_token pattern, now SHARPENED by _jwt_check
           so a non-decoding eyJ.* string is no longer a false positive.
- uuid4  — menu validator only; a UUID is an identifier, not a secret, so it is
           NOT a default pattern (flagging request-IDs would be pure noise).

Vectors are real and verified. Pure stdlib.
"""
import unittest
from pathlib import Path

from glassport.adapters.mcp_session import from_mcp_session
from glassport import detectors

from tests.test_detectors import handshake, call


VALID_B58 = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
             "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"]
INVALID_B58 = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"]   # final char corrupted

VALID_JWT = ("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
             ".eyJzdWIiOiAiMTIzNDU2Nzg5MCJ9"
             ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk")
FAKE_JWT = "eyJxxxxxxxxxx.yyyyyyyyyy.zzzzzzzzzz"        # matches regex, decodes to junk

VALID_UUID4 = "550e8400-e29b-41d4-a716-446655440000"
INVALID_UUID4 = ["550e8400-e29b-31d4-a716-446655440000",   # version 3
                 "550e8400-e29b-41d4-c716-446655440000",   # variant c
                 "550e8400e29b41d4a716446655440000",        # no dashes
                 "not-a-uuid"]


class Base(unittest.TestCase):
    def setUp(self):
        detectors.clear_custom_pii_patterns()

    def exfil(self, args):
        lines = handshake() + [call(6, 3, "web_search", args)]
        return detectors.data_exfiltration(from_mcp_session(lines))

    def categories(self, anns):
        return [a.metadata.get("pii_category") for a in anns]


class TestBase58(Base):
    PACK = Path(__file__).resolve().parent.parent / "examples" / "pii-crypto.json"

    def test_validator_accepts_valid_culls_corrupted(self):
        for a in VALID_B58:
            self.assertTrue(detectors._base58check_check(a), a)
        for a in INVALID_B58:
            self.assertFalse(detectors._base58check_check(a), a)

    def test_validator_total(self):
        for s in ("", "x" * 50_000, "0OIl", "123"):
            self.assertIsInstance(detectors._base58check_check(s), bool)

    def test_menu_name(self):
        self.assertTrue(detectors._NAMED_VALIDATORS["base58"](VALID_B58[0]))

    def test_not_default_but_flagged_when_pack_loaded(self):
        self.assertNotIn("crypto_address",
                         self.categories(self.exfil({"a": VALID_B58[0]})))
        detectors.load_pii_patterns_from_json(str(self.PACK))
        self.assertIn("crypto_address",
                      self.categories(self.exfil({"a": VALID_B58[0]})))


class TestJwt(Base):
    def test_validator_accepts_real_culls_fake(self):
        self.assertTrue(detectors._jwt_check(VALID_JWT))
        self.assertFalse(detectors._jwt_check(FAKE_JWT))

    def test_validator_total(self):
        for s in ("", "x" * 50_000, "a.b.c", "..."):
            self.assertIsInstance(detectors._jwt_check(s), bool)

    def test_menu_name(self):
        self.assertTrue(detectors._NAMED_VALIDATORS["jwt"](VALID_JWT))

    def test_real_jwt_flagged_by_default(self):
        self.assertIn("jwt_token", self.categories(self.exfil({"t": VALID_JWT})))

    def test_fake_jwt_no_longer_a_false_positive(self):
        # the sharpening: _jwt_check culls an eyJ.* that doesn't decode to JSON
        self.assertNotIn("jwt_token", self.categories(self.exfil({"x": FAKE_JWT})))


class TestUuid4(Base):
    def test_validator_accepts_v4_culls_others(self):
        self.assertTrue(detectors._uuid4_check(VALID_UUID4))
        for u in INVALID_UUID4:
            self.assertFalse(detectors._uuid4_check(u), u)

    def test_validator_total(self):
        for s in ("", "x" * 50_000, "----"):
            self.assertIsInstance(detectors._uuid4_check(s), bool)

    def test_menu_name(self):
        self.assertTrue(detectors._NAMED_VALIDATORS["uuid4"](VALID_UUID4))

    def test_uuid_is_not_a_default_finding(self):
        # a UUID is an identifier, not a secret — must not be flagged by default
        self.assertNotIn("uuid4", self.categories(self.exfil({"id": VALID_UUID4})))


if __name__ == "__main__":
    unittest.main()
