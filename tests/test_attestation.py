from __future__ import annotations
import time
import unittest

from glassport.attestation import check_meta, ATTESTATION_KEY


class TestStructuralAttestation(unittest.TestCase):
    def test_absent_meta_is_not_an_error(self):
        result = check_meta(None)
        self.assertFalse(result.present)
        self.assertEqual(result.problems, [])

    def test_well_formed_unexpired_attestation(self):
        meta = {ATTESTATION_KEY: {
            "alg": "ed25519", "sig": "YmFzZTY0",
            "expires_at": int(time.time()) + 3600}}
        result = check_meta(meta)
        self.assertTrue(result.present)
        self.assertTrue(result.well_formed)
        self.assertFalse(result.expired)

    def test_expired_attestation_flagged(self):
        meta = {ATTESTATION_KEY: {
            "alg": "ed25519", "sig": "YmFzZTY0",
            "expires_at": int(time.time()) - 10}}
        result = check_meta(meta)
        self.assertTrue(result.present)
        self.assertTrue(result.expired)
        self.assertIn("expired", " ".join(result.problems))

    def test_malformed_attestation_flagged_not_crashed(self):
        for bad in [{ATTESTATION_KEY: "not-a-dict"},
                    {ATTESTATION_KEY: {"alg": "ed25519"}},
                    {}]:
            result = check_meta(bad)
            self.assertIsInstance(result.problems, list)   # never raises


class TestOptionalSignatureVerification(unittest.TestCase):
    def test_verify_signature_returns_none_when_library_absent(self):
        from glassport import attestation
        if attestation.HAS_CRYPTO:
            self.skipTest("cryptography extra is installed in this env")
        result = attestation.verify_signature(b"payload", "c2ln", "cGs=")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
