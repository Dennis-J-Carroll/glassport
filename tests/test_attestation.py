from __future__ import annotations
import base64
import copy
import json
import time
import unittest
from unittest import mock

from glassport import attestation
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
        with mock.patch.object(attestation, "HAS_CRYPTO", False):
            result = attestation.verify_signature(b"payload", "c2ln", "cGs=")
        self.assertIsNone(result)


class TestSigningPayload(unittest.TestCase):
    def test_excludes_only_signature_without_mutating_input(self):
        params = {"name": "search", "arguments": {"query": "café"},
                  "_meta": {"trace": "keep", ATTESTATION_KEY: {
                      "alg": "ed25519", "sig": "signature", "expires_at": 9999999999}}}
        original = copy.deepcopy(params)
        expected = copy.deepcopy(params)
        del expected["_meta"][ATTESTATION_KEY]["sig"]
        payload = attestation.signing_payload(params)
        self.assertEqual(json.loads(payload), expected)
        self.assertEqual(payload, json.dumps(expected, sort_keys=True,
                                            separators=(",", ":"), ensure_ascii=True,
                                            allow_nan=False).encode("utf-8"))
        self.assertEqual(params, original)
        params["_meta"][ATTESTATION_KEY]["sig"] = "different signature"
        self.assertEqual(attestation.signing_payload(params), payload)

    def test_rejects_non_finite_numbers(self):
        params = {"name": "search", "arguments": {"n": float("nan")},
                  "_meta": {ATTESTATION_KEY: {"alg": "ed25519"}}}
        with self.assertRaises(ValueError):
            attestation.signing_payload(params)

    @unittest.skipUnless(attestation.HAS_CRYPTO, "optional cryptography extra not installed")
    def test_verify_real_signature_rejects_tampering_and_bad_encoding(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        key = Ed25519PrivateKey.generate()
        public_key = base64.b64encode(key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)).decode("ascii")
        signature = base64.b64encode(key.sign(b"payload")).decode("ascii")
        self.assertTrue(attestation.verify_signature(b"payload", signature, public_key))
        self.assertFalse(attestation.verify_signature(b"tampered", signature, public_key))
        self.assertFalse(attestation.verify_signature(b"payload", signature + "!", public_key))


if __name__ == "__main__":
    unittest.main()
