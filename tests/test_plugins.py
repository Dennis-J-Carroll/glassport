"""
Tests for the custom-PII-pattern plugin registry: the register_pii_pattern()
API, JSON-file loading (declarative, validator-by-name), and the
GLASSPORT_PII_PATTERNS env-var autoload.

Drives the REAL adapter + data_exfiltration detector wherever possible, so a
registered pattern is proven end-to-end (it actually fires on a tap session),
not just present in a list. Pure stdlib.
"""
import json
import os
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from glassport.adapters.mcp_session import from_mcp_session
from glassport import detectors

from tests.test_detectors import handshake, call


class PluginRegistryBase(unittest.TestCase):
    def setUp(self):
        detectors.clear_custom_pii_patterns()
        os.environ.pop("GLASSPORT_PII_PATTERNS", None)

    def tearDown(self):
        detectors.clear_custom_pii_patterns()
        os.environ.pop("GLASSPORT_PII_PATTERNS", None)

    def exfil(self, args, name="web_search", tools=None):
        lines = handshake(tools=tools) + [call(6, 3, name, args)]
        return detectors.data_exfiltration(from_mcp_session(lines))

    def categories(self, anns):
        return [a.metadata.get("pii_category") for a in anns]


class TestRegisterApi(PluginRegistryBase):
    def test_registered_pattern_fires_end_to_end(self):
        detectors.register_pii_pattern(detectors.PIIPattern(
            "acme_token", 3, re.compile(r"acme-[A-Za-z0-9]{8,}"),
            None, "Acme API token"))
        anns = self.exfil({"q": "leak acme-DEADBEEF1234"})
        self.assertIn("acme_token", self.categories(anns))

    def test_clear_removes_custom_but_keeps_builtins(self):
        detectors.register_pii_pattern(detectors.PIIPattern(
            "acme_token", 3, re.compile(r"acme-[A-Za-z0-9]{8,}"),
            None, "Acme API token"))
        detectors.clear_custom_pii_patterns()
        anns = self.exfil({"q": "acme-DEADBEEF1234 and bob@example.com"})
        cats = self.categories(anns)
        self.assertNotIn("acme_token", cats)      # custom gone
        self.assertIn("email_address", cats)      # built-ins survive


class TestJsonLoader(PluginRegistryBase):
    def write_json(self, tmp, data):
        p = Path(tmp) / "pii.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_loaded_pattern_fires_and_returns_count(self):
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "acme_token", "severity": 3,
                 "pattern": r"acme-[A-Za-z0-9]{8,}",
                 "description": "Acme API token"}])
            n = detectors.load_pii_patterns_from_json(path)
        self.assertEqual(n, 1)
        anns = self.exfil({"q": "acme-DEADBEEF1234"})
        self.assertIn("acme_token", self.categories(anns))

    def test_validator_by_name_culls_false_positive(self):
        # 'entropy' validator must reject a low-entropy match (all same char)
        # and accept a high-entropy one, same as the built-in generic_api_key.
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "acme_secret", "severity": 3,
                 "pattern": r"ACME([A-Za-z0-9]{32})",
                 "validator": "entropy",
                 "description": "Acme secret (entropy-gated)"}])
            detectors.load_pii_patterns_from_json(path)
        low = self.exfil({"q": "ACME" + "a" * 32})            # 32 chars, H=0.0
        high = self.exfil({"q": "ACMEa9X2kQ7mZ3pL8vR1tB6nW4cD5fH0gJpQ"})  # 32, H=4.9
        self.assertNotIn("acme_secret", self.categories(low))
        self.assertIn("acme_secret", self.categories(high))

    def test_bad_regex_raises_valueerror(self):
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "broken", "severity": 2,
                 "pattern": r"(unclosed", "description": "bad"}])
            with self.assertRaises(ValueError):
                detectors.load_pii_patterns_from_json(path)

    def test_bad_severity_raises_valueerror(self):
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "x", "severity": 9,
                 "pattern": r"foo", "description": "bad sev"}])
            with self.assertRaises(ValueError):
                detectors.load_pii_patterns_from_json(path)

    def test_unknown_validator_name_raises_valueerror(self):
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "x", "severity": 2, "pattern": r"foo",
                 "validator": "no_such_validator", "description": "x"}])
            with self.assertRaises(ValueError):
                detectors.load_pii_patterns_from_json(path)


class TestNamedValidators(PluginRegistryBase):
    """The validator menu the JSON path resolves "validator":"<name>" against.
    Each name: one value it accepts, one it culls. Entropy values are measured,
    not guessed (H in bits/char): 'a'*32 = 0.0, hex digest = 3.906,
    base64 = 4.644, random alnum = 5.087, repeated word = 1.585."""
    V = staticmethod(lambda: detectors._NAMED_VALIDATORS)

    def test_menu_exposes_the_decided_names(self):
        # entropy/luhn/ssn from the registry PR; iban/aba added by the M2
        # checksum PR. New validators extend this set as they land.
        self.assertLessEqual(
            {"entropy", "entropy_high", "luhn", "ssn"}, set(self.V()))

    def test_luhn_accepts_valid_culls_invalid(self):
        luhn = self.V()["luhn"]
        self.assertTrue(luhn("4111111111111111"))      # valid Visa test number
        self.assertFalse(luhn("4111111111111112"))     # checksum fails

    def test_ssn_accepts_valid_culls_unissued_range(self):
        ssn = self.V()["ssn"]
        self.assertTrue(ssn("123-45-6789"))
        self.assertFalse(ssn("000-45-6789"))           # 000 area never issued

    def test_entropy_accepts_random_culls_repetition(self):
        ent = self.V()["entropy"]
        self.assertTrue(ent("ACMEa9X2kQ7mZ3pL8vR1tB6nW4cD5fH0gJ"))  # H=5.09
        self.assertFalse(ent("a" * 32))                             # H=0.0
        self.assertFalse(ent("abcabcabcabcabcabc"))                 # H=1.59

    def test_entropy_high_culls_what_entropy_keeps(self):
        # the tier gap: a 32-char hex digest (H=3.906) is a high-entropy
        # NON-secret. entropy keeps it; entropy_high (>4.0) culls it.
        digest = "a3f5c8b1d2e4f6a7b8c9d0e1f2a3b4c5"
        self.assertTrue(self.V()["entropy"](digest))
        self.assertFalse(self.V()["entropy_high"](digest))
        self.assertTrue(self.V()["entropy_high"](
            "Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBtZW4h"))        # H=4.64

    def test_every_validator_is_total(self):
        # a validator that raises crashes the scan and blinds detection — so
        # every one must return a bool on hostile input, never raise.
        for name, fn in self.V().items():
            for hostile in ("", "x" * 50_000, "​﻿", "123"):
                self.assertIsInstance(fn(hostile), bool,
                                      f"{name} not total on {hostile[:8]!r}")


class TestEnvAutoload(PluginRegistryBase):
    def write_json(self, tmp, data):
        p = Path(tmp) / "pii.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_env_var_autoloads_without_explicit_call(self):
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "acme_token", "severity": 3,
                 "pattern": r"acme-[A-Za-z0-9]{8,}",
                 "description": "Acme API token"}])
            os.environ["GLASSPORT_PII_PATTERNS"] = path
            # no load_pii_patterns_from_json() call — the scan must pick it up
            anns = self.exfil({"q": "acme-DEADBEEF1234"})
        self.assertIn("acme_token", self.categories(anns))

    def test_misconfigured_env_never_blinds_builtins(self):
        # A typo'd custom-pattern file must NOT raise out of the scan and must
        # NOT suppress built-in detection. Fail-safe, unlike the explicit load.
        with TemporaryDirectory() as tmp:
            bad = Path(tmp) / "broken.json"
            bad.write_text("{ this is not valid json ")
            os.environ["GLASSPORT_PII_PATTERNS"] = str(bad)
            import io
            import contextlib
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                anns = self.exfil({"q": "reach bob@example.com"})  # no raise
            self.assertIn("email_address", self.categories(anns))  # builtins live
            self.assertIn("GLASSPORT_PII_PATTERNS", err.getvalue())  # warned

    def test_clear_lets_env_reload(self):
        with TemporaryDirectory() as tmp:
            path = self.write_json(tmp, [
                {"category": "acme_token", "severity": 3,
                 "pattern": r"acme-[A-Za-z0-9]{8,}",
                 "description": "Acme API token"}])
            os.environ["GLASSPORT_PII_PATTERNS"] = path
            self.exfil({"q": "x"})                       # first load
            detectors.clear_custom_pii_patterns()        # resets the cache
            anns = self.exfil({"q": "acme-DEADBEEF1234"})  # reloads from env
        self.assertIn("acme_token", self.categories(anns))


if __name__ == "__main__":
    unittest.main()
