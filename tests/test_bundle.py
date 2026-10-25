"""Bundle integrity, replay, delivery, and public-tier regression tests."""
from __future__ import annotations

import json
import base64
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from urllib.parse import quote
from unittest import mock

from glassport import bundle, tap
from tests.test_decision_journal import JournalCase, wire
from tests.test_http_gate import GateCase


class TestCanonicalization(unittest.TestCase):
    def test_rfc8785_order_unicode_and_numbers(self):
        value = {"\ue000": 1, "\U00010000": 2, "z": "é", "n": 300.0,
                 "tiny": 1e-6, "small": 1e-7}
        self.assertEqual(bundle.canonical_bytes(value),
                         ('{"n":300,"small":1e-7,"tiny":0.000001,"z":"é",'
                          '"𐀀":2,"":1}').encode("utf-8"))
        with self.assertRaises(ValueError):
            bundle.canonical_bytes({"n": float("nan")})
        self.assertEqual(bundle.canonical_bytes([
            333333333.33333329, 1e30, 4.50, 2e-3, 1e-27]),
            b"[333333333.3333333,1e+30,4.5,0.002,1e-27]")

    def test_lone_surrogate_is_clean_refusal(self):
        with self.assertRaises(UnicodeError):
            bundle.canonical_bytes({"bad": "\ud800"})
        with mock.patch.object(bundle, "build_bundle",
                               side_effect=UnicodeEncodeError("utf-8", "\ud800", 0, 1,
                                                              "surrogates not allowed")):
            self.assertEqual(bundle.main(["--wire", "sample.jsonl", "-o", "out"]), 2)


class TestBundleSynthetic(JournalCase):
    def capture(self, secret=None, *, sign=False, redact=False, audit_path=None):
        lease = self.session()
        args = {"query": secret, secret: "key-canary"} if secret else {}
        self.observed(lease, wire(id=4, method="tools/call",
                                  params={"name": "search", "arguments": args}))
        epoch = lease.context.epoch
        lease.release()
        self.observer.close()
        self.journal.close()
        key_file = pub_file = None
        if sign:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = Ed25519PrivateKey.generate()
            key_file, pub_file = self.root / "sign.key", self.root / "sign.pub"
            key_file.write_bytes(key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))
            pub_file.write_bytes(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        out = self.root / "bundle"
        manifest = bundle.build_bundle([self.wire_path(epoch)],
                                       self.root / "decisions", audit_path, out,
                                       key_file, redact)
        return out, manifest, pub_file

    def test_build_verify_and_no_manifest_verdicts(self):
        out, manifest, _ = self.capture()
        self.assertEqual(manifest["schema"], "glassport.bundle/1")
        self.assertEqual(manifest["canonicalization"], "RFC8785")
        self.assertEqual(out.joinpath("manifest.json").read_bytes(),
                         bundle.canonical_bytes(manifest))
        self.assertEqual(bundle.verify_bundle(out)["analysis_reproduced"]["status"],
                         "equivalent")
        self.assertEqual(bundle.verify_bundle(out)["delivery_evidence_present"]["status"],
                         "present")
        self.assertFalse({"verified", "valid", "equivalent"} & set(manifest))
        result = json.loads((out / "index/findings.sarif.json").read_text())
        for finding in result["runs"][0]["results"]:
            self.assertIn(finding["partialFingerprints"]["stable_id"],
                          manifest["analysis"]["findings"])
        with self.assertRaisesRegex(ValueError, "not empty"):
            bundle.build_bundle([self.wire_path(manifest["evidence"]["epochs"][0]["epoch"])],
                                self.root / "decisions", None, out)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"),
                         "optional cryptography extra not installed")
    def test_signature_status_and_manifest_edit(self):
        out, _, pub = self.capture(sign=True)
        self.assertTrue(bundle.verify_bundle(out, pub)["integrity"]["signature"].startswith(
            "valid (fingerprint "))
        wrong = self.root / "wrong.pub"
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        wrong.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.assertIn("signature_invalid",
                      bundle.verify_bundle(out, wrong)["integrity"]["reasons"])
        manifest = json.loads((out / "manifest.json").read_text())
        manifest["bundler"]["version"] = "tampered"
        (out / "manifest.json").write_bytes(bundle.canonical_bytes(manifest))
        self.assertIn("signature_invalid",
                      bundle.verify_bundle(out, pub)["integrity"]["reasons"])

    def test_wire_and_journal_tampers_named(self):
        out, manifest, _ = self.capture()
        item = manifest["evidence"]["epochs"][0]
        wire_path = out / item["wire"]["path"]
        journal_path = out / item["journal"]["path"]
        pristine_wire, pristine_journal = wire_path.read_bytes(), journal_path.read_bytes()
        wire_path.write_bytes(pristine_wire.replace(b'"search"', b'"searck"', 1))
        found = bundle.verify_bundle(out)
        self.assertIn("wire_sha256_mismatch", found["integrity"]["reasons"])
        self.assertIn("trailer_log_sha256_mismatch",
                      found["delivery_evidence_present"]["epochs"][0]["reasons"])
        wire_path.write_bytes(pristine_wire)
        lines = pristine_journal.splitlines(keepends=True)
        journal_path.write_bytes(b"".join(lines[:1] + lines[2:]))
        found = bundle.verify_bundle(out)
        self.assertIn("journal_chain_mismatch",
                      found["analysis_reproduced"]["epochs"][0]["reasons"])
        journal_path.write_bytes(b"".join(lines[:-1]))
        found = bundle.verify_bundle(out)
        self.assertIn("journal_final_record_mismatch", found["integrity"]["reasons"])
        self.assertIn("delivery_missing_or_duplicate",
                      found["delivery_evidence_present"]["epochs"][0]["reasons"])

    def test_malformed_wire_still_reports_verdicts_and_limits(self):
        out, manifest, _ = self.capture()
        wire_path = out / manifest["evidence"]["epochs"][0]["wire"]["path"]
        wire_path.write_bytes(b"{invalid-json\n")
        found = bundle.verify_bundle(out)
        self.assertEqual(found["analysis_reproduced"]["status"], "incomplete")
        self.assertEqual(found["delivery_evidence_present"]["status"], "incomplete")
        self.assertIn("bundle_unreadable", found["integrity"]["reasons"])
        self.assertEqual(found["limits"], manifest["limits"])

    def test_public_canary_absent_everywhere(self):
        secret = "sk-" + "A" * 40
        out, manifest, _ = self.capture(secret, redact=True)
        public = out / "public"
        raw = secret.encode()
        encoded = {
            "plaintext": raw,
            "hex lower": raw.hex().encode(),
            "hex upper": raw.hex().upper().encode(),
            "percent": quote(secret, safe="").encode(),
            "json unicode": "".join(f"\\u{byte:04x}" for byte in raw).encode(),
        }
        for alignment in range(3):
            # Trim edge quartets; interior base64 survives unknown JSON offsets.
            encoded[f"base64 alignment {alignment}"] = (
                base64.b64encode(b"x" * alignment + raw)[4:-4])
        wire_records = [json.loads(line) for line in (out /
            manifest["evidence"]["epochs"][0]["wire"]["path"]).read_text().splitlines()]
        self.assertTrue(any("wire_b64" in record for record in wire_records))
        for path in public.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                for form, value in encoded.items():
                    self.assertNotIn(value, data, f"{path}: {form}")
        data = json.loads((public / "manifest.json").read_text())
        self.assertEqual(data["raw_tier"], "withheld")
        self.assertIn(manifest["evidence"]["epochs"][0]["wire"]["path"],
                      data["raw_hashes"])
        self.assertEqual(data["evidence"]["epochs"][0]["replay_argv"], None)
        public_wire = public / data["evidence"]["epochs"][0]["wire"]["path"]
        public_records = [json.loads(line) for line in public_wire.read_text().splitlines()]
        self.assertTrue(any("wire_b64_sha256" in row for row in public_records))
        for raw_record, public_record in zip(wire_records, public_records):
            if "wire_b64" in raw_record:
                self.assertEqual(public_record["wire_b64_sha256"], bundle._digest(
                    base64.b64decode(raw_record["wire_b64"])))
        self.assertTrue(all(not ({"wire_b64", "frame", "raw", "sse_meta",
                                 "http_observation"} & set(row)) for row in public_records))
        self.assertIn({"code": "public_raw_bytes_removed", "entries": 6}, data["limits"])
        self.assertIn({"code": "no_signature"}, data["limits"])
        self.assertEqual(bundle.main(["verify", "--public", str(public), "--json"]), 2)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"),
                         "optional cryptography extra not installed")
    def test_public_signature_hashes_and_cross_verification(self):
        out, _, pub = self.capture(sign=True, redact=True)
        public = out / "public"
        manifest = json.loads((public / "manifest.json").read_text())
        self.assertEqual(manifest["signed"], "public_manifest")
        self.assertNotIn("no_signature", {x["code"] for x in manifest["limits"]})
        good = bundle.verify_bundle(public, pub, public=True)
        self.assertEqual(good["integrity"]["status"], "passed")
        self.assertTrue(good["integrity"]["signature"].startswith("valid (fingerprint "))
        self.assertEqual(good["analysis_reproduced"]["status"], "not_applicable_redacted")
        self.assertEqual(good["delivery_evidence_present"]["status"],
                         "records_present_digests_withheld")
        self.assertEqual(bundle.verify_exit_code(good), 2)

        raw_sig = (out / "manifest.sig").read_bytes()
        (out / "manifest.sig").write_bytes((public / "manifest.sig").read_bytes())
        self.assertIn("signature_invalid",
                      bundle.verify_bundle(out, pub)["integrity"]["reasons"])
        (out / "manifest.sig").write_bytes(raw_sig)

        wrong = self.root / "wrong.pub"
        wrong.write_bytes(b"x" * 32)
        self.assertEqual(bundle.main(["verify", "--public", str(public),
                                      "--trusted-key", str(wrong), "--json"]), 1)
        wire = public / manifest["evidence"]["epochs"][0]["wire"]["path"]
        wire.write_bytes(wire.read_bytes() + b" ")
        self.assertIn("wire_sha256_mismatch",
                      bundle.verify_bundle(public, pub, public=True)["integrity"]["reasons"])

    @unittest.skipUnless(importlib.util.find_spec("cryptography"),
                         "optional cryptography extra not installed")
    def test_unreadable_trusted_key_does_not_hide_evidence_verdict(self):
        out, _, _ = self.capture(sign=True)
        result = bundle.verify_bundle(out, self.root / "missing.pub")
        self.assertEqual(result["integrity"]["status"], "passed")
        self.assertEqual(result["integrity"]["signature"], "trusted_key_unreadable")
        self.assertEqual(result["analysis_reproduced"]["status"], "equivalent")
        self.assertEqual(bundle.verify_exit_code(result), 2)

    def test_static_audit_indexed_and_copied(self):
        source = self.root / "server.py"
        source.write_text("import urllib.request\n", encoding="utf-8")
        out, manifest, _ = self.capture(audit_path=source)
        self.assertEqual(manifest["evidence"]["audit"]["path"],
                         "evidence/audit.json")
        self.assertTrue((out / "evidence/audit.json").exists())
        findings = manifest["analysis"]["findings"]
        self.assertIn("glassport/net-egress", {f["rule_id"] for f in findings.values()})
        self.assertTrue(any(f["source"] == "audit" and f["epoch"] is None
                            for f in findings.values()))
        self.assertTrue(all(f["source"] == "wire" for f in findings.values()
                            if f["epoch"] is not None))
        self.assertEqual(bundle.verify_bundle(out)["integrity"]["status"], "passed")

    def test_public_audit_text_is_withheld(self):
        source = self.root / "server.py"
        source.write_text('import urllib.request\n', encoding="utf-8")
        out, _, _ = self.capture(audit_path=source, redact=True)
        public = out / "public"
        manifest = json.loads((public / "manifest.json").read_text())
        self.assertIsNone(manifest["evidence"]["audit"])
        self.assertFalse((public / "evidence/audit.json").exists())
        self.assertIn({"code": "public_audit_removed"}, manifest["limits"])
        self.assertTrue(any(f["source"] == "audit" and f["epoch"] is None
                            for f in manifest["analysis"]["findings"].values()))
        self.assertEqual(bundle.verify_bundle(public, public=True)["integrity"]["status"],
                         "passed")

    def test_sign_without_cryptography_fails(self):
        with mock.patch.object(bundle, "_load_private_key",
                               side_effect=ValueError("--sign requires cryptography")):
            with self.assertRaisesRegex(ValueError, "requires cryptography"):
                bundle.build_bundle([self.root / "absent.jsonl"], None, None,
                                    self.root / "bundle", self.root / "key")


class TestBundleStrictHttp(GateCase):
    def test_three_levels_and_bundle_verifies(self):
        self.proxy(strict=True)
        self.handshake(declare=False)
        self.call("search", rid=4)
        self.post({"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
                  session="sess-1")
        self.call("ghost", rid=6)
        self.call("search", rid=7)
        self.quiesce()
        self.observer.close()
        self.journal.close()
        out = self.root / "bundle"
        manifest = bundle.build_bundle(sorted((self.root / "wire").glob("*.jsonl")),
                                       self.root / "decisions", None, out)
        self.assertEqual({d["evidence_level"] for d in manifest["delivery"]},
                         {"blocked_policy", "blocked_evidence_gap", "forwarded"})
        self.assertEqual(bundle.main(["verify", str(out), "--json"]), 0)
