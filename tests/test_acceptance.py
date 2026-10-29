"""Published end-to-end acceptance rows: upstream receipt and bundle verdicts."""
from __future__ import annotations

import io
import base64
import importlib.util
import threading
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
import urllib.error
from urllib.parse import quote
import urllib.request
from unittest import mock

from glassport import bundle, decision_journal as dj, detectors, tap
from glassport.stdio_sessions import StdioObserver
from tests.acceptance_matrix import manifest_hash, normalized_manifest, published_rows
from tests.test_http_gate import GateCase, Upstream
from tests.test_http_gate_correlation import SlowUpstream
from tests.test_http_stateless_scopes import ScopeCase
from tests.test_public_gate import _Sink, _line, assert_public_strings


_DOC = Path(__file__).resolve().parents[1] / "docs" / "acceptance.md"
_RECORDED: dict[str, tuple[int, str, str]] = {}


def _encoded_forms(secret: str) -> dict[str, bytes]:
    raw = secret.encode()
    forms = {"plain": raw, "hex-lower": raw.hex().encode(),
             "hex-upper": raw.hex().upper().encode(),
             "percent": quote(secret, safe="").encode(),
             "json-unicode": "".join(f"\\u{byte:04x}" for byte in raw).encode()}
    for alignment in range(3):
        forms[f"base64-{alignment}"] = base64.b64encode(
            b"x" * alignment + raw)[4:-4]
    return forms


def _assert_public_canary(test: unittest.TestCase, public: Path, secret: str):
    for path in public.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for label, form in _encoded_forms(secret).items():
                test.assertNotIn(form, data, f"{path}: {label}")


def _wait_deliveries(test: unittest.TestCase, root: Path, count: int):
    deadline = time.monotonic() + 5
    deliveries = 0
    while time.monotonic() < deadline:
        deliveries = sum(1 for path in (root / "decisions").glob("*.jsonl")
                         for line in path.read_text().splitlines()
                         if json.loads(line).get("kind") == "delivery")
        if deliveries >= count:
            break
        time.sleep(0.01)
    test.assertGreaterEqual(deliveries, count)


def _assert_row(test: unittest.TestCase, name: str, manifest: dict, verdict: dict,
                expected_code: int, expected_reason: str):
    code = bundle.verify_exit_code(verdict)
    test.assertEqual(code, expected_code, name)
    reasons = ({item["code"] for item in verdict["limits"]} |
               set(verdict["integrity"]["reasons"]) |
               {reason for epoch in verdict["analysis_reproduced"]["epochs"]
                for reason in epoch.get("reasons", [])} |
               {reason for epoch in verdict["delivery_evidence_present"]["epochs"]
                for reason in epoch.get("reasons", [])})
    test.assertIn(expected_reason, reasons, name)
    digest = manifest_hash(manifest)
    if os.environ.get("GLASSPORT_ACCEPTANCE_DUMP"):
        destination = Path(os.environ["GLASSPORT_ACCEPTANCE_DUMP"])
        if destination.is_dir():
            destination /= name + ".json"
        destination.write_text(
            json.dumps(normalized_manifest(manifest), indent=2, sort_keys=True))
    _RECORDED[name] = (code, expected_reason, digest)
    if os.environ.get("GLASSPORT_ACCEPTANCE_RECORD"):
        print(f"ACCEPTANCE_ROW {name} {test.id()} {code} {expected_reason} {digest}")
    else:
        published = published_rows(_DOC)
        test.assertIn(name, published)
        test.assertEqual(published[name]["command"],
                         f"PYTHONPATH=src python -m unittest {test.id()}")
        test.assertEqual(published[name]["verdict"], f"{code}: {expected_reason}")
        test.assertEqual(published[name]["hash"], digest)


class TestHTTPAcceptance(GateCase):
    """Fresh proxy and upstream per row; modes are separate fixtures."""

    def run_row(self, mode_name: str, scenario: str):
        mode = dj.MODE_OBSERVE if mode_name == "observe" else dj.MODE_GATE
        self.proxy(mode=mode, strict=mode_name == "http-strict")
        if scenario != "no-list-client":
            self.handshake(declare=scenario != "missing-declaration")
            _wait_deliveries(self, self.root,
                             2 if scenario == "missing-declaration" else 3)
        before = len(self.upstream_calls())
        if scenario == "malformed-body":
            request = urllib.request.Request(
                self.url, data=b"{bad-json", headers={
                    "Content-Type": "application/json", "Mcp-Session-Id": "sess-1"})
            try:
                urllib.request.urlopen(request, timeout=10).read()
            except urllib.error.HTTPError as exc:
                exc.read()
            forwarded = mode_name == "observe"
        elif scenario == "detector-fault":
            with mock.patch.object(detectors, "_scan_pii",
                                   side_effect=RuntimeError("injected fault")):
                self.call("ghost")
            forwarded = mode_name != "http-strict"
        elif scenario == "missing-declaration":
            try:
                self.call("search")
            except urllib.error.HTTPError as exc:
                exc.read()
            forwarded = mode_name != "http-strict"
        elif scenario == "no-list-client":
            try:
                self.call("search", session=None)
            except urllib.error.HTTPError as exc:
                exc.read()
            forwarded = mode_name != "http-strict"
        elif scenario == "stale-surface":
            Upstream.tools = ["fetch"]
            self.post({"jsonrpc": "2.0", "id": 6, "method": "tools/list"},
                      session="sess-1")
            before = len(self.upstream_calls())
            try:
                self.call("search")
            except urllib.error.HTTPError as exc:
                exc.read()
            forwarded = mode_name == "observe"
        elif scenario == "no-event-observation":
            request = urllib.request.Request(
                self.url, data=b"", headers={
                    "Content-Type": "application/json", "Mcp-Session-Id": "sess-1"})
            try:
                urllib.request.urlopen(request, timeout=10).read()
            except urllib.error.HTTPError as exc:
                exc.read()
            forwarded = mode_name == "observe"
        elif scenario == "failed-wire-write":
            class FailingFile:
                def __init__(self, original):
                    self.original = original
                    self.failed = False

                def write(self, value):
                    if not self.failed and b"tools/call" in value:
                        self.failed = True
                        raise OSError("injected wire write failure")
                    return self.original.write(value)

                def __getattr__(self, name):
                    return getattr(self.original, name)

            with self.observer._lock:
                logs = [context.log for context in self.observer._contexts.values()
                        if context.log is not None]
            self.assertEqual(len(logs), 1)
            writer = FailingFile(logs[0]._fh)
            logs[0]._fh = writer
            try:
                self.call("ghost")
            except urllib.error.HTTPError as exc:
                exc.read()
            self.assertTrue(writer.failed)
            forwarded = mode_name != "http-strict"
        elif scenario == "public-canary":
            canary = "sk-" + "A" * 40
            self.call("search", args={canary: "key-canary"})
            forwarded = True
        else:
            raise AssertionError(scenario)
        self.quiesce()
        received = len(self.upstream_calls()) - before
        if os.environ.get("GLASSPORT_ACCEPTANCE_RECORD"):
            print("ACCEPTANCE_DEBUG", mode_name, scenario, "upstream", received)
        self.assertEqual(received, int(forwarded), f"{mode_name}/{scenario}: upstream")
        expected_records = (0 if scenario == "no-list-client" else
                            2 if scenario == "missing-declaration" else 3) + 1 + (
                                1 if scenario == "stale-surface" else 0)
        self.records(settle=expected_records)
        self.observer.close()
        out = self.root / "bundle"
        manifest = bundle.build_bundle(sorted((self.root / "wire").glob("*.jsonl")),
                                       self.root / "decisions", None, out,
                                       redact=scenario == "public-canary")
        if scenario == "public-canary":
            public = out / "public"
            _assert_public_canary(self, public, canary)
            assert_public_strings(self, public)
            public_manifest = json.loads((public / "manifest.json").read_text())
            verdict = bundle.verify_bundle(public, public=True)
            self.assertEqual(verdict["analysis_reproduced"]["status"],
                             "not_applicable_redacted")
            self.assertEqual(verdict["delivery_evidence_present"]["status"],
                             "records_present_digests_withheld")
            _assert_row(self, f"acceptance.{mode_name}.{scenario}", public_manifest,
                        verdict, 2, "public_gate_tool_hashed")
            return
        verdict = bundle.verify_bundle(out)
        if os.environ.get("GLASSPORT_ACCEPTANCE_RECORD"):
            print("ACCEPTANCE_VERDICT", mode_name, scenario, json.dumps(verdict))
        if scenario == "failed-wire-write":
            self.assertIn("write_failures", {item["code"] for item in manifest["limits"]})
        incomplete_analysis = scenario in ("detector-fault", "failed-wire-write")
        incomplete_delivery = (scenario == "no-event-observation" or
                               scenario == "failed-wire-write" or
                               scenario == "malformed-body" and mode_name != "observe")
        self.assertEqual(verdict["analysis_reproduced"]["status"],
                         "incomplete" if incomplete_analysis else "equivalent")
        self.assertEqual(verdict["delivery_evidence_present"]["status"],
                         "incomplete" if incomplete_delivery else "present")
        reason = ("missing_wire_evidence" if scenario == "failed-wire-write" else
                  "recorded_fault_not_re_executed" if incomplete_analysis else
                  "wire_digest_missing" if incomplete_delivery else
                  "strict_profile" if mode_name == "http-strict" else "default_profile")
        _assert_row(self, f"acceptance.{mode_name}.{scenario}", manifest, verdict,
                    2 if incomplete_analysis or incomplete_delivery else 0, reason)


for _mode in ("http-default", "http-strict", "observe"):
    for _scenario in ("malformed-body", "missing-declaration", "stale-surface",
                      "detector-fault", "no-list-client", "no-event-observation",
                      "failed-wire-write", "public-canary"):
        def _make(mode_name=_mode, scenario=_scenario):
            def test(self):
                self.run_row(mode_name, scenario)
            return test
        setattr(TestHTTPAcceptance, f"test_{_mode.replace('-', '_')}_{_scenario.replace('-', '_')}",
                _make())


class TestStdioAcceptance(unittest.TestCase):
    def run_row(self, scenario: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = tap.open_session_log(root / "wire.jsonl", transport="stdio", mode="gate")
            observer = StdioObserver(log)
            journal = dj.DecisionJournal(root / "decisions", observer, mode="gate")
            observer.start(journal)
            upstream = _Sink()
            downstream = _Sink()
            gate = tap.Gate(hold_timeout=1.0 if scenario == "concurrent-correlation"
                            else 0.01)

            def send(direction: str, raw: bytes):
                tap.pump(io.BytesIO(raw), upstream if direction == "c2s" else downstream,
                         log, direction, gate=gate, client_write=downstream.write,
                         observer=observer, journal=journal)

            if scenario not in ("missing-declaration", "no-list-client",
                                "no-event-observation", "concurrent-correlation"):
                send("c2s", _line({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
                send("s2c", _line({"jsonrpc": "2.0", "id": 2,
                                   "result": {"tools": [{"name": "search"}]}}))
            if scenario == "stale-surface":
                send("c2s", _line({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}))
                send("s2c", _line({"jsonrpc": "2.0", "id": 3,
                                   "result": {"tools": [{"name": "fetch"}]}}))
            before = upstream.getvalue().count(b'"tools/call"')
            frame = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "search", "arguments": {}}}
            canary = "sk-" + "A" * 40
            if scenario == "public-canary":
                frame["params"]["arguments"] = {canary: "key-canary"}
            if scenario == "malformed-body":
                send("c2s", b"{bad-json\n")
                forwarded = False
            elif scenario == "no-event-observation":
                send("c2s", b"\n")
                forwarded = False
            elif scenario == "detector-fault":
                with mock.patch.object(gate, "check_c2s", side_effect=RuntimeError("injected")):
                    send("c2s", _line(frame))
                forwarded = True
            elif scenario == "failed-wire-write":
                class FailingFile:
                    def __init__(self, original):
                        self.original = original
                        self.failed = False

                    def write(self, value):
                        if not self.failed and b"tools/call" in value:
                            self.failed = True
                            raise OSError("injected stdio wire write failure")
                        return self.original.write(value)

                    def __getattr__(self, name):
                        return getattr(self.original, name)

                writer = FailingFile(log._fh)
                log._fh = writer
                send("c2s", _line(frame))
                self.assertTrue(writer.failed)
                forwarded = True
            elif scenario == "concurrent-correlation":
                # A tools/call races the correlated tools/list response.
                send("c2s", _line({"jsonrpc": "2.0", "id": 8,
                                   "method": "tools/list"}))
                finished = threading.Event()

                def pending_call():
                    send("c2s", _line(frame))
                    finished.set()

                worker = threading.Thread(target=pending_call)
                worker.start()
                time.sleep(0.02)
                self.assertFalse(finished.is_set())
                send("s2c", _line({"jsonrpc": "2.0", "id": 8,
                                   "result": {"tools": [{"name": "search"}]}}))
                worker.join(2)
                self.assertTrue(finished.is_set())
                forwarded = True
            else:
                send("c2s", _line(frame))
                forwarded = scenario in ("missing-declaration", "no-list-client")
            received = upstream.getvalue().count(b'"tools/call"') - before
            self.assertEqual(received, int(forwarded), scenario)
            observer.finish()
            log.write_metrics()
            log.close()
            journal.close()
            out = root / "bundle"
            manifest = bundle.build_bundle([root / "wire.jsonl"], None, None, out,
                                           redact=scenario == "public-canary")
            if scenario == "failed-wire-write":
                self.assertIn("write_failures", {item["code"] for item in manifest["limits"]})
            if scenario == "public-canary":
                public = out / "public"
                public_manifest = json.loads((public / "manifest.json").read_text())
                _assert_public_canary(self, public, canary)
                assert_public_strings(self, public)
                verdict = bundle.verify_bundle(public, public=True)
                self.assertEqual(verdict["analysis_reproduced"]["status"],
                                 "not_applicable_redacted")
                self.assertEqual(verdict["delivery_evidence_present"]["status"],
                                 "records_present_digests_withheld")
                _assert_row(self, f"acceptance.stdio-gate.{scenario}", public_manifest,
                            verdict, 2, "public_gate_tool_hashed")
            else:
                verdict = bundle.verify_bundle(out)
                failed = scenario == "failed-wire-write"
                self.assertEqual(verdict["analysis_reproduced"]["status"],
                                 "incomplete" if failed else "equivalent")
                self.assertEqual(verdict["delivery_evidence_present"]["status"],
                                 "incomplete" if failed else "present")
                reason = ("missing_wire_evidence" if failed else
                          "stdio_gate_reasons_not_replayed" if scenario in (
                              "detector-fault", "malformed-body", "missing-declaration", "no-list-client")
                          else "default_profile")
                _assert_row(self, f"acceptance.stdio-gate.{scenario}", manifest, verdict,
                            2 if failed else 0, reason)


for _scenario in ("malformed-body", "missing-declaration", "stale-surface",
                  "detector-fault", "no-list-client", "no-event-observation",
                  "public-canary", "failed-wire-write", "concurrent-correlation"):
    def _make_stdio(scenario=_scenario):
        def test(self):
            self.run_row(scenario)
        return test
    setattr(TestStdioAcceptance, f"test_{_scenario.replace('-', '_')}", _make_stdio())


class TestModernAnonymousAcceptance(ScopeCase):
    """Modern stateless callers, with public surface disabled and enabled."""

    def run_row(self, mode_name: str, public_surface: bool):
        mode = dj.MODE_OBSERVE if mode_name == "observe" else dj.MODE_GATE
        self.proxy(mode=mode, strict=mode_name == "http-strict",
                   public_surface=public_surface)
        self.lists(1, auth=None)
        _wait_deliveries(self, self.root, 1)
        action, received = self.call("ghost", 2, auth=None)
        expected_forward = (mode_name == "observe" or
                            mode_name == "http-default" and not public_surface)
        self.assertEqual(received, int(expected_forward), "upstream receipt")
        if mode_name != "http-strict":
            self.assertEqual(action, "forwarded" if expected_forward else "blocked")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            deliveries = sum(1 for path in (self.root / "decisions").glob("*.jsonl")
                             for line in path.read_text().splitlines()
                             if json.loads(line).get("kind") == "delivery")
            if deliveries >= 2:
                break
            time.sleep(0.01)
        self.assertGreaterEqual(deliveries, 2)
        self.observer.close()
        out = self.root / "bundle"
        wire_paths = sorted((self.root / "wire").glob("*.jsonl"),
                            key=lambda path: json.loads(
                                path.read_text().splitlines()[0])["started_at"])
        manifest = bundle.build_bundle(wire_paths,
                                       self.root / "decisions", None, out)
        verdict = bundle.verify_bundle(out)
        self.assertEqual(verdict["analysis_reproduced"]["status"], "equivalent")
        self.assertEqual(verdict["delivery_evidence_present"]["status"], "present")
        name = (f"acceptance.{mode_name}.anonymous-modern-" +
                ("public" if public_surface else "private"))
        _assert_row(self, name, manifest, verdict, 0,
                    "strict_profile" if mode_name == "http-strict" else "default_profile")


for _mode in ("http-default", "http-strict", "observe"):
    for _public in (False, True):
        def _make_modern(mode_name=_mode, public_surface=_public):
            def test(self):
                self.run_row(mode_name, public_surface)
            return test
        setattr(TestModernAnonymousAcceptance,
                f"test_{_mode.replace('-', '_')}_anonymous_modern_"
                f"{'public' if _public else 'private'}", _make_modern())


class TestMultiEpochAcceptance(ScopeCase):
    def run_row(self, mode_name: str):
        mode = dj.MODE_OBSERVE if mode_name == "observe" else dj.MODE_GATE
        self.proxy(mode=mode, strict=mode_name == "http-strict")
        self.lists(1, auth="Bearer A")
        _wait_deliveries(self, self.root, 1)
        action_a, count_a = self.call("ghost", 2, auth="Bearer A")
        _wait_deliveries(self, self.root, 2)
        self.lists(1, auth="Bearer B")
        _wait_deliveries(self, self.root, 3)
        action_b, count_b = self.call("ghost", 2, auth="Bearer B")
        self.assertEqual((count_a, count_b), (1, 1) if mode_name == "observe"
                         else (0, 0))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            deliveries = sum(1 for path in (self.root / "decisions").glob("*.jsonl")
                             for line in path.read_text().splitlines()
                             if json.loads(line).get("kind") == "delivery")
            if deliveries >= 4:
                break
            time.sleep(0.01)
        self.assertGreaterEqual(deliveries, 4)
        self.observer.close()
        wire_paths = sorted((self.root / "wire").glob("*.jsonl"),
                            key=lambda path: json.loads(
                                path.read_text().splitlines()[0])["started_at"])
        self.assertEqual(len(wire_paths), 2)
        out = self.root / "bundle"
        manifest = bundle.build_bundle(wire_paths, self.root / "decisions", None, out)
        self.assertEqual(len(manifest["evidence"]["epochs"]), 2)
        findings = manifest["analysis"]["findings"]
        self.assertEqual(len(findings), len(set(findings)))
        self.assertTrue(any(re.fullmatch(r"[0-9a-f]{24}-[0-9a-f]{8}(?:-\d+)?", key)
                            for key in findings),
                        "fixture did not exercise stable-ID collision")
        verdict = bundle.verify_bundle(out)
        if os.environ.get("GLASSPORT_ACCEPTANCE_RECORD"):
            print("ACCEPTANCE_MULTI_VERDICT", mode_name, json.dumps(verdict))
        self.assertEqual(verdict["analysis_reproduced"]["status"], "equivalent")
        self.assertEqual(verdict["delivery_evidence_present"]["status"], "present")
        _assert_row(self, f"acceptance.{mode_name}.multi-epoch-stable-id-collision",
                    manifest, verdict, 0,
                    "strict_profile" if mode_name == "http-strict" else "default_profile")


for _mode in ("http-default", "http-strict", "observe"):
    def _make_multi(mode_name=_mode):
        def test(self):
            self.run_row(mode_name)
        return test
    setattr(TestMultiEpochAcceptance,
            f"test_{_mode.replace('-', '_')}_multi_epoch_stable_id_collision",
            _make_multi())


class TestHTTPBundleMutationAcceptance(GateCase):
    """Tamper and trust-pinning rows start with real captured upstream traffic."""

    def run_row(self, mode_name: str, scenario: str):
        mode = dj.MODE_OBSERVE if mode_name == "observe" else dj.MODE_GATE
        self.proxy(mode=mode, strict=mode_name == "http-strict")
        self.handshake()
        _wait_deliveries(self, self.root, 3)
        before = len(self.upstream_calls())
        self.call("search")
        self.quiesce()
        self.assertEqual(len(self.upstream_calls()) - before, 1)
        self.records(settle=4)
        self.observer.close()
        wire_paths = sorted((self.root / "wire").glob("*.jsonl"))
        out = self.root / "bundle"
        if scenario == "signed-rewrite":
            if not importlib.util.find_spec("cryptography"):
                self.skipTest("optional cryptography extra missing")
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            def key_files(label):
                key = Ed25519PrivateKey.generate()
                private = self.root / f"{label}.key"
                public = self.root / f"{label}.pub"
                private.write_bytes(key.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                    serialization.NoEncryption()))
                public.write_bytes(key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                return private, public

            first_key, first_pub = key_files("original")
            second_key, second_pub = key_files("rewrite")
            bundle.build_bundle(wire_paths, self.root / "decisions", None,
                                out, sign_key=first_key)
            self.assertEqual(bundle.verify_exit_code(bundle.verify_bundle(out, first_pub)), 0)
            rewritten = self.root / "rewritten"
            manifest = bundle.build_bundle(wire_paths, self.root / "decisions", None,
                                           rewritten, sign_key=second_key)
            self.assertEqual(bundle.verify_exit_code(
                bundle.verify_bundle(rewritten, second_pub)), 0)
            verdict = bundle.verify_bundle(rewritten, first_pub)
            self.assertEqual(verdict["analysis_reproduced"]["status"], "equivalent")
            self.assertEqual(verdict["delivery_evidence_present"]["status"], "present")
            expected_reason = "signature_invalid"
        else:
            manifest = bundle.build_bundle(wire_paths, self.root / "decisions", None, out)
            if scenario == "malformed-bundle":
                (out / "manifest.json").write_bytes(b"{malformed")
                expected_reason = "bundle_unreadable"
            elif scenario == "epoch-mismatch":
                item = manifest["evidence"]["epochs"][0]
                wire = out / item["wire"]["path"]
                records = [json.loads(line) for line in wire.read_text().splitlines()]
                for record in records:
                    observation = record.get("http_observation")
                    if isinstance(observation, dict) and isinstance(
                            observation.get("epoch"), str):
                        observation["epoch"] = "f" * 32
                wire.write_text("".join(json.dumps(record) + "\n" for record in records))
                expected_reason = "wire_epoch_mismatch"
            else:
                raise AssertionError(scenario)
            verdict = bundle.verify_bundle(out)
        self.assertEqual(bundle.verify_exit_code(verdict), 1)
        _assert_row(self, f"acceptance.{mode_name}.{scenario}", manifest, verdict,
                    1, expected_reason)


for _mode in ("http-default", "http-strict", "observe"):
    for _scenario in ("malformed-bundle", "epoch-mismatch", "signed-rewrite"):
        def _make_mutation(mode_name=_mode, scenario=_scenario):
            def test(self):
                self.run_row(mode_name, scenario)
            return test
        setattr(TestHTTPBundleMutationAcceptance,
                f"test_{_mode.replace('-', '_')}_{_scenario.replace('-', '_')}",
                _make_mutation())


class TestStdioBundleMutationAcceptance(unittest.TestCase):
    def run_row(self, scenario: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_path = root / "wire.jsonl"
            log = tap.open_session_log(log_path, transport="stdio", mode="gate")
            observer = StdioObserver(log)
            journal = dj.DecisionJournal(root / "decisions", observer, mode="gate")
            observer.start(journal)
            upstream = _Sink()
            tap.pump(io.BytesIO(_line({"jsonrpc": "2.0", "id": 4,
                                       "method": "tools/call",
                                       "params": {"name": "search", "arguments": {}}})),
                     upstream, log, "c2s", gate=tap.Gate(hold_timeout=0.01),
                     observer=observer, journal=journal)
            self.assertEqual(upstream.getvalue().count(b'"tools/call"'), 1)
            observer.finish()
            log.write_metrics()
            log.close()
            journal.close()
            out = root / "bundle"
            if scenario == "signed-rewrite":
                if not importlib.util.find_spec("cryptography"):
                    self.skipTest("optional cryptography extra missing")
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

                def key_files(label):
                    key = Ed25519PrivateKey.generate()
                    private, public = root / f"{label}.key", root / f"{label}.pub"
                    private.write_bytes(key.private_bytes(
                        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                        serialization.NoEncryption()))
                    public.write_bytes(key.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
                    return private, public

                first_key, first_pub = key_files("original")
                second_key, second_pub = key_files("rewrite")
                bundle.build_bundle([log_path], None, None, out, sign_key=first_key)
                self.assertEqual(bundle.verify_exit_code(
                    bundle.verify_bundle(out, first_pub)), 0)
                rewritten = root / "rewritten"
                manifest = bundle.build_bundle([log_path], None, None, rewritten,
                                               sign_key=second_key)
                self.assertEqual(bundle.verify_exit_code(
                    bundle.verify_bundle(rewritten, second_pub)), 0)
                verdict = bundle.verify_bundle(rewritten, first_pub)
                self.assertEqual(verdict["analysis_reproduced"]["status"], "equivalent")
                self.assertEqual(verdict["delivery_evidence_present"]["status"], "present")
                reason = "signature_invalid"
            elif scenario == "malformed-bundle":
                manifest = bundle.build_bundle([log_path], None, None, out)
                (out / "manifest.json").write_bytes(b"{malformed")
                verdict = bundle.verify_bundle(out)
                reason = "bundle_unreadable"
            else:
                raise AssertionError(scenario)
            _assert_row(self, f"acceptance.stdio-gate.{scenario}", manifest,
                        verdict, 1, reason)

    def test_malformed_bundle(self):
        self.run_row("malformed-bundle")

    def test_signed_rewrite(self):
        self.run_row("signed-rewrite")


class TestConcurrentAcceptance(GateCase):
    def upstream(self):
        SlowUpstream.slow_tool = None
        srv = ThreadingHTTPServer(("127.0.0.1", 0), SlowUpstream)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}/mcp"

    def run_row(self, mode_name: str):
        mode = dj.MODE_OBSERVE if mode_name == "observe" else dj.MODE_GATE
        self.proxy(mode=mode, strict=mode_name == "http-strict")
        self.handshake()
        _wait_deliveries(self, self.root, 3)
        SlowUpstream.slow_tool = "search"
        before = len(self.upstream_calls())
        outcome = {}

        def slow_call():
            try:
                outcome["response"] = self.call("search", rid=7)[1]
            except Exception as exc:
                outcome["error"] = exc

        thread = threading.Thread(target=slow_call)
        thread.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(self.upstream_calls()) == before:
            time.sleep(0.01)
        self.assertEqual(len(self.upstream_calls()) - before, 1)
        try:
            self.call("ghost", rid=7)
        except urllib.error.HTTPError as exc:
            exc.read()
        thread.join(10)
        self.assertIn("response", outcome, outcome.get("error"))
        self.quiesce()
        expected = 2 if mode_name == "observe" else 1
        self.assertEqual(len(self.upstream_calls()) - before, expected)
        self.records(settle=5)
        self.observer.close()
        out = self.root / "bundle"
        manifest = bundle.build_bundle(sorted((self.root / "wire").glob("*.jsonl")),
                                       self.root / "decisions", None, out)
        verdict = bundle.verify_bundle(out)
        if os.environ.get("GLASSPORT_ACCEPTANCE_RECORD"):
            print("ACCEPTANCE_CONCURRENT_VERDICT", mode_name, json.dumps(verdict))
        self.assertEqual(verdict["analysis_reproduced"]["status"], "equivalent")
        self.assertEqual(verdict["delivery_evidence_present"]["status"], "present")
        _assert_row(self, f"acceptance.{mode_name}.concurrent-correlation",
                    manifest, verdict, 0,
                    "strict_profile" if mode_name == "http-strict" else "default_profile")


for _mode in ("http-default", "http-strict", "observe"):
    def _make_concurrent(mode_name=_mode):
        def test(self):
            self.run_row(mode_name)
        return test
    setattr(TestConcurrentAcceptance,
            f"test_{_mode.replace('-', '_')}_concurrent_correlation",
            _make_concurrent())


class TestAcceptancePublication(unittest.TestCase):
    def test_row_names_match_documented_table(self):
        tests = [name for name in dir(TestHTTPAcceptance) if name.startswith("test_")]
        expected = set()
        for name in tests:
            suffix = name[5:]
            for prefix, path in (("http_default_", "http-default"),
                                 ("http_strict_", "http-strict"),
                                 ("observe_", "observe")):
                if suffix.startswith(prefix):
                    expected.add(f"acceptance.{path}.{suffix[len(prefix):].replace('_', '-')}")
                    break
        expected.update("acceptance.stdio-gate." + scenario for scenario in
                        ("malformed-body", "missing-declaration", "stale-surface",
                         "detector-fault", "no-list-client", "no-event-observation",
                         "public-canary", "failed-wire-write", "concurrent-correlation"))
        expected.update(
            f"acceptance.{mode}.anonymous-modern-{tier}"
            for mode in ("http-default", "http-strict", "observe")
            for tier in ("private", "public"))
        expected.update(
            f"acceptance.{mode}.{scenario}"
            for mode in ("http-default", "http-strict", "observe")
            for scenario in ("malformed-bundle", "epoch-mismatch", "signed-rewrite"))
        expected.update(f"acceptance.{mode}.concurrent-correlation"
                        for mode in ("http-default", "http-strict", "observe"))
        expected.update(f"acceptance.{mode}.multi-epoch-stable-id-collision"
                        for mode in ("http-default", "http-strict", "observe"))
        expected.update(("acceptance.stdio-gate.malformed-bundle",
                         "acceptance.stdio-gate.signed-rewrite"))
        self.assertEqual(set(published_rows(_DOC)), expected)
