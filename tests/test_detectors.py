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


if __name__ == "__main__":
    unittest.main()
