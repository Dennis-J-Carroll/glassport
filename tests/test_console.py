"""
Tests for console.py — the web console: stdlib HTTP + RFC 6455
WebSocket, serving the CRT frontend and streaming ViewModel JSON.

Security posture under test:
  * binds 127.0.0.1 unless --bind is explicit
  * WS handshake enforces an Origin check — cross-origin WebSocket has
    no same-origin policy, so any website could otherwise read the
    console of a localhost server
  * session names are confined to the log dir (no traversal)
  * no gate-toggle endpoint exists (would be CSRF-able)
Pure stdlib, run with:  python3 -m unittest tests.test_console
"""
import base64
import hashlib
import json
import socket
import struct
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from pathlib import Path

from glassport import console
from tests.test_detectors import handshake, call, result

RFC_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
RFC_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def mask_client_frame(payload: bytes, opcode: int = 1) -> bytes:
    """Build a masked client->server frame (clients MUST mask)."""
    mask = b"\x11\x22\x33\x44"
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n <= 125:
        header += bytes([0x80 | n])
    elif n <= 0xFFFF:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return header + mask + masked


class TestWSPrimitives(unittest.TestCase):
    def test_accept_key_rfc_vector(self):
        self.assertEqual(console.ws_accept(RFC_KEY), RFC_ACCEPT)

    def test_encode_text_small(self):
        frame = console.ws_encode_text("hi")
        self.assertEqual(frame, b"\x81\x02hi")

    def test_encode_text_medium_uses_16bit_length(self):
        frame = console.ws_encode_text("x" * 300)
        self.assertEqual(frame[0], 0x81)
        self.assertEqual(frame[1], 126)
        self.assertEqual(struct.unpack(">H", frame[2:4])[0], 300)

    def test_decoder_roundtrip_masked_text(self):
        d = console.WSDecoder()
        msgs = d.feed(mask_client_frame(b'{"attach":"s"}'))
        self.assertEqual(msgs, [(1, b'{"attach":"s"}')])

    def test_decoder_handles_split_frames(self):
        d = console.WSDecoder()
        frame = mask_client_frame(b"hello")
        self.assertEqual(d.feed(frame[:3]), [])
        self.assertEqual(d.feed(frame[3:]), [(1, b"hello")])

    def test_decoder_ping_and_close_opcodes(self):
        d = console.WSDecoder()
        msgs = d.feed(mask_client_frame(b"p", opcode=9)
                      + mask_client_frame(b"", opcode=8))
        self.assertEqual([op for op, _ in msgs], [9, 8])


class TestOriginCheck(unittest.TestCase):
    def test_absent_origin_allowed(self):
        self.assertTrue(console.origin_ok(None, "127.0.0.1:8080"))

    def test_matching_origin_allowed(self):
        self.assertTrue(console.origin_ok("http://127.0.0.1:8080",
                                          "127.0.0.1:8080"))

    def test_cross_origin_rejected(self):
        self.assertFalse(console.origin_ok("https://evil.example",
                                           "127.0.0.1:8080"))

    def test_same_host_wrong_port_rejected(self):
        self.assertFalse(console.origin_ok("http://127.0.0.1:9999",
                                           "127.0.0.1:8080"))


class TestSessionConfinement(unittest.TestCase):
    def test_traversal_and_junk_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "ok.jsonl").write_text("", encoding="utf-8")
            self.assertIsNotNone(console.safe_session("ok.jsonl", base))
            for bad in ("../etc/passwd", "/etc/passwd", "a/b.jsonl",
                        "ok.jsonl.gate", "missing.jsonl", ""):
                self.assertIsNone(console.safe_session(bad, base), bad)


class TestVMPayload(unittest.TestCase):
    def _write(self, tmp, lines):
        p = Path(tmp) / "s.jsonl"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_payload_shape_and_heatmap(self):
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}), result(7, 3),
            call(8, 4, "shadow_fetch", {"u": "http://x"}), result(9, 4),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, lines)
            from glassport.adapters.streaming import StreamingSession
            s = StreamingSession(p)
            s.poll()
            vm = console.vm_payload(s, live=True)
        self.assertEqual(vm["title"], "test-server")
        self.assertTrue(vm["live"])
        self.assertEqual(len(vm["rows"]), 9)
        self.assertEqual(vm["collapsed_rows"], 0)
        self.assertTrue(vm["findings"])
        heat = {h["tool"]: h for h in vm["heatmap"]}
        self.assertIn("shadow_fetch", heat)
        self.assertTrue(heat["shadow_fetch"]["fabricated"])
        self.assertEqual(heat["web_search"]["calls"], 1)

    def test_rows_capped_with_collapsed_count(self):
        lines = handshake()
        for i in range(600):
            lines.append(call(6 + 2 * i, 3 + i, "web_search",
                              {"query": "x"}))
            lines.append(result(7 + 2 * i, 3 + i))
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, lines)
            from glassport.adapters.streaming import StreamingSession
            s = StreamingSession(p)
            s.poll()
            vm = console.vm_payload(s, live=False, max_rows=1000)
        self.assertEqual(len(vm["rows"]), 1000)
        self.assertEqual(vm["collapsed_rows"], 1205 - 1000)
        json.dumps(vm)     # must be wire-serializable as-is


class TestHTTPEndpoints(unittest.TestCase):
    """One live server per class, ephemeral port, real sockets."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.log_dir = Path(cls.tmp.name)
        lines = handshake() + [
            call(6, 3, "web_search", {"query": "x"}), result(7, 3)]
        (cls.log_dir / "a.jsonl").write_text(
            "\n".join(lines) + "\n", encoding="utf-8")
        cls.server = console.ConsoleServer(cls.log_dir, port=0)
        cls.port = cls.server.port
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.tmp.cleanup()

    def _get(self, path):
        return urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}{path}", timeout=5)

    def test_default_bind_is_loopback(self):
        self.assertEqual(self.server.host, "127.0.0.1")

    def test_console_page_served(self):
        body = self._get("/console").read().decode()
        self.assertIn("glassport", body.lower())
        self.assertIn("<html", body.lower())
        # air-gap: no external URLs fetched by the page
        self.assertNotIn("https://cdn.", body)
        self.assertNotIn("googleapis", body)

    def test_root_redirects_to_console(self):
        r = self._get("/")
        self.assertIn("glassport", r.read().decode().lower())

    def test_sessions_listing(self):
        data = json.loads(self._get("/api/sessions").read())
        self.assertEqual([s["name"] for s in data], ["a.jsonl"])

    def test_traversal_is_400(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/api/advise?session=../../etc/passwd")
        self.assertEqual(ctx.exception.code, 400)

    def test_advise_and_sarif_endpoints(self):
        adv = self._get("/api/advise?session=a.jsonl").read().decode()
        self.assertIn("glassport", adv)
        sarif = json.loads(self._get("/api/sarif?session=a.jsonl").read())
        self.assertEqual(sarif["version"], "2.1.0")

    def test_unknown_path_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/nope")
        self.assertEqual(ctx.exception.code, 404)

    # ── WebSocket end-to-end ────────────────────────────────────

    def _ws_connect(self, origin):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        headers = [f"GET /ws HTTP/1.1",
                   f"Host: 127.0.0.1:{self.port}",
                   "Upgrade: websocket",
                   "Connection: Upgrade",
                   f"Sec-WebSocket-Key: {RFC_KEY}",
                   "Sec-WebSocket-Version: 13"]
        if origin:
            headers.append(f"Origin: {origin}")
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
        # read the HTTP response head
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        return sock, head

    def test_ws_handshake_and_vm_push(self):
        sock, head = self._ws_connect(f"http://127.0.0.1:{self.port}")
        try:
            self.assertIn(b"101", head.split(b"\r\n", 1)[0])
            self.assertIn(RFC_ACCEPT.encode(), head)
            sock.sendall(mask_client_frame(
                json.dumps({"attach": "a.jsonl"}).encode()))
            deadline = time.time() + 5
            d = console.WSDecoder()
            payload = None
            while time.time() < deadline and payload is None:
                data = sock.recv(65536)
                if not data:
                    break
                for op, body in d.feed(data):
                    if op == 1:
                        payload = json.loads(body)
            self.assertIsNotNone(payload)
            self.assertEqual(payload["type"], "vm")
            self.assertEqual(payload["session"], "a.jsonl")
            self.assertEqual(payload["vm"]["title"], "test-server")
        finally:
            sock.close()

    def test_ws_ping_answered_with_pong(self):
        sock, head = self._ws_connect(None)     # absent origin: allowed
        try:
            self.assertIn(b"101", head.split(b"\r\n", 1)[0])
            sock.sendall(mask_client_frame(b"echo", opcode=9))
            deadline = time.time() + 5
            d = console.WSDecoder()
            pong = None
            while time.time() < deadline and pong is None:
                data = sock.recv(65536)
                if not data:
                    break
                for op, body in d.feed(data):
                    if op == 10:
                        pong = body
            self.assertEqual(pong, b"echo")
        finally:
            sock.close()

    def test_ws_cross_origin_rejected(self):
        sock, head = self._ws_connect("https://evil.example")
        try:
            self.assertIn(b"403", head.split(b"\r\n", 1)[0])
        finally:
            sock.close()


class TestServeDispatch(unittest.TestCase):
    def test_serve_http_flag_reaches_console(self):
        from glassport import server as server_mod
        # bad usage must not start a server: --http with unknown arg
        rc = server_mod.main(["--http", "--nonsense"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
