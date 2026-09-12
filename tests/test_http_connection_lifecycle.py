"""Issue #77: deterministic resource ownership on every relay exit."""
import contextlib
import http.client
import io
import threading
import unittest
from email.message import Message
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from glassport.adapters import mcp_http
from glassport.tap import SessionLog


class TestUpstreamLifecycle(unittest.TestCase):
    def setUp(self):
        self.log = Mock()
        cls = mcp_http._make_handler(urlsplit("http://upstream.test/mcp"), self.log)
        self.handler = cls.__new__(cls)
        self.handler.headers = Message()
        self.handler.rfile = io.BytesIO()
        self.handler.wfile = io.BytesIO()
        self.handler.close_connection = False
        for method in ("send_response", "send_header", "end_headers"):
            setattr(self.handler, method, Mock())
        self.resp = Mock(status=200)
        self.set_headers({"Content-Type": "application/json", "Content-Length": "2"})
        self.resp.read.side_effect = [b"{}", b""]
        self.conn = Mock()
        self.conn.getresponse.return_value = self.resp

    def set_headers(self, headers):
        self.resp.getheaders.return_value = list(headers.items())
        self.resp.getheader.side_effect = lambda key, default=None: headers.get(key, default)

    def relay(self, error=None, response_created=True):
        with patch.object(mcp_http, "_connect", return_value=self.conn), \
                contextlib.redirect_stderr(io.StringIO()):
            if error:
                with self.assertRaises(error):
                    self.handler._relay("POST")
            else:
                self.handler._relay("POST")
        self.conn.close.assert_called_once_with()
        if response_created:
            self.resp.close.assert_called_once_with()

    def test_normal_json(self):
        self.relay()
        self.assertEqual(self.handler.wfile.getvalue(), b"{}")

    def test_normal_sse(self):
        self.set_headers({"Content-Type": "text/event-stream"})
        self.resp.read.side_effect = [b'data: {"result":{}}\n\n', b""]
        self.relay()
        self.assertEqual(self.handler.wfile.getvalue(), b'data: {"result":{}}\n\n')
        self.assertTrue(self.handler.close_connection)

    def test_upstream_disconnect_mid_body(self):
        self.resp.read.side_effect = [b"{", ConnectionResetError()]
        self.relay(ConnectionResetError)

    def test_read_exception(self):
        self.resp.read.side_effect = http.client.IncompleteRead(b"{")
        self.relay(http.client.IncompleteRead)

    def test_sse_read_exception(self):
        self.set_headers({"Content-Type": "text/event-stream"})
        self.resp.read.side_effect = OSError()
        self.relay(OSError)

    def test_client_write_failure_json_and_sse(self):
        for content_type in ("application/json", "text/event-stream"):
            with self.subTest(content_type=content_type):
                self.setUp()
                self.set_headers({"Content-Type": content_type})
                self.handler.wfile = Mock()
                self.handler.wfile.write.side_effect = BrokenPipeError()
                self.relay()

    def test_response_header_or_downstream_header_exception(self):
        for target in ("getheader", "send_response", "send_header", "end_headers"):
            with self.subTest(target=target):
                self.setUp()
                obj = self.resp if target == "getheader" else self.handler
                getattr(obj, target).side_effect = ValueError("bad header")
                self.relay(ValueError)

    def test_request_and_rejected_response_early_return(self):
        for target in ("request", "getresponse"):
            with self.subTest(target=target):
                self.setUp()
                getattr(self.conn, target).side_effect = http.client.HTTPException("rejected")
                self.relay(response_created=False)
                self.handler.send_response.assert_called_once_with(502)

    def test_error_reporting_exception_still_closes_connection(self):
        self.conn.request.side_effect = OSError()
        self.handler.send_response.side_effect = BrokenPipeError()
        self.relay(BrokenPipeError, response_created=False)

    def test_sse_framing_exception(self):
        self.set_headers({"Content-Type": "text/event-stream"})
        self.resp.read.side_effect = [b"data: {}\n\n", b""]
        with patch.object(mcp_http, "_log_sse_event", side_effect=ValueError("framing")):
            self.relay(ValueError)

    def test_real_log_write_failure_keeps_sse_relay_fail_open(self):
        log = SessionLog.__new__(SessionLog)
        log._lock = threading.Lock()
        log._seq = 0
        log._fh = Mock()
        log._fh.write.side_effect = OSError("disk full")
        self.log.record.side_effect = log.record
        self.set_headers({"Content-Type": "text/event-stream"})
        self.resp.read.side_effect = [b"data: {}\n\n", b"data: []\n\n", b""]
        self.relay()
        self.assertEqual(self.handler.wfile.getvalue(), b"data: {}\n\ndata: []\n\n")

    def test_json_log_exception_after_relay(self):
        self.log.record.side_effect = OSError("log failed")
        self.relay(OSError)
        self.assertEqual(self.handler.wfile.getvalue(), b"{}")

    def test_response_close_exception_still_closes_connection(self):
        self.resp.close.side_effect = OSError("close failed")
        self.relay(OSError)

    def test_rejected_request_does_not_create_connection(self):
        self.handler.headers["Transfer-Encoding"] = "chunked"
        with patch.object(mcp_http, "_connect") as connect:
            self.handler._relay("POST")
        connect.assert_not_called()

    def test_connect_failure_returns_502(self):
        with patch.object(mcp_http, "_connect", side_effect=OSError()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.handler._relay("POST")
        self.handler.send_response.assert_called_once_with(502)
