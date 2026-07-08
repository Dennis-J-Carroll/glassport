# http-tap red-team — findings

| row | result | detail |
|---|---|---|
| H1 multi-line data: loses newline separator | PASS | forwarded=b'data: {"a":1}\ndata: {"b":2}\n\n', log_raw='{"a":1}\n{"b":2}', entries=1 |
| H2 event:/id:/comment lines dropped from log | PASS | forwarded=b'event: tool_result\nid: 42\n:comment\ndata: ok\n\n', log_contains_nondata=True |
| H3 unterminated SSE stream never logged | PASS | forwarded_bytes=459776, s2c_entries=1 |
| H5 leading BOM drops first SSE event | PASS | forwarded_starts_with_bom=True, s2c_entries=1 |
| H6 CRLF terminator \r\n\r\n not split | PASS | forwarded=b'data: ok\r\n\r\n', s2c_entries=1 |
| H4 upstream exception reaches client | PASS | status=502, body=b'glassport: upstream unavailable' |

## Source defects

* `_stream_sse` joins multiple `data:` lines with `b"".join(...)`, dropping the mandatory `\n` separator between them. The logged frame is therefore not the frame the client parsed (H1).

* `_stream_sse` discards `event:`, `id:`, `retry:`, and comment lines when extracting a payload for the log. The relay is byte-faithful, but the analysis view is not (H2).

* `_stream_sse` buffers all SSE bytes until `\n\n` appears. A server that never sends the terminator forwards bytes correctly but never produces a log entry, and the buffer grows without bound (H3).

* `_stream_sse` does not strip a leading UTF-8 BOM before looking for `data:` lines, so a BOM-prefixed event is forwarded but dropped from the log (H5).

* `_stream_sse` only scans for bare `\n\n` event terminators; the SSE-specified `\r\n\r\n` terminator is never matched, so CRLF-only streams are forwarded but never logged (H6).

* `_relay` sends `str(exc)` in the 502 response body when the upstream connection fails. That exception string can include attacker-controlled bytes from the remote URL or transport error (H4).

