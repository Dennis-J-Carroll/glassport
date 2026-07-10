# http-relay red-team — findings

| row | result | detail |
|---|---|---|
| R1 unbounded response → memory/disk DoS | PASS | client_recv=4194304 of 4194304, log_size=1000445 (bounded=True) |
| R2 chunked request smuggling (TE, no CL) | PASS | status=b'HTTP/1.1 400 Bad Request', upstream_saw=[] |
| R2 duplicate Content-Length rejected | PASS | status=b'HTTP/1.1 400 Bad Request' |
| RF conflicting response Content-Length dropped | PASS | client_recv=b'hello', cl=None, conn='close' |
| RF comma-folded response Content-Length dropped | PASS | client_recv=b'hello', cl=None, conn='close' |
| RF lying-short Content-Length forces close (no hang) | PASS | hung=False, partial=b'hello' |
| RF bare-LF header smuggling normalized (CL dropped) | PASS | client_recv=b'hello', cl=None |
| RF chunked upstream de-chunked (no marker leak) | PASS | client_recv=b'helloworld', te=None |
| RF SSE response close-delimited (no client hang) | PASS | client_recv=b'data: hello\n\ndata: world\n\n', conn='close' |
| RF Content-Type substring can't flip to SSE (CL kept) | PASS | client_recv=b'{"ok":"data"}', cl='13' |
| RF oversized SSE event memory-bounded (relay sacred) | PASS | client_recv=2097158 of 2097158, log_size=277 (bounded=True) |
| RF pipeline closes after ambiguous body (no desync) | PASS | responses=1, close_present=True |
| R3 handler defines a socket timeout | PASS | handler.timeout=30 |
| R3 server survives a client aborting mid-request | PASS | post_abort_request_status=200 |
