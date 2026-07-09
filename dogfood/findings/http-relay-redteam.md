# http-relay red-team — findings

| row | result | detail |
|---|---|---|
| R1 unbounded response → memory/disk DoS | PASS | client_recv=4194304 of 4194304, log_size=1000445 (bounded=True) |
| R2 chunked request smuggling (TE, no CL) | PASS | status=b'HTTP/1.1 400 Bad Request', upstream_saw=[] |
| R2 duplicate Content-Length rejected | PASS | status=b'HTTP/1.1 400 Bad Request' |
| R3 handler defines a socket timeout | PASS | handler.timeout=30 |
| R3 server survives a client aborting mid-request | PASS | post_abort_request_status=200 |
