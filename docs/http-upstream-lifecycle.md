# HTTP upstream resource lifetime (#77)

Every connection successfully created by the HTTP relay is closed on every
exit path. Cleanup also closes the response: a close-delimited HTTPResponse
can own a socket that http.client has detached from its connection object.
Nested finally blocks ensure that a response-close failure cannot skip
connection cleanup.

This is a lifecycle correction only. Existing JSON/SSE forwarding, response
delimiting, header hardening, limits, and timeouts remain. Unexpected framing
exceptions propagate as before, with cleanup guaranteed; ordinary SessionLog
write failures remain isolated from forwarding. No HTTP enforcement is added.

Fifteen regression tests in tests/test_http_connection_lifecycle.py assert
close calls directly across normal JSON/SSE, upstream disconnect/read failure,
client write/header failure, rejected responses, request failure, early returns,
SSE framing/logging failure, cleanup failure, and real logger write failure.
The existing HTTP tap and relay adversarial grills exercise byte-level behavior.

This isolated PR is based on current main and does not depend on #76 or the
incremental detector changes. Validation of its exact head is tracked in PR CI.
