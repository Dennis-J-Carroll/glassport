# sarif red-team — findings

| row | result | detail |
|---|---|---|
| S1 static-json-well-formed | PASS | valid JSON, 2 results |
| S2 runtime-json-well-formed | PASS | valid JSON, 34 results |
| S3 static-no-raw-secret | PASS | no raw secret present |
| S4 runtime-no-raw-secret | PASS | no raw secret present |
| S5 dos-output-bounded | PASS | output 103041 bytes (limit 2000000) |
| S6 sarif-no-bidi-control | PASS | no bidi control in SARIF message.text |
| S7 sarif-no-zwj | PASS | no zero-width joiner in SARIF message.text |
| S8 sarif-no-novel-secret | PASS | no raw secret present |

## Threat & method

`json.dumps` makes the SARIF envelope structurally injection-proof (quotes, backslashes and C0 controls are all escaped) and `message.text` is a plain-text field GitHub never renders as HTML, so the JSON-break / markup-smuggle threats are closed by format (S1/S2 lock that). The real finding is credential leakage: a hostile server can name a directory like a secret, and the audit finding's path flowed into the SARIF URI / fingerprint verbatim. `render_sarif` now scrubs the message, URI and fingerprint with `detectors.redact_secrets` (S3). A poisoning *directive* the audit quotes in a finding is NOT redacted — that is the tool faithfully reporting the attack it found, not a leak. S5 bounds output against a hostile multi-megabyte tool name that rides into a.explanation — the message is clamped per field.

S6/S7 close Unicode deception in SARIF `message.text`: bidi overrides and zero-width joiners from hostile tool names rode into annotation explanations and would be rendered literally by `ensure_ascii=False` JSON. Both renderers now apply the same `neutralize_text` scrubber used by the HTML report.

S8 locks the novel Stripe key shape in the runtime SARIF path: a credential-named tool reaches `message.text` via annotation explanations and is redacted by the same new pattern that closes R14.

