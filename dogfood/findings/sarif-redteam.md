# sarif red-team — findings

| row | result | detail |
|---|---|---|
| S1 static-json-well-formed | PASS | valid JSON, 2 results |
| S2 runtime-json-well-formed | PASS | valid JSON, 24 results |
| S3 static-no-raw-secret | PASS | no raw secret present |
| S4 runtime-no-raw-secret | PASS | no raw secret present |

## Threat & method

`json.dumps` makes the SARIF envelope structurally injection-proof (quotes, backslashes and C0 controls are all escaped) and `message.text` is a plain-text field GitHub never renders as HTML, so the JSON-break / markup-smuggle threats are closed by format (S1/S2 lock that). The real finding is credential leakage: a hostile server can name a directory like a secret, and the audit finding's path flowed into the SARIF URI / fingerprint verbatim. `render_sarif` now scrubs the message, URI and fingerprint with `detectors.redact_secrets` (S3). A poisoning *directive* the audit quotes in a finding is NOT redacted — that is the tool faithfully reporting the attack it found, not a leak.

