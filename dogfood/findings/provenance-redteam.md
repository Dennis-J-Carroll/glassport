# provenance red-team — findings

| row | result | detail |
|---|---|---|
| P1 redirect SSRF to 127.0.0.1 | PASS | redirect_hits=[], result.status='error' |
| P2 attacker name injected into request URL | PASS | request_path=None |
| P3 attacker package name reaches finding | PASS | findings=2, package_field='evil�<script>alert(1)</script>�_pkg' |
| P5 file:// redirect not followed (negative) | PASS | result.status='error' |
| P4 deprecated string is not echoed (negative) | PASS | detail='the latest release is marked deprecated by the registry', leaked=False |

## Source defects

* `fetch_registry` uses `urllib.request.urlopen` with the default redirect handler. A compromised registry or typosquat can return `Location: http://127.0.0.1/...` (or `[::1]`, metadata IPs) and the fetcher will follow it (P1).

* npm package names from `package.json` keys are interpolated into the registry URL without percent-encoding. Characters like `?`, `#`, `%`, and unencoded `@scope/name` paths inject attacker bytes into the HTTP request line (P2).

* `ProvenanceFinding.package` is copied straight from the manifest without normalization or scrubbing, so newlines, HTML, and Unicode directional controls reach the audit output channel (P3).

* urllib's built-in redirect handler rejects non-HTTP schemes, so a `Location: file:///etc/passwd` redirect fails safely with status `error` and does not read local files (P5).

* The npm `deprecated` string is correctly treated as a boolean flag by `_is_deprecated`; `evaluate()` emits only a generic sentence, so the attacker-controlled deprecation message does not currently leak into findings (P4).

