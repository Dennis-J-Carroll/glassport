# Phase 4 acceptance matrix

Run from repository root as an ordinary user. Each named fixture starts with a
fresh capture, counts the decisive request **at the upstream**, builds a bundle,
and asserts replay status, delivery status, verify exit code, and reason. The
`public-canary` fixtures search every file in `public/` for plaintext, base64
at three alignments, lower and upper hex, percent encoding, and JSON Unicode
escapes. `tests/test_public_gate.py` separately proves the encoded tool-name
leak failed before the §8 fix and passes after it.

The table records expected SHA-256 of the **normalized manifest**. For malformed
bundle and wire/journal mismatch rows, hash is from the manifest as built,
before the deliberate mutation. Signed rewrite rows hash the second, newly
signed manifest. This hash is an acceptance fingerprint; `bundle verify` still
checks original artifact SHA-256 values and any trusted signature.

## Normalization

`tests/acceptance_matrix.py::normalized_manifest` transforms exactly these
capture-specific values before RFC 8785 serialization and SHA-256:

- UTC ISO timestamps in all string fields, including wire header `started_at`,
  journal profile times, and `bundler.created_at`, become
  `2000-01-01T00:00:00+00:00`.
- Opaque HTTP epoch IDs become `epoch-0001`, `epoch-0002`, etc., in evidence,
  profile-map keys, delivery rows, and finding records. Stdio remains `stdio`.
- Hex digests of 24–64 characters become stable `digest-0001` tokens, assigned
  by first occurrence. These include artifact hashes derived from timestamped
  wire/journal bytes and finding IDs. Repeated original digests share a token.
  Eight-character random collision suffixes become `collision`, preserving
  the fact of a stable-ID collision.
- Ephemeral `remote.port` for the local loopback upstream becomes `0`.
- Journal profile `n` becomes `0`. Delivery rows sort by normalized epoch,
  wire sequence, and code; `intent_n` and `delivery_n` become sequential
  positional numbers. Their original append order can race a client response;
  replay and delivery checks still verify the unnormalized journal links.

The normalized manifest retains actions, reasons, severity, evidence levels,
counts, paths, transport, mode, and limit codes. HTTP fixture code waits for
handshake journal deliveries before each decisive request. Multi-epoch fixtures
order wire logs by header `started_at`, not random file name. Two independent
full matrix runs reproduced all 56 normalized hashes; CI runs the same guard
on a fresh machine.

## Matrix

| Fixture | Command | Verify exit and reason | Normalized manifest SHA-256 |
| --- | --- | --- | --- |
| `acceptance.http-default.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_default_anonymous_modern_private` | `0: default_profile` | `dbf9669590d61ac509b9a0edc76f6f04c71770959d9b3c5e01c1e629e58f402a` |
| `acceptance.http-default.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_default_anonymous_modern_public` | `0: default_profile` | `9453f714062c35f0455de3b4ec0d4ead06a81b1322265535b553043ab8308819` |
| `acceptance.http-default.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_http_default_concurrent_correlation` | `0: default_profile` | `2d87225bac56ee46601bdfb60021152065c16a2c766390b4513cacb82c6a2684` |
| `acceptance.http-default.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_detector_fault` | `2: recorded_fault_not_re_executed` | `caf78ba721e314f59e934f4b59d089b43a8ee71dcf74883485cd9023adce1575` |
| `acceptance.http-default.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_epoch_mismatch` | `1: wire_epoch_mismatch` | `158485f0a011dcac158649f10f5f3d020bd9debd75ff4e7965f18cada46de5b3` |
| `acceptance.http-default.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_failed_wire_write` | `2: missing_wire_evidence` | `3d7bdbf263cbe06748f15e8b96d3e0eabb6c1f05af9da7ce165ea3344d236273` |
| `acceptance.http-default.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_malformed_body` | `2: wire_digest_missing` | `d0f0d5d3e6562a12e210be439db93b5f98e9cf422bec76bfd5842051a450d393` |
| `acceptance.http-default.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_malformed_bundle` | `1: bundle_unreadable` | `158485f0a011dcac158649f10f5f3d020bd9debd75ff4e7965f18cada46de5b3` |
| `acceptance.http-default.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_missing_declaration` | `0: default_profile` | `fe6f8b46c7ca18f60430979df61f5e61167781cf90f1b9bcab51ecd854290f7e` |
| `acceptance.http-default.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_http_default_multi_epoch_stable_id_collision` | `0: default_profile` | `9d1a00d67d4803d13092ef8b7e16c400c2a72b553c47a17eb5ed48aad61910eb` |
| `acceptance.http-default.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_no_event_observation` | `2: wire_digest_missing` | `d0f0d5d3e6562a12e210be439db93b5f98e9cf422bec76bfd5842051a450d393` |
| `acceptance.http-default.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_no_list_client` | `0: default_profile` | `c9cf5445bf9fa220ea8599f8efc7eb879068cd73798bd0f6f6355fc09bfe7d20` |
| `acceptance.http-default.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_public_canary` | `2: public_gate_tool_hashed` | `395fcbcdf3af193d9f3f597627d7154176a4aff294a4f3999832c8a1f32cee94` |
| `acceptance.http-default.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_signed_rewrite` | `1: signature_invalid` | `d1b0e4143c0069e7e00ef0c9c5d575db724a27dc9228412eda1ce69efd096669` |
| `acceptance.http-default.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_stale_surface` | `0: default_profile` | `6acde3d05a91bbb520a134142888fa06e5aec7ccf459fb3a54871760763dd004` |
| `acceptance.http-strict.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_strict_anonymous_modern_private` | `0: strict_profile` | `9cd03ba6571ed79b956b0b2fe8cdd0ae2d0ed9b0f903f75ac894e0a3beb1742f` |
| `acceptance.http-strict.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_strict_anonymous_modern_public` | `0: strict_profile` | `71b205c486afb151d5649ae41955abbb3b101126d14468e1a3d4fd2d6e941da3` |
| `acceptance.http-strict.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_http_strict_concurrent_correlation` | `0: strict_profile` | `2de226b515a06ca44f78c2b1ff675fa024841240b89b9ae53fd188a84ea6ffb9` |
| `acceptance.http-strict.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_detector_fault` | `2: recorded_fault_not_re_executed` | `170c5bffcd8e026fa025499d47d7ab712e32de8dbc85e26dc95aa5c66b34efe5` |
| `acceptance.http-strict.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_epoch_mismatch` | `1: wire_epoch_mismatch` | `a23118da5384f68c3b5f717d5a44cd00c4de79b8f50d71305fbd708cca239a1f` |
| `acceptance.http-strict.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_failed_wire_write` | `2: missing_wire_evidence` | `526bdcb02011a173f2f7412f3811c179ba8c4bd9fe27b984b908ce4339ecda4b` |
| `acceptance.http-strict.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_malformed_body` | `2: wire_digest_missing` | `9b56fd62959b43eccf025200d49c1671b438ca6a60c9e3c6b5246703302e5a79` |
| `acceptance.http-strict.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_malformed_bundle` | `1: bundle_unreadable` | `a23118da5384f68c3b5f717d5a44cd00c4de79b8f50d71305fbd708cca239a1f` |
| `acceptance.http-strict.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_missing_declaration` | `0: strict_profile` | `c632de5180639374f4218dbbba561d60a6d469686a3b501f1d4cd19f63a3ea09` |
| `acceptance.http-strict.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_http_strict_multi_epoch_stable_id_collision` | `0: strict_profile` | `fedff13f0aee57c6f43ef02552d119c96db1bc6f529dfa041d4c3a001b3b583c` |
| `acceptance.http-strict.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_no_event_observation` | `2: wire_digest_missing` | `9b56fd62959b43eccf025200d49c1671b438ca6a60c9e3c6b5246703302e5a79` |
| `acceptance.http-strict.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_no_list_client` | `0: strict_profile` | `827339356ac5d06e4079e1e9e0abb0bb51a8645617bcba7dc9ed95acb93eb5dc` |
| `acceptance.http-strict.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_public_canary` | `2: public_gate_tool_hashed` | `44221c5b52459b18116c16c5cc43c633e8a6cf458da8ebd64adc9531a14576af` |
| `acceptance.http-strict.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_signed_rewrite` | `1: signature_invalid` | `1f28e48b9f71b678456b0a16d2f6037bbdda63c1e9c6001f37578a50379884ff` |
| `acceptance.http-strict.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_stale_surface` | `0: strict_profile` | `aa591565cb4c7d3ab260012b85446c89a7150f93d4e92bf5bdabb1c469a281bc` |
| `acceptance.observe.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_observe_anonymous_modern_private` | `0: default_profile` | `2bd8bfad6f2db8b0052874b9997cc6710827cb6a227f96ae1f2dc5fee51d3b8c` |
| `acceptance.observe.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_observe_anonymous_modern_public` | `0: default_profile` | `6f18c85b731e59e1969cf13e62cf64e9035572271faf5ff0da7cf64cc4b7185f` |
| `acceptance.observe.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_observe_concurrent_correlation` | `0: default_profile` | `84510b4731c51f6f36d0559804738fc42f37d37baf4056daeee11fca0b3a724b` |
| `acceptance.observe.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_detector_fault` | `2: recorded_fault_not_re_executed` | `8e638d5e3e2da6ba6f9d992a9228b4d775fa4aae79a4e1b056456760acabf524` |
| `acceptance.observe.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_epoch_mismatch` | `1: wire_epoch_mismatch` | `b1167d554ead86fec36563b4b4ca3b1bc12dacdbd59ceeb8f0a4e8cc510ecceb` |
| `acceptance.observe.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_failed_wire_write` | `2: missing_wire_evidence` | `0ef9951cc878f1d5ac0500eb3400ee70dff4bdd4505e2f520eef9847e3bb42c2` |
| `acceptance.observe.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_malformed_body` | `0: default_profile` | `aa6eb6c6b9095e322f184031c3c4c19ee0b660c0cdd9c6253ec87cdd5ac3bbc0` |
| `acceptance.observe.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_malformed_bundle` | `1: bundle_unreadable` | `b1167d554ead86fec36563b4b4ca3b1bc12dacdbd59ceeb8f0a4e8cc510ecceb` |
| `acceptance.observe.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_missing_declaration` | `0: default_profile` | `373acf0d931bca5fed7dc1f13f7d7d7748505d440dd2ee93afc439f522875be5` |
| `acceptance.observe.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_observe_multi_epoch_stable_id_collision` | `0: default_profile` | `da5a1f0f7c835979feafaff1464f198bb022b2dd7124f86d7bb39145574a4dba` |
| `acceptance.observe.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_no_event_observation` | `2: wire_digest_missing` | `1b486eae0e1aa8f037947613cc761e2917b87e2b70ebcbe22daed60512c0d4a8` |
| `acceptance.observe.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_no_list_client` | `0: default_profile` | `1e26e1926bd3f2fef256d91b5bf7e6af2798a47bad61ad6a18aa9adb48b83d6b` |
| `acceptance.observe.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_public_canary` | `2: public_gate_tool_hashed` | `9eae64595e42dbc28b2e587352d2ef781334450040ade62da46b89c89b0af1c7` |
| `acceptance.observe.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_signed_rewrite` | `1: signature_invalid` | `8b5de3b8447c038588ffc7ff6d4ff2a09581cd9a63650bfa9634e334489aaf59` |
| `acceptance.observe.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_stale_surface` | `0: default_profile` | `899e2a90ac41f897603dda8060e7eda7909af008afdedc6735d081ab2fc8ddfc` |
| `acceptance.stdio-gate.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_concurrent_correlation` | `2: no_journal_for_path` | `92793037ecad3b8f7d9c0d0938b597ea0a2502543a2b8ffb197ca8d8730f5faa` |
| `acceptance.stdio-gate.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_detector_fault` | `2: no_journal_for_path` | `efcb266b87f48c94d7e3bf9e30e6757fb5901a03b9ba20b97dcf78d980b8bdfa` |
| `acceptance.stdio-gate.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_failed_wire_write` | `2: no_journal_for_path` | `5b275fc13611cb44c700c415ca2dd03597f33e99fae59c83703b07c8d8435755` |
| `acceptance.stdio-gate.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_malformed_body` | `2: no_journal_for_path` | `ee651ab3c77224ead1f81e15108ee4a36c41fb2ea7cbf89f76cbc81bb4fd4f66` |
| `acceptance.stdio-gate.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioBundleMutationAcceptance.test_malformed_bundle` | `1: bundle_unreadable` | `d669aeb0fdfc18de898c1733d112f0ee91222e82f71096b1c8e9ae55b544c6d5` |
| `acceptance.stdio-gate.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_missing_declaration` | `2: no_journal_for_path` | `d669aeb0fdfc18de898c1733d112f0ee91222e82f71096b1c8e9ae55b544c6d5` |
| `acceptance.stdio-gate.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_no_event_observation` | `2: no_journal_for_path` | `1eafc63f96b848ab8c172f40d18f9c0fe5fb7f56b19fb920565f4a5f280283bb` |
| `acceptance.stdio-gate.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_no_list_client` | `2: no_journal_for_path` | `d669aeb0fdfc18de898c1733d112f0ee91222e82f71096b1c8e9ae55b544c6d5` |
| `acceptance.stdio-gate.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_public_canary` | `2: public_gate_tool_hashed` | `9fce933cc06e5930fd4c314910864a6765d0685d98190e2b627b99e6a6e3d151` |
| `acceptance.stdio-gate.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioBundleMutationAcceptance.test_signed_rewrite` | `1: signature_invalid` | `f775346d2b22a548172e277171dda1de1d41ff6e5e24b128fc8fb05641df02ce` |
| `acceptance.stdio-gate.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_stale_surface` | `2: no_journal_for_path` | `faaac6fdb4af86d532314672d5976e4c1d757306cb6fb69bd71c213fa2b39eff` |

## Path applicability

Anonymous modern scope and `--public-surface` are HTTP-only. Stdio has one
wire epoch and no decision journal, so epoch mismatch between wire and journal
and multi-epoch stable-ID collision have no stdio equivalent. Untampered stdio
rows assert exit `2` with `no_journal_for_path`. A malformed stdio bundle and
a re-signed stdio bundle correctly take exit `1` for integrity failure, while
still lacking a replayable journal. Public verify likewise exits `2` because
redacted records cannot replay as raw evidence.
