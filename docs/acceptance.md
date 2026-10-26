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
- The glassport release version (`bundler.version`, `glassport_version`)
  becomes `0.0.0`, so a version bump alone does not change any fingerprint.
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

To re-record after an intended manifest change, run
`GLASSPORT_ACCEPTANCE_RECORD=1 PYTHONPATH=src python -m unittest tests.test_acceptance -v`
and copy each printed `ACCEPTANCE_ROW name test-id exit reason sha256` into the
table below. `GLASSPORT_ACCEPTANCE_DUMP=DIR` writes each normalized manifest
as JSON for diffing.

## Matrix

| Fixture | Command | Verify exit and reason | Normalized manifest SHA-256 |
| --- | --- | --- | --- |
| `acceptance.http-default.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_default_anonymous_modern_private` | `0: default_profile` | `bc07b364e45e8b2b589c92146873e01c10359618a65bc376af6d2a186d0e60f0` |
| `acceptance.http-default.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_default_anonymous_modern_public` | `0: default_profile` | `f7b86103a3fa5894290c395cb5cda889c74ee7a8065a9a888f312c1ac9d19681` |
| `acceptance.http-default.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_http_default_concurrent_correlation` | `0: default_profile` | `d0e572e600b28534fd8a14e95c272fe60156cab9b129611e388c539f116a7960` |
| `acceptance.http-default.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_detector_fault` | `2: recorded_fault_not_re_executed` | `4386688c0522ff3df95a948a1b81bd2d90eaaaa9f01d267b34d608840fa1cfe3` |
| `acceptance.http-default.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_epoch_mismatch` | `1: wire_epoch_mismatch` | `0fe40df3eb79b969e2bd89567672e84dd4288e1784275f230021c9d15fc2eabb` |
| `acceptance.http-default.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_failed_wire_write` | `2: missing_wire_evidence` | `5bc4bcfb58366294978d2491657bed16f2c24872403b3cd3819b5335bff7864e` |
| `acceptance.http-default.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_malformed_body` | `2: wire_digest_missing` | `e76df68dde359e6390ad14c5f200a9f8b9d31718ea9a8b13e4d0247a5c61c035` |
| `acceptance.http-default.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_malformed_bundle` | `1: bundle_unreadable` | `0fe40df3eb79b969e2bd89567672e84dd4288e1784275f230021c9d15fc2eabb` |
| `acceptance.http-default.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_missing_declaration` | `0: default_profile` | `61ea49e84e7288e0c17501dd1463da139ee896dd32d4ba06ab3ce1abf2b8499b` |
| `acceptance.http-default.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_http_default_multi_epoch_stable_id_collision` | `0: default_profile` | `5d2823877837740e189995496efeaeedbec00a7eda6549aa640e2d4eba30bf9d` |
| `acceptance.http-default.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_no_event_observation` | `2: wire_digest_missing` | `e76df68dde359e6390ad14c5f200a9f8b9d31718ea9a8b13e4d0247a5c61c035` |
| `acceptance.http-default.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_no_list_client` | `0: default_profile` | `fa98eabf6813c351e8a594760665d75590e8c9e1494abf69e2b1b156690401d8` |
| `acceptance.http-default.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_public_canary` | `2: public_gate_tool_hashed` | `51116748214f188a25a822d917d1dd86da9ee0601f999b39cb4c26e7dc3879a3` |
| `acceptance.http-default.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_signed_rewrite` | `1: signature_invalid` | `5c4a9ff4c9e957a8a53edd608ccd0b4f8f4e5ee6a35946ceec19aac29f945284` |
| `acceptance.http-default.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_stale_surface` | `0: default_profile` | `31c9ce900b9c5a30680610179805a1628a6bf75df81e37f7e93be2d05cd55bb4` |
| `acceptance.http-strict.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_strict_anonymous_modern_private` | `0: strict_profile` | `ab37f86059a4b6e1b59d2f2606690faf6df4b0b88f6b03180ce10297ce57a6c0` |
| `acceptance.http-strict.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_strict_anonymous_modern_public` | `0: strict_profile` | `d14541a2281ce842628fc15a0207c0177a6ac0a26f96ea4dfdf61641ee7372ef` |
| `acceptance.http-strict.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_http_strict_concurrent_correlation` | `0: strict_profile` | `edf58a8e7e3aa1bc45d4c9740061f1714414684bd9297641d658ba88021291d8` |
| `acceptance.http-strict.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_detector_fault` | `2: recorded_fault_not_re_executed` | `73106e96a84118e024f51aa4434a477b5ca62576060dc3d6b550caa11d72cd6d` |
| `acceptance.http-strict.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_epoch_mismatch` | `1: wire_epoch_mismatch` | `07ad898c1fe3763c4a8dbb4bb494629d9ba856213e9648f948652c35a2940658` |
| `acceptance.http-strict.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_failed_wire_write` | `2: missing_wire_evidence` | `37677c24aa571d394ea5396e56ccbcdd494e4402f24ef7c72af0543ed19566bf` |
| `acceptance.http-strict.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_malformed_body` | `2: wire_digest_missing` | `bfda222561168f43daf4b8d1a4979f3d45931069412889879ed4ef404b894fab` |
| `acceptance.http-strict.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_malformed_bundle` | `1: bundle_unreadable` | `07ad898c1fe3763c4a8dbb4bb494629d9ba856213e9648f948652c35a2940658` |
| `acceptance.http-strict.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_missing_declaration` | `0: strict_profile` | `cac9fcee6c5feb5bf5cb5e75b260a5c2b54c6c6a3d9e8ed1fc5f76c01ae4ed05` |
| `acceptance.http-strict.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_http_strict_multi_epoch_stable_id_collision` | `0: strict_profile` | `6b7c372588792672febe3ed553c71edfaf4ae74db9ff1dd071dd66b32ab1f1d4` |
| `acceptance.http-strict.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_no_event_observation` | `2: wire_digest_missing` | `bfda222561168f43daf4b8d1a4979f3d45931069412889879ed4ef404b894fab` |
| `acceptance.http-strict.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_no_list_client` | `0: strict_profile` | `1b1534675d2ff525fa9ed1ee8e7046cadfda2ff7de207b8aba263003a515c2f6` |
| `acceptance.http-strict.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_public_canary` | `2: public_gate_tool_hashed` | `f5c924ff59daf0acbf8f0468002b10d3a77dfc81ff82994a56750046d76f20de` |
| `acceptance.http-strict.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_signed_rewrite` | `1: signature_invalid` | `cc1e5f368cbe29a1e922300bd0c64cb505bd0798cb2b39caaf45062ae45a2c51` |
| `acceptance.http-strict.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_stale_surface` | `0: strict_profile` | `93e3e59af4cff4551af2d7bc8b0137f1e6c4620675a1fe513efe16eab77f93e0` |
| `acceptance.observe.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_observe_anonymous_modern_private` | `0: default_profile` | `804817fe9812cad50002b31325fc5f15a294d0c10338527ab756c84ff1d6060f` |
| `acceptance.observe.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_observe_anonymous_modern_public` | `0: default_profile` | `3c384c9e7ac0941cb72f90d3121019503c99bf6da3b66cb10275d2e9891073d5` |
| `acceptance.observe.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_observe_concurrent_correlation` | `0: default_profile` | `cbf213be49cf9fd6510cb4e06bc80bdfbad30ec40af6df17ce96dbada5756028` |
| `acceptance.observe.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_detector_fault` | `2: recorded_fault_not_re_executed` | `4b55073281537b8b2a8668b61d2265b7ba3344e3f6f9c3d50098db909752592a` |
| `acceptance.observe.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_epoch_mismatch` | `1: wire_epoch_mismatch` | `1cb6f4b7dec49c8303ff8f3443e9745cef671670cd1a7c10df73f95edd8a7032` |
| `acceptance.observe.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_failed_wire_write` | `2: missing_wire_evidence` | `1b377eff80a31e3ce9f1e3fb9f7107210023921fea8794ff2f83203c2e13f8dd` |
| `acceptance.observe.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_malformed_body` | `0: default_profile` | `7ff27b1a680895c4e7e76b6deef44379769fbaee41731d2ed012d11c9e2d03f7` |
| `acceptance.observe.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_malformed_bundle` | `1: bundle_unreadable` | `1cb6f4b7dec49c8303ff8f3443e9745cef671670cd1a7c10df73f95edd8a7032` |
| `acceptance.observe.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_missing_declaration` | `0: default_profile` | `86c0cc1f2dcfa38a15ea7ad199c300eaa4d356ecbb6d916ad62cfadc0b89c8f5` |
| `acceptance.observe.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_observe_multi_epoch_stable_id_collision` | `0: default_profile` | `12cc6c13b370f97438d60c83e470be04037979dad55e605d38fdf99a7229755e` |
| `acceptance.observe.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_no_event_observation` | `2: wire_digest_missing` | `ddb86a9c4a4f6d11f5eede7d8fc32b01f468be23eeacd3afac06668a3c5cbd17` |
| `acceptance.observe.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_no_list_client` | `0: default_profile` | `60a432350008172fe173887dfe42a6ac62cfc51cb6b9c0528aab706647b8cb76` |
| `acceptance.observe.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_public_canary` | `2: public_gate_tool_hashed` | `8bce7e2bab1fbed8ead16ce10c594d89652eca897c3137bd064b346db59b9432` |
| `acceptance.observe.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_signed_rewrite` | `1: signature_invalid` | `334b1b0a0df00ed0d466e66f2fcd64dea2465319f3ebe339fa1b9c2ac2fc4338` |
| `acceptance.observe.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_stale_surface` | `0: default_profile` | `3de0c8b9ae335e7a8b3dcce8d3d0fe765da2cd3849b2609a0920e74c44937078` |
| `acceptance.stdio-gate.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_concurrent_correlation` | `2: no_journal_for_path` | `44822da18287d5b898c85d6f1aba4d6a6f71665850a308aba93aaf441a66dd60` |
| `acceptance.stdio-gate.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_detector_fault` | `2: no_journal_for_path` | `abd78f9c6b78725e05063f1a1ea23ac0ce21a019dcdfff1822516f904d5b3030` |
| `acceptance.stdio-gate.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_failed_wire_write` | `2: no_journal_for_path` | `ac540a365d4f054edbed5a62b193ff0ae88e52b2f3f63964c04666f3693fcaff` |
| `acceptance.stdio-gate.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_malformed_body` | `2: no_journal_for_path` | `c95dc9169a5e12eb9369be0a254cd87e255c8209b3d34882a9740600c01fb559` |
| `acceptance.stdio-gate.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioBundleMutationAcceptance.test_malformed_bundle` | `1: bundle_unreadable` | `23fa799257034c8f55fa0e0d5bdb4510e19e8eaf2a1d660a4d26f2a4ad352253` |
| `acceptance.stdio-gate.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_missing_declaration` | `2: no_journal_for_path` | `23fa799257034c8f55fa0e0d5bdb4510e19e8eaf2a1d660a4d26f2a4ad352253` |
| `acceptance.stdio-gate.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_no_event_observation` | `2: no_journal_for_path` | `e4a304a4461ba480d79b0fa2d5af4fde833894a0c8f11e489d1d6eb90c224944` |
| `acceptance.stdio-gate.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_no_list_client` | `2: no_journal_for_path` | `23fa799257034c8f55fa0e0d5bdb4510e19e8eaf2a1d660a4d26f2a4ad352253` |
| `acceptance.stdio-gate.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_public_canary` | `2: public_gate_tool_hashed` | `2730d5852139d500086ef155bb3e384243df03e111cb00d7185befc54aeac68e` |
| `acceptance.stdio-gate.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioBundleMutationAcceptance.test_signed_rewrite` | `1: signature_invalid` | `f0b27e69db9e6beaf5c5e005053708828774bb926ba38b8100622d3dfa484758` |
| `acceptance.stdio-gate.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_stale_surface` | `2: no_journal_for_path` | `0fc6f0aa8b63f051881de8bd85e34f79965195aa7015b879c95f2cfc68a5f9a6` |

## Path applicability

Anonymous modern scope and `--public-surface` are HTTP-only. Stdio has one
wire epoch and no decision journal, so epoch mismatch between wire and journal
and multi-epoch stable-ID collision have no stdio equivalent. Untampered stdio
rows assert exit `2` with `no_journal_for_path`. A malformed stdio bundle and
a re-signed stdio bundle correctly take exit `1` for integrity failure, while
still lacking a replayable journal. Public verify likewise exits `2` because
redacted records cannot replay as raw evidence.
