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
- Opaque HTTP and new stdio epoch IDs become `epoch-0001`, `epoch-0002`, etc., in evidence,
  profile-map keys, delivery rows, and finding records. Legacy no-epoch stdio remains `stdio`.
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
table below. `GLASSPORT_ACCEPTANCE_DUMP=DIR` (an existing directory) writes each normalized manifest
as JSON for diffing.

## Matrix

| Fixture | Command | Verify exit and reason | Normalized manifest SHA-256 |
| --- | --- | --- | --- |
| `acceptance.http-default.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_default_anonymous_modern_private` | `0: default_profile` | `39d96f51360563718be57b6c751bd64a66edcfa90b9cbaf9577bd5419429c309` |
| `acceptance.http-default.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_default_anonymous_modern_public` | `0: default_profile` | `c1edcba92ae50306d42417d094b1ded86261c9aea81b22170e737cab2e2936a0` |
| `acceptance.http-default.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_http_default_concurrent_correlation` | `0: default_profile` | `1cd6b581256c0f12e1b7bbcb51e442766e8a9619b8eae5e6b78a6cb27e473ac9` |
| `acceptance.http-default.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_detector_fault` | `2: recorded_fault_not_re_executed` | `bb3e0ec997f85b0a5be6c4bb4ba8a87e78235c5007dbc70251596d5f48e88b45` |
| `acceptance.http-default.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_epoch_mismatch` | `1: wire_epoch_mismatch` | `1549026bfed2570f8711a9b1705846213c434c3eb70964a742ad3d045ac6c927` |
| `acceptance.http-default.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_failed_wire_write` | `2: missing_wire_evidence` | `babf1f3f6545405c8d16947aa032f360789fb35ffa5a05cb06fd19d4b47e4816` |
| `acceptance.http-default.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_malformed_body` | `2: wire_digest_missing` | `c27f825b3396bcd695ba750bb44a8f3df9776be2064b8865c3161ce1fd7e1fd0` |
| `acceptance.http-default.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_malformed_bundle` | `1: bundle_unreadable` | `1549026bfed2570f8711a9b1705846213c434c3eb70964a742ad3d045ac6c927` |
| `acceptance.http-default.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_missing_declaration` | `0: default_profile` | `a1b23ff97c5855e606bbcf9afd899f6aab955de4169186ba5b67438e353744c3` |
| `acceptance.http-default.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_http_default_multi_epoch_stable_id_collision` | `0: default_profile` | `41d395218ebe35e36b930b144eadfdb01cb6c13db05ec39e5a419fb02c364a11` |
| `acceptance.http-default.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_no_event_observation` | `2: wire_digest_missing` | `c27f825b3396bcd695ba750bb44a8f3df9776be2064b8865c3161ce1fd7e1fd0` |
| `acceptance.http-default.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_no_list_client` | `0: default_profile` | `642aa551a1b314bbe5ceb7dcbae7b3dc02b1f24a03e2356aa5f37c129d4cd717` |
| `acceptance.http-default.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_public_canary` | `2: public_gate_tool_hashed` | `d66ee104fdc59ac14c27f16f5c47cab8fe5a4bd4cebce11d540da844786f6351` |
| `acceptance.http-default.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_default_signed_rewrite` | `1: signature_invalid` | `00d7fbc00543f34d39dd22e21677c7ea04cd60652ad1828053ceb109bcb4a024` |
| `acceptance.http-default.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_default_stale_surface` | `0: default_profile` | `9fb7189092534f98ebd51ae5b90a2e561913db8379326a2a2dab24aab8acd4a5` |
| `acceptance.http-strict.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_strict_anonymous_modern_private` | `0: strict_profile` | `adc71e18e346bc8797daea962edee62937f317e65968971441a53e705b50a703` |
| `acceptance.http-strict.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_http_strict_anonymous_modern_public` | `0: strict_profile` | `77169da011e1cbbdc3f747e2e45fff9ad8e5871a1353d235e8b737db4a92055d` |
| `acceptance.http-strict.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_http_strict_concurrent_correlation` | `0: strict_profile` | `ba0a8144189b6e4e6a7dc3f4ddad02f25660658856704ce99c9a9c3fe3e45cdd` |
| `acceptance.http-strict.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_detector_fault` | `2: recorded_fault_not_re_executed` | `f0cdf7c49ace63456f824615fddb7b7884f8b76eb78871f2ff8d1d750e622923` |
| `acceptance.http-strict.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_epoch_mismatch` | `1: wire_epoch_mismatch` | `dea76c20a2932111f06c1565d19bd3b844ae7cfa5ef5953f9c2482a97d9e3cb1` |
| `acceptance.http-strict.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_failed_wire_write` | `2: missing_wire_evidence` | `ca0ae6a07feaf8b5048b119611babd115f28a8bbf1065ed836ad6e6f841df67d` |
| `acceptance.http-strict.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_malformed_body` | `2: wire_digest_missing` | `83139296d09f29d24555a78db0f270f084b20c998b56b5dc670ff81a5391b269` |
| `acceptance.http-strict.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_malformed_bundle` | `1: bundle_unreadable` | `dea76c20a2932111f06c1565d19bd3b844ae7cfa5ef5953f9c2482a97d9e3cb1` |
| `acceptance.http-strict.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_missing_declaration` | `0: strict_profile` | `f673dabf8699d985cd1eb1e0f2409e1b4fc7c0a08b8c2b33cdc99f0806f66f10` |
| `acceptance.http-strict.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_http_strict_multi_epoch_stable_id_collision` | `0: strict_profile` | `97554c62c09399aea7749b3c2b07c8b3f7af89c5a1f45f15ef8c904c8c66f052` |
| `acceptance.http-strict.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_no_event_observation` | `2: wire_digest_missing` | `83139296d09f29d24555a78db0f270f084b20c998b56b5dc670ff81a5391b269` |
| `acceptance.http-strict.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_no_list_client` | `0: strict_profile` | `1b90ea3e5f86305d3fe63937673524cc1dfe2d1cfd4a79728a47e18a932459f5` |
| `acceptance.http-strict.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_public_canary` | `2: public_gate_tool_hashed` | `401cf35da2816d7c19387b7834ff66ca90364b9d9864eb73269536a0309b0d99` |
| `acceptance.http-strict.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_http_strict_signed_rewrite` | `1: signature_invalid` | `aa12ca9e5cffd33ad7ce14980909fedf2235d1ba0abd56f9e4fe3816bf96f783` |
| `acceptance.http-strict.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_http_strict_stale_surface` | `0: strict_profile` | `642fc7ceb42495666a9b0947f87c3a08842b5078bd02e374fe751dd8ea9cb9aa` |
| `acceptance.observe.anonymous-modern-private` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_observe_anonymous_modern_private` | `0: default_profile` | `c8240331d568938c768c670cca611994b09ebf3f6af20b37a23276f9a48589a7` |
| `acceptance.observe.anonymous-modern-public` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestModernAnonymousAcceptance.test_observe_anonymous_modern_public` | `0: default_profile` | `0471d6924bcc6b3cf407ed0723de2f337f4afdf38b29414fe6508a92aa4a7702` |
| `acceptance.observe.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestConcurrentAcceptance.test_observe_concurrent_correlation` | `0: default_profile` | `31da93d4f68a243387795a5754fc0154e0b4231d4134b7e63f32daf6b624c9d7` |
| `acceptance.observe.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_detector_fault` | `2: recorded_fault_not_re_executed` | `328af9eaea5377ca5752c73b4b07325715d258b17c83620cbddff928e56e7ca5` |
| `acceptance.observe.epoch-mismatch` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_epoch_mismatch` | `1: wire_epoch_mismatch` | `0ca5e263fdcbee74307d423f085ee04606fb31a3059f7c83789edbb9ef27c4ad` |
| `acceptance.observe.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_failed_wire_write` | `2: missing_wire_evidence` | `7b056cb4dd4f7369b7a5a7c8d44a0a8d23f652d2f4329eb8f4911e75b2888c67` |
| `acceptance.observe.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_malformed_body` | `0: default_profile` | `1fa0f220a6842288016af432395560445b6f984cbfa77ca9ebbb3b00721a5979` |
| `acceptance.observe.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_malformed_bundle` | `1: bundle_unreadable` | `0ca5e263fdcbee74307d423f085ee04606fb31a3059f7c83789edbb9ef27c4ad` |
| `acceptance.observe.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_missing_declaration` | `0: default_profile` | `3fb62cb69294fe3479618da2b648aa137f0d59dc2ff0d163b536e4b13c895e87` |
| `acceptance.observe.multi-epoch-stable-id-collision` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestMultiEpochAcceptance.test_observe_multi_epoch_stable_id_collision` | `0: default_profile` | `15c43aaf362ee42bf428f6f9063173a8b5f9cdd10deea2f5498e19ec06de91a1` |
| `acceptance.observe.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_no_event_observation` | `2: wire_digest_missing` | `5cb0ea28de63a6bf21658243538ba404d2b5bb1561f68e474bf1b2553e14d53a` |
| `acceptance.observe.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_no_list_client` | `0: default_profile` | `ebcd09d97331218f66ca61f32f68cea511a5bfcbedf28687db984e65352e8793` |
| `acceptance.observe.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_public_canary` | `2: public_gate_tool_hashed` | `c3b594a6e973d94afd4cb42f53a068a45f34b1483cd668973e17ecd7a9553291` |
| `acceptance.observe.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPBundleMutationAcceptance.test_observe_signed_rewrite` | `1: signature_invalid` | `f95dac0c8aba047f01838850e2b14fcf49e08b7fe515b23a8a13a2c98a317dd6` |
| `acceptance.observe.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestHTTPAcceptance.test_observe_stale_surface` | `0: default_profile` | `fb2870704833b2217e9f94fa8a97dd57e9b29f36cb60c0b85e4d63d3dbc83763` |
| `acceptance.stdio-gate.concurrent-correlation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_concurrent_correlation` | `0: default_profile` | `7c4a6fbf3d4b46805f7821abf507875fdf446b2a61a560181e7b29d1ccddf931` |
| `acceptance.stdio-gate.detector-fault` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_detector_fault` | `0: stdio_gate_reasons_not_replayed` | `4079871e08a5957dbe1d9594638ab32952d1445edab091dc4c5177ced1e01fab` |
| `acceptance.stdio-gate.failed-wire-write` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_failed_wire_write` | `2: missing_wire_evidence` | `8095db9973c4a4b9cdb83afa298592dd5d89b700237a147da9b4fc50deaa3170` |
| `acceptance.stdio-gate.malformed-body` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_malformed_body` | `0: stdio_gate_reasons_not_replayed` | `7cd6f58b234677f15c055e99536aff5256f390999a95e247db6ec817170653a9` |
| `acceptance.stdio-gate.malformed-bundle` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioBundleMutationAcceptance.test_malformed_bundle` | `1: bundle_unreadable` | `5ef89bafa6092890aec23660c0e17c942581171edd49b98297033e8eff090810` |
| `acceptance.stdio-gate.missing-declaration` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_missing_declaration` | `0: stdio_gate_reasons_not_replayed` | `5ef89bafa6092890aec23660c0e17c942581171edd49b98297033e8eff090810` |
| `acceptance.stdio-gate.no-event-observation` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_no_event_observation` | `0: default_profile` | `31d17200ff22a059c4f1f710dafa3badb8872e237f7d8296fdcf4d57422c5aa4` |
| `acceptance.stdio-gate.no-list-client` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_no_list_client` | `0: stdio_gate_reasons_not_replayed` | `5ef89bafa6092890aec23660c0e17c942581171edd49b98297033e8eff090810` |
| `acceptance.stdio-gate.public-canary` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_public_canary` | `2: public_gate_tool_hashed` | `277d10095fab618aa06ed3c88f643eb660ca3f1083634407763224ed44e17194` |
| `acceptance.stdio-gate.signed-rewrite` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioBundleMutationAcceptance.test_signed_rewrite` | `1: signature_invalid` | `cdfc0fda49827ce7c8702094381b2a09095c5d1b5563f3e980b9399397fdc61f` |
| `acceptance.stdio-gate.stale-surface` | `PYTHONPATH=src python -m unittest tests.test_acceptance.TestStdioAcceptance.test_stale_surface` | `0: default_profile` | `982de78386952f3fff1e5153ca2aa983bbf2bfdd5e5b53593f51de3515a41a27` |

## Path applicability

Anonymous modern scope and `--public-surface` are HTTP-only. Stdio now has
one distinct header epoch and one decision journal per capture; new regression
tests cover multiple stdio epochs and wire/journal tampering.

The seven intact raw stdio rows formerly reported `2: no_journal_for_path`;
they now report `0`. The gate-fault row injects a **gate** exception, which is
recorded as `gate_skipped/gate_check_error`, not an analysis-engine fault.
Malformed input is an admission block; missing-declaration/no-list forwards
carry `gate_skipped/no_surface_timeout`. Those four rows name the unreplayed
gate-reasons limit. Concurrent correlation, blank lines (folded as MESSAGE),
and stale-surface exclusion now replay and link successfully.

Failed wire persistence remains `2`, now with `missing_wire_evidence`.
Malformed-bundle and signed-rewrite rows remain `1`. Public verify remains `2`
because redacted evidence cannot reproduce raw analysis. All HTTP verdicts
and normalized fingerprints are unchanged by stdio journaling.
