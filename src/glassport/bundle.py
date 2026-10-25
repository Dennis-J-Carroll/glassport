"""Portable, versioned capture bundle. Manifest records facts; verify derives claims.

PLAY-BY-PLAY
------------
A bundle is what you hand someone else: wire logs, decision journals,
SARIF, limits, and optional signatures, in one directory with a manifest
that describes it. The design rule in the docstring above is the whole
architecture -- the manifest records facts, and `verify` derives claims
from them.

The build path:

1. `build_bundle()` reads the inputs and writes each artifact, recording
   its digest in the manifest. `canonical_bytes()` is what makes those
   digests stable: RFC 8785 JSON, so two encoders agree on the bytes.
2. `_wire_facts()` and `compute_limits()` record what the capture does and
   does not prove. A bundle that claims more than its wire supports is the
   failure mode this section exists to prevent.
3. `_public_tier()` produces a redacted copy for sharing, with
   `_redact_value()` applied; the private tier stays put.

The verify path is separate on purpose: `verify_bundle()` re-reads the
files, recomputes the digests, and reports what is and is not proven --
signature status, chain integrity, limits. It trusts the manifest only as
far as it can check it.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not evaluate policy, does not repair a broken bundle, and does not
claim authenticity from a digest. Digests prove the files agree with the
manifest; only a signature proves who wrote them.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import sys

from glassport import __version__, audit, decision_replay, detectors, sarif
from glassport.adapters.mcp_session import from_mcp_session_file
from glassport.limits import compute_limits


SCHEMA = "glassport.bundle/1"


# PLAY: RFC 8785. Two writers that both follow it produce byte-identical
# output for the same value, which is the precondition for every digest in
# this file. Without a canonical form, a digest would depend on key order
# and whitespace rather than content.
def canonical_bytes(value) -> bytes:
    """RFC 8785 JSON canonicalization for JSON-safe Python values.

    Object keys use UTF-16 code-unit order. Floats use shortest round-trip
    decimal representation with ECMAScript's fixed/scientific thresholds.
    Non-finite values and integers outside binary64's exact range fail closed.
    """
    def number(value):
        if isinstance(value, int):
            if abs(value) > 2**53 - 1:
                raise ValueError("JCS integer exceeds exact binary64 range")
            return str(value)
        if not math.isfinite(value):
            raise ValueError("JCS forbids non-finite numbers")
        if value == 0:
            return "0"
        raw = repr(value)
        magnitude = abs(value)
        if 1e-6 <= magnitude < 1e21:
            fixed = format(Decimal(raw), "f")
            return fixed.rstrip("0").rstrip(".") if "." in fixed else fixed
        mantissa, exponent = raw.lower().split("e")
        mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
        exp = int(exponent)
        return f"{mantissa}e{'+' if exp >= 0 else ''}{exp}"

    def encode(item):
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, (int, float)):
            return number(item)
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(part) for part in item) + "]"
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ValueError("JCS object keys must be strings")
            keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
            return "{" + ",".join(encode(key) + ":" + encode(item[key])
                                  for key in keys) + "}"
        raise ValueError(f"JCS unsupported value: {type(item).__name__}")

    return encode(value).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# PLAY: Both the parsed records and the original bytes are kept. The bytes
# are what gets hashed into the manifest, so verification can re-hash exactly
# what was received instead of a re-serialization that might differ by
# whitespace and make an intact bundle look tampered with.
def _read_jsonl(path: Path) -> tuple[list[dict], list[bytes]]:
    records, lines = [], []
    for raw in path.read_bytes().splitlines(keepends=True):
        if not raw.strip():
            continue
        item = json.loads(raw)
        if not isinstance(item, dict):
            raise ValueError(f"non-object JSONL record: {path}")
        records.append(item)
        lines.append(raw)
    return records, lines


# PLAY: The capture's own bookends, read once and returned as named values.
# Note the epoch check: an HTTP session that resumed across a reconnect can
# carry observations from two epochs, and splicing those into one timeline
# would invent an ordering the wire never had. That is an error, not a
# limitation.
def _wire_facts(records: list[dict], lines: list[bytes]):
    header = next((r for r in records if r.get("type") == "glassport.header"), None)
    trailer_positions = [i for i, r in enumerate(records)
                         if r.get("type") == "glassport.metrics"]
    trailer = records[trailer_positions[-1]] if trailer_positions else None
    entries = [r for r in records if type(r.get("seq")) is int]
    seqs = [r["seq"] for r in entries]
    pretrailer = b"".join(lines[:trailer_positions[-1]]) if trailer else None
    epochs = {obs.get("epoch") for r in entries
              for obs in [r.get("http_observation")]
              if isinstance(obs, dict) and isinstance(obs.get("epoch"), str)}
    if len(epochs) > 1:
        raise ValueError("wire_epoch_mismatch: multiple epochs in one log")
    epoch = next(iter(epochs)) if epochs else "stdio"
    return header, trailer, entries, seqs, pretrailer, epoch


# PLAY: Manifest paths are data, so they can point anywhere. Every read
# and write goes through here to keep a member inside the bundle root --
# a manifest that names ../../etc/passwd must not become a file access.
def _safe_member(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("bundle_path_unsafe")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("bundle_path_unsafe")
    return resolved


def _artifact(path: str, data: bytes) -> dict:
    return {"path": path, "sha256": _digest(data)}


# PLAY: Two captures can legitimately share a stable name (same server, same
# second). The filename has to stay unique without being random, or the same
# inputs would produce a different bundle every run. Suffixing with a digest
# of the context gives a deterministic tiebreak.
def _unique_stable(existing: dict, stable: str, context: str) -> str:
    if stable not in existing:
        return stable
    suffix = _digest(context.encode("utf-8"))[:8]
    candidate = f"{stable}-{suffix}"
    number = 2
    while candidate in existing:
        candidate = f"{stable}-{suffix}-{number}"
        number += 1
    return candidate


def _load_private_key(path: Path):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ValueError("--sign requires cryptography (install glassport[attestation])") from exc
    data = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        key = Ed25519PrivateKey.from_private_bytes(data)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("--sign requires an Ed25519 private key")
    return key


# PLAY: Four answers, and the difference between them is the point:
# "absent", "present, no trusted key given", "present, not verified
# (cryptography not installed)", and "valid"/"invalid". A bundle with a
# signature and no key to check it against is not verified, and saying so is
# more useful than refusing or, worse, printing "signed".
def _signature_status(root: Path, manifest: dict, trusted_key: Path | None) -> str:
    sig_path = root / "manifest.sig"
    if not sig_path.exists():
        return "absent"
    if trusted_key is None:
        return "present, no trusted key given"
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return "present, not verified (cryptography not installed)"
    data = trusted_key.read_bytes()
    try:
        try:
            key = serialization.load_pem_public_key(data)
        except ValueError:
            key = Ed25519PublicKey.from_public_bytes(data)
        if not isinstance(key, Ed25519PublicKey):
            return "invalid"
        sig = base64.b64decode(sig_path.read_bytes().strip(), validate=True)
        key.verify(sig, canonical_bytes(manifest))
        raw = key.public_bytes(serialization.Encoding.Raw,
                               serialization.PublicFormat.Raw)
        return f"valid (fingerprint {_digest(raw)})"
    except (ValueError, InvalidSignature):
        return "invalid"


# PLAY: Applied to the public tier only. The private tier keeps the real
# values; the shareable copy is scrubbed field by field so a bundle can be
# sent to someone without also sending the credentials it captured.
def _redact_value(value):
    """Public tier: redact every free-text leaf, including SARIF and profile."""
    if isinstance(value, str):
        return detectors.redact_secrets_strict(value)
    if isinstance(value, list):
        return [_redact_value(part) for part in value]
    if isinstance(value, dict):
        return {_redact_value(key): _redact_value(part)
                for key, part in value.items()}
    return value


# PLAY: `mode=0o700` on the directory and `0o600` on the file, plus the
# explicit chmod afterwards because open() honors umask. These files hold
# captured traffic, which routinely contains tokens; on a shared host the
# window between create and chmod is the only exposure, and 0o600 closes it.
def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as output:
        output.write(data)
    if os.name == "posix":
        path.chmod(0o600)


def _public_tier(root: Path, manifest: dict) -> None:
    public = root / "public"
    public.mkdir(mode=0o700)
    redacted = _redact_value(deepcopy(manifest))
    raw_hashes: dict[str, str] = {}
    for index, epoch in enumerate(redacted["evidence"]["epochs"], 1):
        original = manifest["evidence"]["epochs"][index - 1]
        alias = "stdio" if original["epoch"] == "stdio" else f"epoch-{index:04d}"
        epoch["epoch"] = alias
        for kind in ("wire", "journal"):
            if epoch[kind] is None:
                continue
            old = original[kind]["path"]
            raw_hashes[old] = original[kind]["sha256"]
            source = _safe_member(root, old)
            records, _ = _read_jsonl(source)
            for position, original_record in enumerate(records):
                record = _redact_value(original_record)
                records[position] = record
                if kind == "journal":
                    record["epoch"] = alias
                obs = record.get("http_observation")
                if isinstance(obs, dict) and "epoch" in obs:
                    obs["epoch"] = alias
            rel = f"evidence/{alias}.{kind}.jsonl"
            data = b"".join(json.dumps(record, ensure_ascii=False,
                                       separators=(",", ":")).encode("utf-8") + b"\n"
                            for record in records)
            _write_private(public / rel, data)
            epoch[kind]["path"] = rel
            epoch[kind]["sha256"] = _digest(data)
            if kind == "wire":
                epoch[kind]["trailer_log_sha256"] = None
            else:
                epoch[kind]["final_record_sha256"] = _digest(data.splitlines(keepends=True)[-1])
        epoch["replay_argv"] = None  # public redaction changes replay inputs
    for delivery in redacted["delivery"]:
        original_epoch = delivery.get("epoch")
        for index, item in enumerate(manifest["evidence"]["epochs"], 1):
            if item["epoch"] == original_epoch:
                delivery["epoch"] = ("stdio" if item["epoch"] == "stdio"
                                      else f"epoch-{index:04d}")
                break
        delivery["wire_entry_sha256"] = None
    redacted["profile"]["journal_profiles"] = {
        ("stdio" if item["epoch"] == "stdio" else f"epoch-{index:04d}"):
        _redact_value(manifest["profile"]["journal_profiles"].get(item["epoch"]))
        for index, item in enumerate(manifest["evidence"]["epochs"], 1)
        if item["epoch"] in manifest["profile"]["journal_profiles"]}
    for finding in redacted["analysis"]["findings"].values():
        for index, item in enumerate(manifest["evidence"]["epochs"], 1):
            if finding.get("epoch") == item["epoch"]:
                finding["epoch"] = "stdio" if item["epoch"] == "stdio" else f"epoch-{index:04d}"
                break
    sarif_path = manifest["evidence"]["sarif"]["path"]
    raw_hashes[sarif_path] = manifest["evidence"]["sarif"]["sha256"]
    public_sarif = _redact_value(json.loads(_safe_member(root, sarif_path).read_text()))
    for run in public_sarif.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri")
                for index, item in enumerate(manifest["evidence"]["epochs"], 1):
                    if uri == item["wire"]["path"]:
                        physical["artifactLocation"]["uri"] = (
                            f"evidence/epoch-{index:04d}.wire.jsonl" if item["epoch"] != "stdio"
                            else "evidence/stdio.wire.jsonl")
    for index, item in enumerate(manifest["evidence"]["epochs"], 1):
        alias = "stdio" if item["epoch"] == "stdio" else f"epoch-{index:04d}"
        profile = redacted["profile"]["journal_profiles"].get(alias)
        if isinstance(profile, dict):
            profile["epoch"] = alias
    audit_meta = manifest["evidence"]["audit"]
    if audit_meta:
        audit_path = audit_meta["path"]
        raw_hashes[audit_path] = audit_meta["sha256"]
        public_audit = canonical_bytes(_redact_value(json.loads(
            _safe_member(root, audit_path).read_text())))
        _write_private(public / audit_path, public_audit)
        redacted["evidence"]["audit"]["sha256"] = _digest(public_audit)
    sarif_data = canonical_bytes(public_sarif)
    _write_private(public / sarif_path, sarif_data)
    redacted["evidence"]["sarif"]["sha256"] = _digest(sarif_data)
    redacted["raw_tier"] = "withheld"
    raw_hashes["manifest.json"] = _digest((root / "manifest.json").read_bytes())
    if (root / "manifest.sig").exists():
        raw_hashes["manifest.sig"] = _digest((root / "manifest.sig").read_bytes())
    redacted["raw_hashes"] = raw_hashes
    redacted["limits"] = [limit for limit in redacted["limits"]
                          if limit.get("code") != "no_signature"]
    redacted["limits"].append({"code": "public_redaction_not_replay_equivalent"})
    _write_private(public / "manifest.json", canonical_bytes(redacted))


def build_bundle(wire_paths: list[Path], journal_dir: Path | None,
                 audit_path: Path | None, out: Path, sign_key: Path | None = None,
                 redact: bool = False) -> dict:
    """Collect immutable evidence, then record only derived facts in manifest."""
    if not wire_paths:
        raise ValueError("bundle requires at least one wire log")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("output already exists and is not empty")
    key = _load_private_key(sign_key) if sign_key else None
    journal_by_epoch: dict[str, Path] = {}
    if journal_dir is not None:
        for path in sorted(journal_dir.glob("*.jsonl")):
            records, _ = _read_jsonl(path)
            profiles = [r for r in records if r.get("kind") == "profile"]
            if profiles:
                epoch = profiles[0].get("epoch")
                if not isinstance(epoch, str) or any(r.get("epoch") != epoch for r in records):
                    raise ValueError(f"journal_epoch_mismatch: {path}")
                if epoch in journal_by_epoch:
                    raise ValueError(f"duplicate journal epoch: {epoch}")
                journal_by_epoch[epoch] = path
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest = {
        "schema": SCHEMA, "canonicalization": "RFC8785",
        "bundler": {"version": __version__,
                    "created_at": datetime.now(timezone.utc).isoformat()},
        "versions": {}, "evidence": {"epochs": [], "audit": None, "sarif": {}},
        "profile": {"header": None, "journal_profiles": {}},
        "analysis": {"findings": {}}, "delivery": [], "limits": [],
    }
    sarif_rules: dict[str, dict] = {}
    sarif_results: list[dict] = []
    sarif_artifacts: list[dict] = []
    seen_epochs: set[str] = set()
    for source in wire_paths:
        records, lines = _read_jsonl(source)
        header, trailer, entries, seqs, _pretrailer, epoch = _wire_facts(records, lines)
        journal_source = journal_by_epoch.get(epoch)
        if header and header.get("transport") == "http" and epoch == "stdio":
            raise ValueError(f"wire_epoch_missing: {source}")
        if epoch in seen_epochs:
            raise ValueError(f"duplicate wire epoch: {epoch}")
        seen_epochs.add(epoch)
        journal_records = None
        if journal_source:
            journal_records, _ = _read_jsonl(journal_source)
        alias = "stdio" if epoch == "stdio" else f"epoch-{len(seen_epochs):04d}"
        # Opaque file names prevent credential-shaped source names escaping.
        wire_rel = f"evidence/{alias}.wire.jsonl"
        raw = source.read_bytes()
        _write_private(out / wire_rel, raw)
        wire_meta = {**_artifact(wire_rel, raw),
                     "trailer_log_sha256": trailer.get("log_sha256") if trailer else None,
                     "entries": len(entries),
                     "seq_range": [min(seqs), max(seqs)] if seqs else [1, 0]}
        journal_meta = None
        replay_argv = None
        if journal_source:
            journal_rel = f"evidence/{alias}.journal.jsonl"
            journal_raw = journal_source.read_bytes()
            _write_private(out / journal_rel, journal_raw)
            journal_meta = {**_artifact(journal_rel, journal_raw),
                            "records": len(journal_records),
                            "final_record_sha256": _digest(
                                journal_raw.splitlines(keepends=True)[-1])
                            if journal_raw.strip() else None}
            replay_argv = ["glassport", "replay-decisions", journal_rel,
                           "--wire", wire_rel, "--json"]
            profile = next((r for r in journal_records if r.get("kind") == "profile"), None)
            if profile:
                manifest["profile"]["journal_profiles"][epoch] = profile
            intents = {r.get("n"): r for r in journal_records if r.get("kind") == "intent"}
            for record in journal_records:
                if record.get("kind") != "delivery":
                    continue
                intent = intents.get(record.get("intent"), {})
                manifest["delivery"].append({
                    "epoch": epoch, "intent_n": record.get("intent"),
                    "delivery_n": record.get("n"), "wire_seq": intent.get("wire_seq"),
                    "wire_entry_sha256": intent.get("wire_entry_sha256"),
                    "outcome": record.get("outcome"), "code": record.get("code"),
                    "evidence_level": record.get("evidence_level")})
        manifest["evidence"]["epochs"].append({
            "epoch": epoch, "wire": wire_meta, "journal": journal_meta,
            "replay_argv": replay_argv})
        if manifest["profile"]["header"] is None:
            manifest["profile"]["header"] = header
        manifest["limits"].extend(limit for limit in
                                  compute_limits(header, trailer, journal_records, entries)
                                  if sign_key is None or limit["code"] != "no_signature")
        trace = from_mcp_session_file(out / wire_rel)
        detectors.annotate(trace)
        doc = json.loads(sarif.render_session_sarif(trace, str(out / wire_rel)))
        run = doc["runs"][0]
        for rule in run["tool"]["driver"]["rules"]:
            sarif_rules[rule["id"]] = rule
        events_by_id = {event.id: event for event in trace.events}
        for result, annotation in zip(run["results"], trace.annotations):
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = wire_rel
            stable = _unique_stable(manifest["analysis"]["findings"],
                                    result["partialFingerprints"]["stable_id"],
                                    f"{epoch}:{len(sarif_results)}")
            result["partialFingerprints"]["stable_id"] = stable
            manifest["analysis"]["findings"][stable] = {
                "epoch": epoch, "rule_id": result["ruleId"],
                "severity": result["properties"]["severity"],
                "evidence_level": result["properties"]["evidence_level"],
                "wire_seq": events_by_id[annotation.event_id].metadata.get("seq")
                if annotation.event_id in events_by_id else None,
            }
            sarif_results.append(result)
        sarif_artifacts.append({"location": {"uri": wire_rel},
                                "hashes": {"sha-256": wire_meta["sha256"]}})
    header = manifest["profile"]["header"] or {}
    manifest["versions"] = {
        "glassport_version": header.get("glassport_version"),
        "commit": header.get("commit"), "schema_version": header.get("schema_version"),
        "policy_version": header.get("policy_version"),
        "detector_engine": header.get("detector_engine"),
        "journal_schema": header.get("journal_schema"),
    }
    if audit_path is not None:
        report = audit.audit_path(audit_path)
        data = audit.render_json(report).encode("utf-8")
        audit_rel = "evidence/audit.json"
        _write_private(out / audit_rel, data)
        manifest["evidence"]["audit"] = _artifact(audit_rel, data)
        audit_doc = json.loads(sarif.render_sarif(report))
        audit_run = audit_doc["runs"][0]
        for rule in audit_run["tool"]["driver"]["rules"]:
            sarif_rules[rule["id"]] = rule
        for ordinal, result in enumerate(audit_run["results"]):
            location = result.get("locations", [{}])[0].get("physicalLocation", {})
            identity = [result.get("ruleId"), location.get("artifactLocation", {}).get("uri"),
                        location.get("region", {}).get("startLine"), ordinal]
            stable = _unique_stable(manifest["analysis"]["findings"],
                                    _digest(canonical_bytes(identity))[:24],
                                    f"audit:{ordinal}")
            result.setdefault("partialFingerprints", {})["stable_id"] = stable
            manifest["analysis"]["findings"][stable] = {
                "epoch": "audit", "rule_id": result.get("ruleId"),
                "severity": result.get("properties", {}).get("severity"),
                "evidence_level": "analyzed", "wire_seq": None}
            sarif_results.append(result)
    document = json.loads(sarif._sarif_document(
        list(sarif_rules.values()), sarif_results,
        {"bundle_schema": SCHEMA}, sarif_artifacts))
    sarif_data = canonical_bytes(document)
    sarif_rel = "index/findings.sarif.json"
    _write_private(out / sarif_rel, sarif_data)
    manifest["evidence"]["sarif"] = _artifact(sarif_rel, sarif_data)
    manifest_bytes = canonical_bytes(manifest)
    _write_private(out / "manifest.json", manifest_bytes)
    if key:
        _write_private(out / "manifest.sig", base64.b64encode(key.sign(manifest_bytes)) + b"\n")
    if redact:
        _public_tier(out, manifest)
    return manifest


def _verify_bundle_impl(root: Path, trusted_key: Path | None = None) -> dict:
    """Derive replay, delivery, and integrity verdicts from copied artifacts."""
    raw_manifest = (root / "manifest.json").read_bytes()
    manifest = json.loads(raw_manifest)
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported_bundle_schema")
    integrity: list[str] = []
    if manifest.get("canonicalization") != "RFC8785" or raw_manifest != canonical_bytes(manifest):
        integrity.append("manifest_not_canonical")
    signature = _signature_status(root, manifest, trusted_key)
    if signature == "invalid":
        integrity.append("signature_invalid")
    if manifest.get("raw_tier") == "withheld":
        integrity.append("public_redaction_not_replay_equivalent")
    epochs_out: list[dict] = []
    all_delivery: list[dict] = []
    for item in manifest.get("evidence", {}).get("epochs", []):
        epoch = item.get("epoch")
        wire_meta = item.get("wire") or {}
        wire_path = _safe_member(root, wire_meta.get("path", ""))
        wire_raw = wire_path.read_bytes()
        epoch_integrity = []
        if _digest(wire_raw) != wire_meta.get("sha256"):
            epoch_integrity.append("wire_sha256_mismatch")
        wire, raw_lines = _read_jsonl(wire_path)
        header, trailer, entries, seqs, pretrailer, observed_epoch = _wire_facts(
            wire, raw_lines)
        if epoch != observed_epoch:
            epoch_integrity.append("wire_epoch_mismatch")
        if wire_meta.get("entries") != len(entries):
            epoch_integrity.append("wire_entry_count_mismatch")
        if wire_meta.get("seq_range") != ([min(seqs), max(seqs)] if seqs else [1, 0]):
            epoch_integrity.append("wire_seq_range_mismatch")
        if wire_meta.get("trailer_log_sha256") != (trailer.get("log_sha256") if trailer else None):
            epoch_integrity.append("trailer_claim_mismatch")
        delivery_reasons = []
        if trailer is None:
            delivery_reasons.append("trailer_missing")
        elif _digest(pretrailer) != trailer.get("log_sha256"):
            delivery_reasons.append("trailer_log_sha256_mismatch")
        if trailer is not None and wire[-1].get("type") != "glassport.metrics":
            delivery_reasons.append("trailer_not_last")
        if sum(r.get("type") == "glassport.metrics" for r in wire) > 1:
            delivery_reasons.append("trailer_multiple")
        journal_meta = item.get("journal")
        replay = {"status": "unsupported", "reasons": ["no_journal_for_path"]}
        if journal_meta is None:
            delivery_reasons.append("no_journal_for_path")
        else:
            journal_path = _safe_member(root, journal_meta.get("path", ""))
            journal_raw = journal_path.read_bytes()
            if _digest(journal_raw) != journal_meta.get("sha256"):
                epoch_integrity.append("journal_sha256_mismatch")
            journal, journal_lines = _read_jsonl(journal_path)
            if journal_meta.get("records") != len(journal):
                epoch_integrity.append("journal_record_count_mismatch")
            final = _digest(journal_lines[-1]) if journal_lines else None
            if journal_meta.get("final_record_sha256") != final:
                epoch_integrity.append("journal_final_record_mismatch")
            if any(r.get("epoch") != epoch for r in journal):
                epoch_integrity.append("journal_epoch_mismatch")
            recorded_profile = next((r for r in journal if r.get("kind") == "profile"), None)
            if manifest.get("profile", {}).get("journal_profiles", {}).get(epoch) != recorded_profile:
                epoch_integrity.append("journal_profile_mismatch")
            expected_argv = ["glassport", "replay-decisions", journal_meta["path"],
                             "--wire", wire_meta["path"], "--json"]
            if item.get("replay_argv") != expected_argv:
                epoch_integrity.append("replay_argv_mismatch")
            intents = {r.get("n"): r for r in journal if r.get("kind") == "intent"}
            deliveries = [r for r in journal if r.get("kind") == "delivery"]
            by_intent: dict[int, list[dict]] = {}
            for record in deliveries:
                by_intent.setdefault(record.get("intent"), []).append(record)
            for n in intents:
                if len(by_intent.get(n, [])) != 1:
                    delivery_reasons.append("delivery_missing_or_duplicate")
            seq_hashes = {r["seq"]: _digest(raw) for r, raw in zip(wire, raw_lines)
                          if type(r.get("seq")) is int}
            actual_delivery = []
            for record in deliveries:
                intent = intents.get(record.get("intent"))
                if intent is None:
                    delivery_reasons.append("delivery_orphaned")
                    continue
                seq = intent.get("wire_seq")
                digest = intent.get("wire_entry_sha256")
                if digest is None:
                    delivery_reasons.append("wire_digest_missing")
                elif seq_hashes.get(seq) != digest:
                    delivery_reasons.append("delivery_wire_digest_mismatch")
                actual_delivery.append({
                    "epoch": epoch, "intent_n": record.get("intent"),
                    "delivery_n": record.get("n"), "wire_seq": seq,
                    "wire_entry_sha256": digest, "outcome": record.get("outcome"),
                    "code": record.get("code"),
                    "evidence_level": record.get("evidence_level")})
            expected_delivery = [r for r in manifest.get("delivery", [])
                                 if r.get("epoch") == epoch]
            if actual_delivery != expected_delivery:
                epoch_integrity.append("manifest_delivery_mismatch")
            all_delivery.extend(actual_delivery)
            replay = decision_replay.verify_journal(journal_path, wire_path).as_dict()
        epochs_out.append({"epoch": epoch, "analysis": replay,
                           "delivery": {"status": "present" if not delivery_reasons
                                        else "incomplete",
                                        "reasons": sorted(set(delivery_reasons))},
                           "integrity_reasons": sorted(set(epoch_integrity))})
        integrity.extend(epoch_integrity)
    if len(all_delivery) != len(manifest.get("delivery", [])):
        integrity.append("manifest_delivery_mismatch")
    if manifest.get("profile", {}).get("header") != (
            _wire_facts(*_read_jsonl(_safe_member(root,
                manifest["evidence"]["epochs"][0]["wire"]["path"]))))[0]:
        integrity.append("manifest_header_mismatch")
    header = manifest.get("profile", {}).get("header") or {}
    expected_versions = {
        "glassport_version": header.get("glassport_version"),
        "commit": header.get("commit"), "schema_version": header.get("schema_version"),
        "policy_version": header.get("policy_version"),
        "detector_engine": header.get("detector_engine"),
        "journal_schema": header.get("journal_schema")}
    if manifest.get("versions") != expected_versions:
        integrity.append("manifest_versions_mismatch")
    for name in ("sarif", "audit"):
        meta = manifest.get("evidence", {}).get(name)
        if meta:
            data = _safe_member(root, meta.get("path", "")).read_bytes()
            if _digest(data) != meta.get("sha256"):
                integrity.append(f"{name}_sha256_mismatch")
    sarif_meta = manifest.get("evidence", {}).get("sarif")
    if sarif_meta:
        sarif_doc = json.loads(_safe_member(root, sarif_meta["path"]).read_text())
        indexed = {result.get("partialFingerprints", {}).get("stable_id")
                   for run in sarif_doc.get("runs", [])
                   for result in run.get("results", [])}
        if indexed != set(manifest.get("analysis", {}).get("findings", {})):
            integrity.append("manifest_findings_mismatch")
    states = [item["analysis"]["status"] for item in epochs_out]
    analysis_status = next((state for state in ("divergent", "incomplete", "unsupported")
                            if state in states), "equivalent" if states else "incomplete")
    delivery_status = ("present" if epochs_out and all(
        item["delivery"]["status"] == "present" for item in epochs_out)
        else "incomplete")
    integrity = sorted(set(integrity))
    return {
        "analysis_reproduced": {"status": analysis_status,
                                "epochs": [{"epoch": item["epoch"],
                                            **item["analysis"]} for item in epochs_out]},
        "delivery_evidence_present": {"status": delivery_status,
                                      "epochs": [{"epoch": item["epoch"],
                                                  **item["delivery"]} for item in epochs_out]},
        "integrity": {"status": "passed" if not integrity else "failed",
                      "reasons": integrity, "signature": signature},
        "limits": manifest.get("limits", []),
    }


# PLAY: The public verify entry point. It recomputes rather than trusting:
# every digest is checked against the bytes on disk, and the result
# separates "the files are intact" from "the files are authentic".
def verify_bundle(root: Path, trusted_key: Path | None = None) -> dict:
    """Always return both verdicts, integrity, and available limits."""
    try:
        return _verify_bundle_impl(root, trusted_key)
    except (OSError, ValueError, UnicodeError, TypeError, KeyError,
            IndexError, RecursionError) as exc:
        try:
            manifest = json.loads((root / "manifest.json").read_bytes())
            limits = manifest.get("limits", []) if isinstance(manifest, dict) else []
        except (OSError, ValueError, UnicodeError):
            limits = []
        return {
            "analysis_reproduced": {"status": "incomplete", "epochs": []},
            "delivery_evidence_present": {"status": "incomplete", "epochs": []},
            "integrity": {"status": "failed", "reasons": ["bundle_unreadable"],
                          "error_type": type(exc).__name__, "signature": "absent"},
            "limits": limits,
        }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="glassport bundle")
    sub = parser.add_subparsers(dest="verb")
    verify = sub.add_parser("verify")
    verify.add_argument("out", type=Path)
    verify.add_argument("--trusted-key", type=Path)
    verify.add_argument("--json", action="store_true")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--wire", type=Path, nargs="+", action="append")
    source.add_argument("--log-dir", type=Path)
    parser.add_argument("--journal-dir", type=Path)
    parser.add_argument("--audit", type=Path)
    parser.add_argument("-o", "--out", type=Path)
    parser.add_argument("--sign", type=Path)
    parser.add_argument("--redact", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.verb == "verify":
            result = verify_bundle(args.out, args.trusted_key)
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(f"analysis reproduced: {result['analysis_reproduced']['status']}")
                for epoch in result["analysis_reproduced"]["epochs"]:
                    print(f"  {epoch['epoch']}: {epoch['status']} "
                          f"({', '.join(epoch['reasons'])})")
                print(f"delivery evidence present: {result['delivery_evidence_present']['status']}")
                for epoch in result["delivery_evidence_present"]["epochs"]:
                    print(f"  {epoch['epoch']}: {epoch['status']} "
                          f"({', '.join(epoch['reasons'])})")
                print(f"integrity: {result['integrity']['status']} "
                      f"({', '.join(result['integrity']['reasons'])})")
                print(f"signature: {result['integrity']['signature']}")
                print("limits: " + json.dumps(result["limits"], ensure_ascii=False))
            return 0 if (result["analysis_reproduced"]["status"] == "equivalent"
                         and result["delivery_evidence_present"]["status"] == "present"
                         and result["integrity"]["status"] == "passed") else 1
        if not args.out or not (args.wire or args.log_dir):
            parser.error("provide --wire PATH... or --log-dir DIR and -o OUT")
        paths = ([path for group in args.wire for path in group] if args.wire
                 else sorted(args.log_dir.glob("*.jsonl")))
        build_bundle(paths, args.journal_dir, args.audit, args.out,
                     args.sign, args.redact)
        print(args.out)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"glassport bundle: {exc}", file=sys.stderr)
        return 2
