"""Verify a recorded decision journal against the wire capture of its epoch.

Equivalence is a claim about two runs of the same analysis over the same
evidence, so this module refuses to make it unless it can first prove the
preconditions:

* the journal carries a configuration profile, and that profile matches the
  implementation and pattern configuration active right now (schema, policy
  version, detector engine identity, frozen PII pattern digest);
* the recorded pattern profile is reproducible — a consumer-registered
  arbitrary callable validator cannot be reconstructed from a digest, so such a
  run is reported ``incomplete``, never compared and called equal;
* the wire evidence for the epoch is present, in order, and belongs to that
  epoch.

Where a precondition fails the run is ``unsupported``; where the recording
itself was partial — a detector fault captured during the original pass, a
record dropped by the journal's per-epoch bound, or wire evidence missing for a
recorded decision — the run is ``incomplete``. A recorded fault is *never*
re-executed and compared: whether detectors raise identically twice is not a
fact this module is willing to assume.

Digests here cross-check artifacts. They are not signatures: an attacker able
to rewrite both the journal and the wire log can make them agree, and nothing
in this module claims otherwise.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import sys

from glassport import decision_journal as dj
from glassport import detectors, policy
from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.incremental import DetectorEngine, default_detectors
from glassport.session import SessionLimits

STATUS_EQUIVALENT = "equivalent"
STATUS_DIVERGENT = "divergent"
STATUS_INCOMPLETE = "incomplete"
STATUS_UNSUPPORTED = "unsupported"

# Replay reads the wire file whole and line by line, deliberately NOT through
# from_mcp_session_file(): that reader's default 50 MB tail cap would silently
# compare a recorded journal against a partial capture.


@dataclass
class ReplayResult:
    status: str
    epoch: str | None = None
    compared: int = 0
    matched: int = 0
    mismatched: list = field(default_factory=list)
    recorded_faults: int = 0
    missing_evidence: list = field(default_factory=list)
    not_analyzable: int = 0
    reasons: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"status": self.status, "epoch": self.epoch,
                "compared": self.compared, "matched": self.matched,
                "mismatched": list(self.mismatched),
                "recorded_faults": self.recorded_faults,
                "missing_evidence": list(self.missing_evidence),
                "not_analyzable": self.not_analyzable,
                "reasons": list(self.reasons)}


def _unsupported(reason, epoch=None) -> ReplayResult:
    return ReplayResult(STATUS_UNSUPPORTED, epoch, reasons=[reason])


def _read_records(path):
    """Parse a JSONL artifact; returns (records, error_reason)."""
    records = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    return records, "malformed_line"
                if not isinstance(obj, dict):
                    return records, "malformed_line"
                records.append(obj)
    except OSError:
        return records, "unreadable"
    return records, None


def _profile_core(record) -> tuple:
    """The identity of a configuration profile, ignoring per-write fields."""
    return (record.get("schema"), record.get("mode"),
            record.get("policy_version"), record.get("detector_engine"),
            record.get("pattern_digest"), record.get("pattern_status"),
            json.dumps(record.get("registry_limits"), sort_keys=True),
            json.dumps(record.get("session_limits"), sort_keys=True))


def _session_limits(record) -> SessionLimits | None:
    raw = record.get("session_limits")
    if not isinstance(raw, dict):
        return None
    try:
        return SessionLimits(**{k: v for k, v in raw.items()
                                if k in SessionLimits.__dataclass_fields__})
    except (TypeError, ValueError):
        return None


def verify_journal(journal_path, wire_path, *, patterns=None) -> ReplayResult:
    """Replay one epoch's journal against its wire log under the same profile."""
    journal, err = _read_records(journal_path)
    if err:
        return _unsupported(f"journal_{err}")
    if not journal:
        return _unsupported("journal_empty")

    profiles = [r for r in journal if r.get("kind") == "profile"]
    if not profiles:
        return _unsupported("profile_missing")
    # An epoch evicted from the journal's bounded map and later resumed writes
    # its profile again. An identical repeat is a benign resume marker; a
    # CONFLICTING one means two different configurations wrote one file.
    if len({_profile_core(p) for p in profiles}) > 1:
        return _unsupported("profile_conflict", profiles[0].get("epoch"))
    profile = profiles[0]
    epoch = profile.get("epoch")

    current = dj.pattern_profile(
        detectors.snapshot_pii_patterns() if patterns is None else patterns)
    for field_name, expected in (("schema", dj.JOURNAL_SCHEMA),
                                 ("policy_version", dj.POLICY_VERSION),
                                 ("detector_engine", dj.DETECTOR_ENGINE_VERSION),
                                 ("pattern_digest", current.digest)):
        if profile.get(field_name) != expected:
            return _unsupported(f"profile_mismatch_{field_name}", epoch)

    result = ReplayResult(STATUS_EQUIVALENT, epoch)
    if profile.get("pattern_status") != dj.PROFILE_REPRODUCIBLE:
        # An arbitrary callable validator was active. Never compare and call it
        # equal — the recording cannot be reconstructed from what is on disk.
        result.status = STATUS_INCOMPLETE
        result.reasons.append("nonreproducible_pattern_profile")
        return result
    if profile.get("pattern_snapshot_exact") is False:
        result.status = STATUS_INCOMPLETE
        result.reasons.append("pattern_snapshot_inexact")
        return result
    if any(r.get("kind") == "truncated" for r in journal):
        result.status = STATUS_INCOMPLETE
        result.reasons.append("journal_truncated")
        return result

    intents = [r for r in journal if r.get("kind") == "intent"]
    if any(r.get("epoch") != epoch for r in journal):
        return _unsupported("journal_epoch_mismatch", epoch)

    wire, err = _read_records(wire_path)
    if err:
        return _unsupported(f"wire_{err}", epoch)

    by_seq, last = {}, None
    limits = _session_limits(profile)
    builder = MCPTraceBuilder(retain_events=False, limits=limits)
    engine = DetectorEngine(default_detectors(
        detectors.snapshot_pii_patterns() if patterns is None else patterns))
    for entry in wire:
        seq = entry.get("seq")
        if entry.get("type") == "glassport.metrics":
            continue
        if isinstance(seq, int) and not isinstance(seq, bool):
            if last is not None and seq <= last:
                return _unsupported("wire_reordered", epoch)
            last = seq
        observation = entry.get("http_observation")
        if isinstance(observation, dict) and observation.get("epoch") not in (None, epoch):
            return _unsupported("wire_epoch_mismatch", epoch)
        try:
            event = builder.feed(entry)
        except Exception:
            return _unsupported("wire_unfoldable", epoch)
        if event is None or not isinstance(seq, int):
            continue
        by_seq[seq] = (event, tuple(engine.on_event(event, builder.state)))

    previous = None
    for record in intents:
        seq = record.get("event_seq")
        if record.get("faults"):
            # Recorded fault: analysis was already incomplete when this decision
            # was made. Re-running detectors that may not raise this time proves
            # nothing about equivalence, so this record is never compared.
            result.recorded_faults += 1
            continue
        if not isinstance(seq, int) or isinstance(seq, bool):
            result.not_analyzable += 1
            continue
        if previous is not None and seq <= previous:
            return _unsupported("journal_reordered", epoch)
        previous = seq
        if seq not in by_seq:
            result.missing_evidence.append(seq)
            continue
        event, annotations = by_seq[seq]
        faults = [a for a in annotations if getattr(a, "subcategory", None) == "detector_error"]
        findings = dj.semantic_findings(annotations, event.id)
        # The recorded `action` is the CANDIDATE verdict, which record_intent
        # computes with the blocking rule armed in both modes. Replaying it
        # with block_fabricated=False would report action_mismatch for every
        # real observed-surface exclusion, in observe-mode journals as much as
        # gate-mode ones. Mode needs no branch here precisely because the
        # candidate is mode-independent; what a gate additionally *did* with it
        # lives in the delivery records, which equivalence does not re-execute.
        decision = policy.decide(event.id, annotations, block_fabricated=True)
        problems = []
        if faults:
            problems.append("unrecorded_fault")
        if decision.action.value != record.get("action"):
            problems.append("action_mismatch")
        if dj.findings_digest(findings) != record.get("findings_digest"):
            problems.append("findings_mismatch")
        result.compared += 1
        if problems:
            result.mismatched.append({"event_seq": seq, "problems": problems,
                                      "recorded_action": record.get("action"),
                                      "replayed_action": decision.action.value})
        else:
            result.matched += 1

    if result.mismatched:
        result.status = STATUS_DIVERGENT
        result.reasons.append("findings_or_action_diverged")
        return result
    if result.missing_evidence:
        result.status = STATUS_INCOMPLETE
        result.reasons.append("missing_wire_evidence")
    if result.recorded_faults:
        result.status = STATUS_INCOMPLETE
        result.reasons.append("recorded_fault_not_re_executed")
    if not result.compared and result.status == STATUS_EQUIVALENT:
        result.status = STATUS_INCOMPLETE
        result.reasons.append("no_comparable_records")
    return result


def main(argv: list[str]) -> int:
    """`glassport replay-decisions <journal.jsonl> --wire <session.jsonl>`.

    Exit 0 only when equivalence is proved; 1 when it is not (divergent,
    incomplete or unsupported); 2 on a usage error.
    """
    args, wire, as_json = list(argv), None, False
    positional = []
    while args:
        arg = args.pop(0)
        if arg == "--json":
            if as_json:
                print("glassport: --json given twice", file=sys.stderr)
                return 2
            as_json = True
        elif arg == "--wire":
            if wire is not None or not args:
                print("glassport: --wire requires exactly one session log",
                      file=sys.stderr)
                return 2
            wire = args.pop(0)
        elif arg.startswith("-"):
            print(f"glassport: unknown option {arg!r} for replay-decisions",
                  file=sys.stderr)
            return 2
        else:
            positional.append(arg)
    if len(positional) != 1 or wire is None:
        print("usage: glassport replay-decisions <journal.jsonl> "
              "--wire <session.jsonl> [--json]", file=sys.stderr)
        return 2
    result = verify_journal(Path(positional[0]), Path(wire))
    if as_json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"replay: {result.status} (epoch {result.epoch})")
        print(f"  compared={result.compared} matched={result.matched} "
              f"recorded_faults={result.recorded_faults} "
              f"missing_evidence={len(result.missing_evidence)}")
        for reason in result.reasons:
            print(f"  reason: {reason}")
        for item in result.mismatched:
            print(f"  mismatch seq={item['event_seq']}: "
                  f"{','.join(item['problems'])}")
    return 0 if result.status == STATUS_EQUIVALENT else 1
