"""Versioned decision-intent and delivery-outcome records for observed epochs.

This module records what analysis *concluded* and what the transport *actually
did*. It has no transport authority: nothing here forwards, delays, alters or
blocks a byte, and every entry point fails open (returns a falsy value) rather
than raising into a relay.

Three invariants hold every record honest:

* **Separate stream.** Decision records live in their own per-epoch file, never
  merged into the wire capture. They carry epoch + wire sequence linkage so the
  two can be joined later, deliberately, by a reader that owns both.
* **Structured facts only.** Annotation ``explanation``/``detail`` text, tool
  names, hosts, paths, arguments and payload bytes are attacker-influenced and
  are *never* copied here. Only fixed vocabularies (annotation kind, sanitized
  subcategory, integer severity, decision action/reason, delivery outcome code)
  and digests of canonical semantic content reach disk.
* **Intent is not delivery.** A candidate action is recorded before the upstream
  request begins; the terminal delivery outcome is recorded after it resolves.
  In observation mode a candidate BLOCK would still forward — which is exactly
  why the two records are distinct. A completed local send is never treated as
  proof that a remote tool executed.

Bounds (all configurable through :class:`JournalLimits`, all documented in
``docs/http-decision-journal.md``): tracked epochs, records per epoch, listed
findings per record and listed faults per record are each capped. Nothing here
grows without a limit.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import re
import threading

from glassport import detectors, policy
from glassport.interaction_trace import AnnotationKind

# Bumped by hand whenever the record shape or the decision semantics change.
# Replay refuses to claim equivalence across a change in any of the three.
JOURNAL_SCHEMA = "glassport.decision-journal/1"
POLICY_VERSION = "glassport.policy/1"
DETECTOR_ENGINE_VERSION = "glassport.detectors/1"

MODE_OBSERVE = "observe"

# Delivery outcome vocabulary. "sent" is a completed local send that upstream
# answered — never evidence that a remote tool ran.
OUTCOME_NOT_ATTEMPTED = "not_attempted"   # no upstream request was ever begun
OUTCOME_NOT_SENT = "not_sent"             # begun, provably zero bytes on the wire
OUTCOME_SENT = "sent"                     # complete request sent, status received
OUTCOME_FAILED = "failed"                 # status received, transfer failed after
OUTCOME_UNKNOWN = "unknown"               # indeterminate: partial send or no status
DELIVERY_OUTCOMES = frozenset({
    OUTCOME_NOT_ATTEMPTED, OUTCOME_NOT_SENT, OUTCOME_SENT,
    OUTCOME_FAILED, OUTCOME_UNKNOWN})

# Fixed diagnostic codes; a caller-supplied code outside this set is replaced
# rather than written, so no free text can reach the journal through it.
DELIVERY_CODES = frozenset({
    "not_begun", "framing_rejected", "connect_failed", "send_indeterminate",
    "response_indeterminate", "upstream_response", "body_transfer_failed",
    "handler_aborted", "unspecified"})

_SAFE_TOKEN_RE = re.compile(r"[^a-z0-9_.:/-]")
_MAX_TOKEN_CHARS = 64
_NONCONFORMING = "nonconforming"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_token(value, *, default=_NONCONFORMING) -> str:
    """Reduce a value to a short lowercase token from a fixed charset.

    Detector subcategories are code-authored literals today, but some are built
    from PII pattern categories, which come from operator-supplied config. This
    is the chokepoint that guarantees nothing shaped like prose, markup or a
    payload fragment can ever land in a record.
    """
    if not isinstance(value, str) or not value:
        return default
    cleaned = _SAFE_TOKEN_RE.sub("", value.lower())[:_MAX_TOKEN_CHARS]
    return cleaned or default


def _safe_severity(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(3, value))


def _safe_kind(value) -> str:
    try:
        return AnnotationKind(value).value
    except (ValueError, TypeError):
        return _NONCONFORMING


def _limits_dict(limits) -> dict:
    """Canonical JSON-safe view of a limits dataclass."""
    if limits is None:
        return {}
    if is_dataclass(limits) and not isinstance(limits, type):
        raw = asdict(limits)
    elif isinstance(limits, dict):
        raw = dict(limits)
    else:
        return {}
    return {str(k): v for k, v in sorted(raw.items())
            if isinstance(v, (int, float, str, bool)) or v is None}


# --- configuration profile ------------------------------------------------

# Reverse map from the declarative validator menu, by identity: a pattern whose
# validator IS one of these can be reconstructed from a name, so it round-trips
# through pii_pattern_from_dict and is reproducible. Anything else supplied by
# a consumer is an arbitrary Python callable that no digest can reconstruct.
def _validator_name(fn) -> str | None:
    if fn is None:
        return None
    for name, known in detectors._NAMED_VALIDATORS.items():
        if fn is known:
            return name
    return None


VALIDATOR_BUILTIN = "<builtin>"     # pinned by DETECTOR_ENGINE_VERSION
VALIDATOR_OPAQUE = "<opaque>"       # arbitrary callable: not reproducible

PROFILE_REPRODUCIBLE = "reproducible"
PROFILE_INCOMPLETE = "incomplete"


def _pattern_descriptor(pat, builtin: bool) -> dict:
    """Everything that decides what a pattern matches, in digest order."""
    name = _validator_name(pat.validator)
    if name is None and pat.validator is not None:
        # A built-in default's inline lambda is still pinned by the detector
        # module version; only a consumer-registered callable is unreplayable.
        name = VALIDATOR_BUILTIN if builtin else VALIDATOR_OPAQUE
    return {
        "origin": "builtin" if builtin else "custom",
        "category": _safe_token(pat.category),
        "severity": _safe_severity(pat.severity),
        # The regex SOURCE, never re.Pattern.flags: normalized flag bits are
        # not stable across the 3.10-3.13 matrix and would report a spurious
        # profile mismatch for an identical configuration. Inline flags such
        # as generic_api_key's (?i) live in the source itself.
        "regex": pat.pattern.pattern,
        "validator": name,
    }


@dataclass(frozen=True)
class PatternProfile:
    digest: str
    status: str
    summary: tuple
    unsupported: tuple


def pattern_profile(patterns) -> PatternProfile:
    """Describe a frozen pattern set: digest, reproducibility, and a summary.

    The summary persisted alongside the digest carries a per-pattern regex
    digest rather than the regex source, so a record stays small and readable
    while the profile digest still covers the full matching behavior.
    """
    descriptors, summary, unsupported = [], [], []
    builtins = detectors.PII_PATTERNS
    for pat in patterns or ():
        builtin = any(pat is b for b in builtins)
        d = _pattern_descriptor(pat, builtin)
        descriptors.append(d)
        summary.append({
            "origin": d["origin"], "category": d["category"],
            "severity": d["severity"], "validator": d["validator"],
            "regex_digest": hashlib.sha256(
                d["regex"].encode("utf-8", "surrogatepass")).hexdigest()[:16],
        })
        if d["validator"] == VALIDATOR_OPAQUE:
            unsupported.append(d["category"])
    blob = json.dumps(descriptors, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"))
    return PatternProfile(
        hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest(),
        PROFILE_INCOMPLETE if unsupported else PROFILE_REPRODUCIBLE,
        tuple(summary), tuple(sorted(set(unsupported))))


def semantic_findings(annotations, event_id=None) -> list[dict]:
    """Sanitized (kind, subcategory, severity) triples for one event.

    Explanations and metadata are dropped on the floor: both embed
    attacker-influenced text (tool names, hosts, deltas, payload fragments).
    """
    out = []
    for ann in annotations or ():
        if event_id is not None and getattr(ann, "event_id", None) not in (event_id, ""):
            continue
        out.append({"kind": _safe_kind(getattr(ann, "kind", None)),
                    "subcategory": _safe_token(getattr(ann, "subcategory", None)),
                    "severity": _safe_severity(getattr(ann, "severity", None))})
    return out


def findings_digest(findings) -> str:
    """Order-independent digest of the semantic findings of one event.

    Annotation ids are deliberately excluded: they are fresh random values on
    every run, so including them would make every replay report a mismatch.
    """
    blob = json.dumps(sorted((f["kind"], f["subcategory"], f["severity"])
                             for f in findings),
                      ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


# --- the journal ----------------------------------------------------------

@dataclass(frozen=True)
class JournalLimits:
    max_epochs: int = 128          # tracked epochs (and open journal files)
    max_records: int = 4096        # records written per epoch, profile included
    max_findings: int = 32         # findings LISTED per record (digest covers all)
    max_faults: int = 8            # detector faults listed per record

    def __post_init__(self):
        if any(type(getattr(self, k)) is not int or getattr(self, k) < 1
               for k in ("max_epochs", "max_records", "max_findings", "max_faults")):
            raise ValueError("journal limits must be positive integers")


@dataclass(frozen=True)
class Intent:
    """Handle linking a later delivery record back to its decision record."""
    epoch: str
    n: int
    event_seq: int | None
    action: str
    written: bool


class _EpochJournal:
    def __init__(self, epoch, log, path):
        self.epoch, self.log, self.path = epoch, log, path
        self.records = 0
        self.truncated = False


class DecisionJournal:
    """Per-epoch decision/delivery records beside (never inside) the wire log.

    `observer` supplies the epoch's frozen PII pattern snapshot and the limits
    in force; only `.pattern_snapshot(epoch)`, `.limits` and `.session_limits`
    are used, so a test or an alternative transport can pass any object with
    that surface. Every public method is fail-open: an unwritable directory, a
    mid-write error or an exhausted bound yields a falsy return, never a raise.
    """

    def __init__(self, journal_dir, observer, *, limits: JournalLimits | None = None):
        self.dir = Path(journal_dir)
        self.observer = observer
        self.limits = limits or JournalLimits()
        # There is no other mode: no gate exists, so every record this module
        # writes describes a candidate that was forwarded regardless.
        self.mode = MODE_OBSERVE
        self._lock = threading.Lock()
        self._epochs: OrderedDict[str, _EpochJournal] = OrderedDict()
        # One monotonic ordinal across every epoch of this journal: an evicted
        # epoch that later returns therefore cannot reuse a record number an
        # earlier delivery already links to.
        self._counter = itertools.count(1)
        self._closed = False

    # -- paths / lifecycle -------------------------------------------------

    def path_for(self, epoch) -> Path:
        return self.dir / f"{_safe_token(epoch, default='unknown')}.jsonl"

    def close(self) -> None:
        with self._lock:
            self._closed = True
            entries, self._epochs = list(self._epochs.values()), OrderedDict()
        for entry in entries:
            self._close(entry)

    @staticmethod
    def _close(entry) -> None:
        try:
            if entry.log is not None:
                entry.log.close()
        except Exception:
            pass

    # -- internals ---------------------------------------------------------

    def _write(self, entry, record) -> bool:
        """Append one record, honoring the per-epoch bound. Never raises."""
        if entry.records >= self.limits.max_records:
            if not entry.truncated:
                entry.truncated = True
                # One marker past the cap, then silence: replay reads it and
                # refuses to claim equivalence over a prefix.
                self._emit(entry, {"kind": "truncated", "epoch": entry.epoch,
                                   "n": next(self._counter), "ts": _now_iso(),
                                   "limit": self.limits.max_records})
            return False
        return self._emit(entry, record)

    def _emit(self, entry, record) -> bool:
        entry.records += 1
        if entry.log is None:
            return False
        try:
            return bool(entry.log.write_json(record))
        except Exception:
            return False

    def _open(self, epoch):
        """Return the epoch journal, opening (and profiling) it on first use.

        Caller holds the lock. Returns None only when the epoch id is unusable.
        """
        entry = self._epochs.get(epoch)
        if entry is not None:
            self._epochs.move_to_end(epoch)
            return entry
        while len(self._epochs) >= self.limits.max_epochs:
            self._close(self._epochs.popitem(last=False)[1])
        from glassport.tap import open_session_log
        path = self.path_for(epoch)
        try:
            log = open_session_log(path)
        except Exception:
            log = None
        entry = _EpochJournal(epoch, log, path)
        self._epochs[epoch] = entry
        self._write(entry, self._profile_record(epoch))
        return entry

    def _profile_record(self, epoch) -> dict:
        """The versioned configuration profile, written once per epoch.

        Later records reference it by epoch id; none of them copies it.
        """
        try:
            patterns = self.observer.pattern_snapshot(epoch)
        except Exception:
            patterns = None
        if patterns is None:
            # The epoch is gone from the registry (retired between the fold and
            # this write). Describe the live registry instead and say so, rather
            # than inventing a profile the recording never used.
            patterns = detectors.snapshot_pii_patterns()
            exact = False
        else:
            exact = True
        try:
            profile = pattern_profile(patterns)
        except Exception:
            # A malformed/adversarial pattern (a custom pattern object missing
            # an expected attribute, a non-compiled `.pattern`, etc.) must not
            # raise into the caller. Fall back to an explicitly incomplete,
            # empty profile rather than claim a digest over patterns this call
            # could not describe; `exact` drops to False too, since what got
            # persisted no longer reflects the patterns actually in force.
            profile = PatternProfile(digest="", status=PROFILE_INCOMPLETE,
                                      summary=(), unsupported=(_NONCONFORMING,))
            exact = False
        return {
            "kind": "profile", "schema": JOURNAL_SCHEMA, "epoch": epoch,
            "n": next(self._counter), "ts": _now_iso(), "mode": self.mode,
            "policy_version": POLICY_VERSION,
            "detector_engine": DETECTOR_ENGINE_VERSION,
            "pattern_digest": profile.digest,
            "pattern_status": (profile.status if exact else PROFILE_INCOMPLETE),
            "pattern_snapshot_exact": exact,
            "unsupported_patterns": list(profile.unsupported),
            "patterns": list(profile.summary),
            "registry_limits": _limits_dict(getattr(self.observer, "limits", None)),
            "session_limits": _limits_dict(getattr(self.observer, "session_limits", None)),
            "journal_limits": _limits_dict(self.limits),
        }

    # -- public recording --------------------------------------------------

    def record_intent(self, epoch, observation=None) -> Intent | None:
        """Record the candidate action for one observed frame, before delivery.

        Returns a handle for the matching delivery record, or None when there
        is no epoch to attribute the decision to (an unroutable request that
        never got a context, or a closed journal) — unavailable evidence stays
        fail-open, exactly as the surrounding observation path does.
        """
        if self._closed or not isinstance(epoch, str) or not epoch:
            return None
        # Epoch ids are locally generated hex today, so this is a no-op for
        # every real caller — and a guarantee that no future one can route an
        # arbitrary string into a record or a filename.
        epoch = _safe_token(epoch, default="")
        if not epoch:
            return None
        event = getattr(observation, "event", None)
        annotations = tuple(getattr(observation, "annotations", ()) or ())
        event_id = getattr(event, "id", None) if event is not None else None
        analyzed = isinstance(event_id, str) and bool(event_id)
        try:
            if analyzed:
                decision = policy.decide(event_id, annotations, block_fabricated=False)
                action, reason = decision.action.value, decision.reason
                findings = semantic_findings(annotations, event_id)
            else:
                # skip-marked or unparseable frames fold to no event: there is
                # nothing to decide over, and policy.decide rejects an empty id.
                action, reason, findings = policy.Action.ALLOW.value, "no_analyzable_event", []
            faults = [{"detector": _safe_token(a.metadata.get("detector")),
                       "error_type": _safe_token(a.metadata.get("error_type"))}
                      for a in annotations
                      if getattr(a, "subcategory", None) == "detector_error"]
        except Exception:
            # policy.decide() and the faults scan read annotation attributes
            # directly, with no getattr() guard, because real annotations are
            # engine-produced and trusted. A malformed/adversarial annotation
            # object (a future caller, a buggy custom detector) must not raise
            # out of the journal: no honest record can be written for evidence
            # this call could not even parse, so this folds to the same
            # "nothing to attribute the decision to" case used above —
            # unavailable evidence stays fail-open.
            return None
        wire_seq = getattr(observation, "seq", None)
        if isinstance(wire_seq, bool) or not isinstance(wire_seq, int):
            wire_seq = None
        # event_seq is the comparison key: the wire sequence of the entry that
        # produced a foldable event. A frame that legitimately folds to no
        # event (skip-marked, transport-only) keeps its wire_seq for linkage
        # but carries no event_seq, so replay reports it as not-analyzable
        # rather than as evidence that went missing.
        event_seq = wire_seq if analyzed else None
        diagnostic = _safe_token(getattr(observation, "diagnostic", None), default="") or None
        record = {
            "kind": "intent", "schema": JOURNAL_SCHEMA, "epoch": epoch,
            "n": 0, "ts": _now_iso(), "mode": self.mode,
            "action": action, "reason": _safe_token(reason),
            # Observation mode never enforces; a candidate block would still
            # forward. The field exists so a later gate records the same shape.
            "candidate_block": action == policy.Action.BLOCK.value,
            "wire_seq": wire_seq,
            "event_seq": event_seq,
            "persisted": bool(getattr(observation, "persisted", False)),
            "diagnostic": diagnostic,
            "findings": findings[:self.limits.max_findings],
            "findings_total": len(findings),
            "findings_digest": findings_digest(findings),
            "faults": faults[:self.limits.max_faults],
            "faults_total": len(faults),
        }
        with self._lock:
            if self._closed:
                return None
            entry = self._open(epoch)
            record["n"] = next(self._counter)
            written = self._write(entry, record)
        return Intent(epoch, record["n"], event_seq, action, written)

    def record_delivery(self, intent, outcome, *, code=None, status=None) -> bool:
        """Record the terminal delivery outcome for one recorded intent.

        A "sent" outcome means the complete request left the local socket and
        upstream answered. It is not evidence that a remote tool executed.
        """
        if self._closed or not isinstance(intent, Intent):
            return False
        if outcome not in DELIVERY_OUTCOMES:
            outcome = OUTCOME_UNKNOWN
        if code not in DELIVERY_CODES:
            code = "unspecified"
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            status = None
        record = {
            "kind": "delivery", "schema": JOURNAL_SCHEMA, "epoch": intent.epoch,
            "n": 0, "ts": _now_iso(), "mode": self.mode, "intent": intent.n,
            "outcome": outcome, "code": code, "status": status,
            # Observation mode changes no traffic; a recorded candidate block
            # was still forwarded. Task 4 flips this, not this module.
            "enforced": False,
            "candidate_action": intent.action,
        }
        with self._lock:
            if self._closed:
                return False
            entry = self._open(intent.epoch)
            record["n"] = next(self._counter)
            return self._write(entry, record)
