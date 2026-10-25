"""Deterministic finding identity without replacing random Annotation.id.

PLAY-BY-PLAY
------------
Every finding carries two identities, and they answer different questions.

`Annotation.id` is random. It is unique inside one run, which is all a
dedupe pass inside that run ever needs. It is useless across runs: the
same finding in yesterday's capture and today's gets two unrelated ids.

`stable_id()` answers the cross-run question. It hashes the inputs that
decided the finding -- engine version, detector name, subcategory, kind,
wire sequence number, and an ordinal -- so the same finding computed
from the same inputs always lands on the same 24 hex characters. That
is what makes a bundle diff, a replay comparison, or a "my fix actually
removed this finding" check possible at all.

The order of work:

1. `stable_id()` builds the hash. Its determinism depends on the JSON
   being canonical: fixed tuple order, no whitespace, ASCII only.
   Change a separator and every id in every existing bundle stops
   matching, because the id is a format, not an implementation detail.
2. `assign_stable_ids()` walks one detector's annotations and stamps
   ``metadata["stable_id"]`` onto each.

The engine version sits inside the hash on purpose. Upgrading the
engine re-keys every finding, so a stale suppression or baseline cannot
keep silently applying to detector behavior that changed underneath it.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not deduplicate, order, filter, or judge severity. It does not
replace `Annotation.id`, and it does not make a repeated finding any
less true. An identity is a name, not evidence.
"""
from __future__ import annotations

import hashlib
import json


def stable_id(detector_name: str, subcategory: str, kind: str,
              seq: int | None, ordinal: int) -> str:
    # PLAY: Imported inside the call, not at module scope. The constant
    # lives in a module that imports the whole detector engine, and
    # detectors imports this file. Reading the constant here means an
    # importer of finding_ids never pays for the engine, and the import
    # graph is walked only when a hash is actually built.
    from glassport.decision_journal import DETECTOR_ENGINE_VERSION

    # PLAY: The tuple order IS the format. Insert a field anywhere but
    # the end and every previously issued stable id changes meaning.
    parts = (DETECTOR_ENGINE_VERSION, detector_name, subcategory, kind,
             seq, ordinal)
    # PLAY: separators=(",", ":") strips the spaces json.dumps adds by
    # default. Whitespace is part of the bytes being hashed, so leaving
    # it in would make the id depend on formatting rather than content.
    blob = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()[:24]


def assign_stable_ids(annotations, detector_name: str) -> None:
    """Number duplicates within each event and semantic finding category."""
    # PLAY: One counter per (frame, subcategory, kind). This exists for
    # the case where a single frame produces two otherwise identical
    # findings: without the ordinal they would share an id and read as
    # one finding that fired twice. Keeping the key narrow also means
    # unrelated findings never consume each other's numbers.
    ordinals: dict[tuple, int] = {}
    for ann in annotations:
        # PLAY: metadata is the detector's own bookkeeping. Trust it
        # only when it really is a dict; anything else gets a fresh one,
        # so a malformed value cannot steer the counter below.
        metadata = ann.metadata if isinstance(ann.metadata, dict) else {}
        seq = metadata.get("seq")
        # PLAY: `type(seq) is int`, not isinstance: bool is an int
        # subclass, and True would silently open a second ordinal bucket
        # for the same wire frame.
        seq = seq if type(seq) is int else None
        kind = getattr(ann.kind, "value", str(ann.kind))
        subcategory = ann.subcategory or "annotation"
        key = (seq, subcategory, kind)
        ordinal = ordinals.get(key, 0)
        ordinals[key] = ordinal + 1
        # PLAY: Written back onto the annotation rather than returned, so
        # every later reader (report, SARIF, journal, replay) sees the
        # same name for the same finding without re-deriving it.
        metadata["stable_id"] = stable_id(detector_name, subcategory, kind,
                                          seq, ordinal)
        ann.metadata = metadata
