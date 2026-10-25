"""Deterministic finding identity without replacing random Annotation.id."""
from __future__ import annotations

import hashlib
import json


def stable_id(detector_name: str, subcategory: str, kind: str,
              seq: int | None, ordinal: int) -> str:
    from glassport.decision_journal import DETECTOR_ENGINE_VERSION

    parts = (DETECTOR_ENGINE_VERSION, detector_name, subcategory, kind,
             seq, ordinal)
    blob = json.dumps(parts, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()[:24]


def assign_stable_ids(annotations, detector_name: str) -> None:
    """Number duplicates within each event and semantic finding category."""
    ordinals: dict[tuple, int] = {}
    for ann in annotations:
        metadata = ann.metadata if isinstance(ann.metadata, dict) else {}
        seq = metadata.get("seq")
        seq = seq if type(seq) is int else None
        kind = getattr(ann.kind, "value", str(ann.kind))
        subcategory = ann.subcategory or "annotation"
        key = (seq, subcategory, kind)
        ordinal = ordinals.get(key, 0)
        ordinals[key] = ordinal + 1
        metadata["stable_id"] = stable_id(detector_name, subcategory, kind,
                                          seq, ordinal)
        ann.metadata = metadata
