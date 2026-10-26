"""Shared checks for the published Phase 4 acceptance matrix."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from glassport import __version__, bundle


_HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{24,64}(?![0-9a-f])")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)")


def normalized_manifest(manifest: dict) -> dict:
    """Remove capture entropy, retaining decisions, counts, and structure.

    Replaces UTC timestamps, random epoch identifiers, derived digests, and
    the glassport release version.
    Digest bytes depend on timestamped wire and journal records, so they cannot
    survive timestamp normalization. Repeated values keep the same token.
    """
    result = deepcopy(manifest)
    epochs = {item["epoch"]: f"epoch-{index:04d}"
              for index, item in enumerate(result["evidence"]["epochs"], 1)
              if item["epoch"] != "stdio"}
    for profile in result.get("profile", {}).get("journal_profiles", {}).values():
        if isinstance(profile, dict) and "n" in profile:
            profile["n"] = 0
    result["delivery"].sort(key=lambda row: (
        epochs.get(row.get("epoch"), row.get("epoch", "")),
        row.get("wire_seq") if isinstance(row.get("wire_seq"), int) else -1,
        str(row.get("code", ""))))
    for index, row in enumerate(result["delivery"], 1):
        # Journal append order can race a client response; wire linkage does not.
        row["intent_n"] = 2 * index - 1
        row["delivery_n"] = 2 * index
    digests: dict[str, str] = {}

    def string(value: str) -> str:
        if value == __version__:
            # A release bump must not invalidate every published fingerprint.
            return "0.0.0"
        for original, replacement in epochs.items():
            value = value.replace(original, replacement)
        value = _TIME.sub("2000-01-01T00:00:00+00:00", value)

        def digest(match):
            original = match.group()
            if original not in digests:
                digests[original] = f"digest-{len(digests) + 1:04d}"
            return digests[original]

        value = _HEX.sub(digest, value)
        return re.sub(r"(digest-\d{4})-[0-9a-f]{8}", r"\1-collision", value)

    def walk(value):
        if isinstance(value, dict):
            return {string(key): (0 if key == "port" and value.get("host") == "127.0.0.1"
                                  else walk(child)) for key, child in value.items()}
        if isinstance(value, list):
            return [walk(child) for child in value]
        return string(value) if isinstance(value, str) else value

    return walk(result)


def manifest_hash(manifest: dict) -> str:
    return hashlib.sha256(bundle.canonical_bytes(normalized_manifest(manifest))).hexdigest()


def published_rows(path: Path) -> dict[str, dict]:
    """Read machine-readable table cells from docs/acceptance.md."""
    rows = {}
    for line in path.read_text().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [part.strip() for part in line.strip("|").split("|")]
        if len(cells) != 4:
            continue
        name = cells[0].strip("`")
        if name.startswith("acceptance."):
            rows[name] = {"command": cells[1].strip("`"),
                          "verdict": cells[2].strip("`"),
                          "hash": cells[3].strip("`")}
    return rows
