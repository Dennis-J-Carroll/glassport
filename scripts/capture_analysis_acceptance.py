#!/usr/bin/env python3
"""Freeze actual acceptance-matrix wire captures for the annotation golden test.

Run from an unchanged-main checkout (before detector optimization):
PYTHONPATH=src:. python scripts/capture_analysis_acceptance.py \
    docs/acceptance.md /path/to/analysis-acceptance-wire.json

Every published row runs its real fixture; capture occurs before its temporary
directory is cleaned. The output retains wire entries verbatim. Re-running
regenerates timestamps and epochs, so regenerate the golden snapshot with it.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import unittest
from unittest import mock

from glassport import bundle
from tests.acceptance_matrix import published_rows


def capture(source: Path, destination: Path) -> int:
    rows = published_rows(source)
    original = bundle.build_bundle
    out = {}
    for name, spec in rows.items():
        test_id = spec["command"].split()[-1]
        captures = []

        def record(wire_paths, *args, **kwargs):
            manifest = original(wire_paths, *args, **kwargs)
            captures.append([Path(path).read_text().splitlines() for path in wire_paths])
            return manifest

        stream = io.StringIO()
        with mock.patch.object(bundle, "build_bundle", side_effect=record):
            result = unittest.TextTestRunner(stream=stream, verbosity=0).run(
                unittest.defaultTestLoader.loadTestsFromName(test_id))
        if not result.wasSuccessful() or not captures:
            raise RuntimeError(f"{name}: {stream.getvalue()}")
        out[name] = captures[-1]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(out, sort_keys=True, indent=2,
                                      ensure_ascii=True) + "\n")
    return len(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("acceptance_doc", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(f"captured {capture(args.acceptance_doc, args.output)} acceptance rows")


if __name__ == "__main__":
    main()
