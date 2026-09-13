"""Known-answer tests for the stabilization findings ledger."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ledger import load_ledger, upsert_finding, validate_finding


def _finding(fid: str = "F-001", **over) -> dict:
    base = {
        "id": fid,
        "title": "example",
        "status": "provisional",
        "severity": "P2",
        "metrics": {"count": 1},
        "provenance": "dogfood/stabilization/baseline-0610.json",
        "depends_on": [],
        "explanation": "eli5: something happened; why-it-matters: it matters.",
    }
    base.update(over)
    return base


class TestLedger(unittest.TestCase):
    def test_upsert_creates_and_is_idempotent(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "ledger.json"
            upsert_finding(path, _finding())
            upsert_finding(path, _finding())  # same id twice
            data = load_ledger(path)
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"]["F-001"]["severity"], "P2")

    def test_upsert_updates_in_place(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "ledger.json"
            upsert_finding(path, _finding())
            upsert_finding(path, _finding(severity="P1"))
            data = load_ledger(path)
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["findings"]["F-001"]["severity"], "P1")

    def test_missing_field_rejected_before_write(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "ledger.json"
            bad = _finding()
            del bad["explanation"]
            with self.assertRaises(ValueError):
                upsert_finding(path, bad)
            self.assertFalse(path.exists())  # nothing written

    def test_invalid_status_and_severity_rejected(self):
        with self.assertRaises(ValueError):
            validate_finding(_finding(status="done"))
        with self.assertRaises(ValueError):
            validate_finding(_finding(severity="high"))

    def test_corrupt_ledger_raises_not_silently_resets(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "ledger.json"
            path.write_text('{"findings": "not-a-map"}')
            with self.assertRaises(ValueError):
                load_ledger(path)

    def test_atomic_no_tmp_left_behind(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "ledger.json"
            upsert_finding(path, _finding())
            leftovers = [p for p in Path(td).iterdir() if p.suffix == ".tmp"]
            self.assertEqual(leftovers, [])
            # file is valid json on disk
            json.loads(path.read_text())


if __name__ == "__main__":
    unittest.main()
