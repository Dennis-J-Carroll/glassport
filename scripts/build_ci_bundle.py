#!/usr/bin/env python3
"""Produce fresh strict-gate bundle from the real loopback test upstream."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassport.bundle import build_bundle, verify_bundle
from tests.test_http_gate import GateCase


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    fixture = GateCase()
    fixture.setUp()
    try:
        fixture.proxy(strict=True)
        fixture.handshake(declare=False)
        fixture.call("search", rid=4)  # strict evidence-gap block
        fixture.post({"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
                     session="sess-1")
        fixture.call("ghost", rid=6)   # proved policy block
        fixture.call("search", rid=7)  # complete request sent upstream
        fixture.quiesce()
        fixture.observer.close()
        fixture.journal.close()
        manifest = build_bundle(sorted((fixture.root / "wire").glob("*.jsonl")),
                                fixture.root / "decisions", None, args.out)
        levels = {delivery["evidence_level"] for delivery in manifest["delivery"]}
        required = {"blocked_policy", "blocked_evidence_gap", "forwarded"}
        if not required <= levels:
            raise RuntimeError(f"CI fixture missing delivery levels: {required - levels}")
        result = verify_bundle(args.out)
        if (result["analysis_reproduced"]["status"] != "equivalent"
                or result["delivery_evidence_present"]["status"] != "present"
                or result["integrity"]["status"] != "passed"):
            raise RuntimeError(f"CI bundle did not verify: {result}")
        print(args.out)
        return 0
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    raise SystemExit(main())
