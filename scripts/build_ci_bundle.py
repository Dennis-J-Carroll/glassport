#!/usr/bin/env python3
"""Produce a fresh HTTP or stdio gate bundle that must verify exactly zero."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from glassport.bundle import build_bundle, verify_bundle, verify_exit_code
from glassport.tap import Gate
from tests.test_http_gate import GateCase
from tests.test_stdio_journal import Capture


def build_stdio(out: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        capture = Capture(Path(tmp), Gate(strict=True))
        try:
            capture.declare()
            capture.call('ghost')
            capture.call(arguments={'q': 'sk-' + 'A' * 40}, rid=3)
            with patch.object(capture.gate, 'check_c2s', side_effect=RuntimeError('fixture')):
                capture.call(rid=4)
            capture.call(rid=5)
            if capture.upstream.getvalue().count(b'"tools/call"') != 1:
                raise RuntimeError('stdio CI blocks reached upstream')
        finally:
            capture.close()
        manifest = build_bundle([capture.path], None, None, out)
        codes = {row['code'] for row in manifest['delivery']}
        if not {'stdio_written', 'stdio_gate_blocked', 'stdio_gate_strict_blocked'} <= codes:
            raise RuntimeError('stdio CI delivery cases missing')
        result = verify_bundle(out)
        if verify_exit_code(result) != 0:
            raise RuntimeError(f'stdio CI bundle verify exit must be 0: {result}')
        print(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--transport", choices=("http", "stdio"), default="http")
    args = parser.parse_args()
    if args.transport == "stdio":
        build_stdio(args.out)
        return 0
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
        if verify_exit_code(result) != 0:
            raise RuntimeError(f"CI bundle verify exit must be 0: {result}")
        print(args.out)
        return 0
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    raise SystemExit(main())
