"""Test package bootstrap.

Makes the test suite runnable straight from a clone — no install
required — by putting src/ on sys.path. A no-op when glassport is
already installed (e.g. ``pip install -e .`` in CI).
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
