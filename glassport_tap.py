#!/usr/bin/env python3
"""
Back-compat launcher for the Glassport tap.

The implementation lives in src/glassport/tap.py; this shim exists so
MCP configs that point at /path/to/glassport_tap.py keep working after
the move to a proper package layout, and so a bare git clone stays
runnable without pip install:

    {
      "mcpServers": {
        "exa": {
          "command": "python3",
          "args": ["/path/to/glassport_tap.py", "--", "npx", "exa-mcp-server"]
        }
      }
    }

Installed users get the same thing as a console script:

    pip install glassport
    glassport -- npx exa-mcp-server
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from glassport.tap import cli

if __name__ == "__main__":
    cli()
