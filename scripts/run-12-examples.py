#!/usr/bin/env python3
"""Live test: run the 12 examples through the real MCP server.

Thin wrapper around gmi_security_mcp.mcp_test, which is also
installed as the `mcp-test` console script. See that module for
the full docstring.

Usage:
  GMI_API_KEY=... python3 scripts/run-12-examples.py [--out log.json]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp.mcp_test import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
