#!/usr/bin/env python3
"""Call one MCP tool and print the raw JSON result.

A small debugging helper for the tutorial and for manual checks.
It is not part of the installed package: run it from a checkout
with the venv Python that has the MCP SDK installed.

Needs GMI_API_KEY in the environment for tools that call GMI.
estimate_cost needs no key.

Usage:
  python3 scripts/call-tool.py estimate_cost '{"model": "google/gemini-3.5-flash-lite", "text_length_chars": 1000, "max_tokens": 2500, "n_findings": 1}'
  python3 scripts/call-tool.py triage_semgrep_finding '{"finding": "...", "code": "...", "stage1_model": "google/gemini-3.5-flash-lite"}'
"""

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402


async def call(tool, args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gmi_security_mcp.server"],
        env=env,
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            print(result.content[0].text)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    tool, args = argv[0], json.loads(argv[1])
    asyncio.run(call(tool, args))
    return 0


if __name__ == "__main__":
    sys.exit(main())
