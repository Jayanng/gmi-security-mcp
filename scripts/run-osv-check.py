#!/usr/bin/env python3
"""Live test: check_osv_advisory and explain_cve via the MCP server.

Calls both Phase 3 tools over stdio. check_osv_advisory needs
osv-scanner on PATH; explain_cve fetches the advisory from the
OSV API and, when --model is given, asks GMI for one paragraph
from the advisory only.

Needs GMI_API_KEY only when --model is given. Writes a JSON log
to --out when given; the log is checked for the key value before
it is written.

Usage:
  python3 scripts/run-osv-check.py --lockfile /path/package-lock.json
  python3 scripts/run-osv-check.py --explain CVE-2021-44228 [--model google/gemini-3.5-flash-lite]
  python3 scripts/run-osv-check.py --lockfile ... --explain CVE-2021-44228 --out results.json
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402


def _tool_json(text):
    """Parse a tool result. A non-JSON result is a server error, not a
    verdict: report it instead of crashing on json.loads."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print("ERROR: tool returned non-JSON result: %s" % text[:500],
              file=sys.stderr)
        raise SystemExit(4)


async def main():
    parser = argparse.ArgumentParser(description="Run OSV tools live.")
    parser.add_argument("--lockfile", default=None)
    parser.add_argument("--explain", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    if not args.lockfile and not args.explain:
        print("ERROR: give --lockfile, --explain, or both.", file=sys.stderr)
        return 2

    key = os.environ.get("GMI_API_KEY", "").strip()
    if args.model and not key:
        print("ERROR: GMI_API_KEY is not set.", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gmi_security_mcp.server"],
        env=env,
        cwd=str(ROOT),
    )
    log = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("tools:", ", ".join(names))
            if args.lockfile:
                if "check_osv_advisory" not in names:
                    print("ERROR: check_osv_advisory missing.", file=sys.stderr)
                    return 2
                call = await session.call_tool(
                    "check_osv_advisory",
                    {"lockfile_path": args.lockfile},
                )
                result = _tool_json(call.content[0].text)
                log["check_osv_advisory"] = result
                print(
                    "lockfile %s: ecosystem %s, parsed %d packages, "
                    "scanned %d, vulnerable %d, unresolved %d, error=%s" % (
                        result.get("lockfile_path"),
                        result.get("ecosystem"),
                        result.get("packages_parsed", 0),
                        result.get("packages_scanned", 0),
                        result.get("vulnerable_packages", 0),
                        len(result.get("unresolved_packages") or []),
                        result.get("error"),
                    )
                )
                for advisory in result.get("advisories") or []:
                    print(
                        "  %s %s %s fixed=%s cvss=%s: %s" % (
                            advisory.get("package"),
                            advisory.get("installed_version"),
                            advisory.get("id"),
                            advisory.get("fixed_version"),
                            advisory.get("cvss_score"),
                            advisory.get("summary"),
                        )
                    )
            if args.explain:
                if "explain_cve" not in names:
                    print("ERROR: explain_cve missing.", file=sys.stderr)
                    return 2
                call = await session.call_tool(
                    "explain_cve",
                    {
                        "advisory_id": args.explain,
                        "stage1_model": args.model,
                    },
                )
                result = _tool_json(call.content[0].text)
                log["explain_cve"] = result
                print("explain %s: found=%s" % (args.explain, result.get("found")))
                if result.get("found"):
                    advisory = result["advisory"]
                    print("  summary: %s" % advisory.get("summary"))
                    print("  cvss: %s" % advisory.get("cvss_score"))
                    print("  fixed: %s" % advisory.get("fixed_versions"))
                    print("  explanation (%s): %s" % (
                        result.get("explanation_source"),
                        result.get("explanation"),
                    ))
                    print("  citations: %s" % result.get("citations"))
                    print("  cost: $%s" % result.get("cost_usd"))
                if result.get("error"):
                    print("  error: %s" % result["error"])
    if args.out:
        text = json.dumps(log, indent=2)
        if key and key in text:
            print("ERROR: key found in log, refusing to write.", file=sys.stderr)
            return 4
        Path(args.out).write_text(text)
        print("log written to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
