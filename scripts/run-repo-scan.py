#!/usr/bin/env python3
"""Live test: run repo_scan through the real MCP server.

Calls repo_scan over stdio with the real GMI API, Stage 1 and
Stage 2 as given. Prints the report totals, per-finding verdicts,
and the total spend. A dry run makes no GMI calls.

Needs GMI_API_KEY in the environment unless --dry-run is given.
Needs semgrep and osv-scanner on PATH for the local scanner runs.
Writes a JSON results log to --out when given; the log is checked
for the key value before it is written.

Usage:
  GMI_API_KEY=... python3 scripts/run-repo-scan.py --repo /path/to/repo
      [--stage1 google/gemini-3.5-flash-lite]
      [--stage2 Qwen/Qwen3.8-Flash] [--cap-usd 1.00]
      [--max-file-kb 40] [--dry-run] [--write-report report.md]
      [--out results.json]
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
    parser = argparse.ArgumentParser(description="Run repo_scan live.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--stage1", default="google/gemini-3.5-flash-lite")
    parser.add_argument("--stage2", default="Qwen/Qwen3.8-Flash")
    parser.add_argument("--cap-usd", type=float, default=1.00)
    parser.add_argument("--max-file-kb", type=int, default=40)
    parser.add_argument("--max-total-kb", type=int, default=200)
    parser.add_argument("--max-files", type=int, default=10)
    parser.add_argument("--semgrep-config", default=None,
                        help="semgrep config set, e.g. p/default; "
                        "default is the server default set")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--write-report", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    key = os.environ.get("GMI_API_KEY", "").strip()
    if not key and not args.dry_run:
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
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("tools:", ", ".join(names))
            if "repo_scan" not in names:
                print("ERROR: repo_scan tool missing.", file=sys.stderr)
                return 2
            call = await session.call_tool(
                "repo_scan",
                {
                    "repo_path": args.repo,
                    "stage1_model": args.stage1,
                    "stage2_model": args.stage2,
                    "spend_cap_usd": args.cap_usd,
                    "max_files": args.max_files,
                    "max_file_kb": args.max_file_kb,
                    "max_total_kb": args.max_total_kb,
                    "dry_run": args.dry_run,
                    "write_report": args.write_report,
                }
                | ({"semgrep_config": args.semgrep_config}
                   if args.semgrep_config else {}),
            )
            report = _tool_json(call.content[0].text)

    print("repo: %s" % report.get("repo_path"))
    print(
        "findings: total %d, triaged %d, real %d, false_positive %d, "
        "no_verdict %d" % (
            report.get("findings_total", 0),
            report.get("findings_triaged", 0),
            report.get("findings_real", 0),
            report.get("findings_false_positive", 0),
            report.get("findings_no_verdict", 0),
        )
    )
    print("skipped: %d" % len(report.get("skipped") or []))
    for item in report.get("skipped") or []:
        print("  skipped %s:%s - %s" % (
            item.get("file"), item.get("line"), item.get("reason")))
    for finding in report.get("findings") or []:
        print(
            "  %s:%s %-14s %-14s conf %s stage %s $%.6f" % (
                finding.get("file"),
                finding.get("line"),
                finding.get("check"),
                str(finding.get("verdict")),
                finding.get("confidence"),
                finding.get("stage_used"),
                finding.get("cost_usd") or 0,
            )
        )
    for section in (report.get("osv") or {}).get("lockfiles") or []:
        print(
            "osv %s: %d packages, %d vulnerable, error=%s" % (
                section.get("lockfile_path"),
                section.get("packages_scanned", 0),
                section.get("vulnerable_packages", 0),
                section.get("error"),
            )
        )
        for advisory in section.get("advisories") or []:
            print(
                "  osv %s %s %s fixed=%s cvss=%s" % (
                    advisory.get("package"),
                    advisory.get("installed_version"),
                    advisory.get("id"),
                    advisory.get("fixed_version"),
                    advisory.get("cvss_score"),
                )
            )
    print(
        "cost: actual $%.6f, estimate typical $%s, max $%s, "
        "stopped_early=%s (%s)" % (
            report.get("total_cost_usd") or 0,
            report.get("estimate_usd"),
            report.get("max_estimate_usd"),
            report.get("stopped_early"),
            report.get("stopped_reason"),
        )
    )
    if report.get("errors"):
        for error in report["errors"]:
            print("error: %s" % error)
    if args.out:
        text = json.dumps(report, indent=2)
        if key and key in text:
            print("ERROR: key found in log, refusing to write.", file=sys.stderr)
            return 4
        Path(args.out).write_text(text)
        print("log written to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
