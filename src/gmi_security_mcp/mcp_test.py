#!/usr/bin/env python3
"""mcp-test: run the 12 examples through the live MCP server.

Calls triage_semgrep_finding over stdio with the real GMI API, one
call per example, model google/gemini-3.5-flash-lite unless --model
is given. Estimates the total cost first with estimate_cost and
refuses to run when the estimate exceeds --cap-usd (default $1.00).

Needs GMI_API_KEY in the environment. Writes a JSON results log to
--out when given, and prints a per-example pass/fail table plus the
total spend. The key is never written to the log: the log is checked
for the key value before it is written.

Installed as the `mcp-test` console script. Also runnable from a
checkout as `python3 scripts/run-12-examples.py`, which is a thin
wrapper around this module.

Usage:
  mcp-test [--model google/gemini-3.5-flash-lite] [--cap-usd 1.00]
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

DEFAULT_MODEL = "google/gemini-3.5-flash-lite"

def _tool_json(text):
    """Parse a tool result. A non-JSON result is a server error, not a
    verdict: report it instead of crashing on json.loads."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print("ERROR: tool returned non-JSON result: %s" % text[:500],
              file=sys.stderr)
        raise SystemExit(4)



def _repo_root():
    """Repo root in a checkout, else the current directory."""
    here = Path(__file__).resolve()
    candidate = here.parents[2]
    if (candidate / "examples" / "examples-12.json").is_file():
        return candidate
    return Path.cwd()


def _examples_path():
    """examples-12.json from the checkout, else from package data."""
    root = _repo_root()
    checkout = root / "examples" / "examples-12.json"
    if checkout.is_file():
        return checkout
    packaged = Path(__file__).resolve().parent / "examples-12.json"
    return packaged


async def run_examples(model=DEFAULT_MODEL, cap_usd=1.00, max_tokens=2500,
                       out=None):
    """Run the 12 examples live. Returns (exit_code, log_dict)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    key = os.environ.get("GMI_API_KEY", "").strip()
    if not key:
        print("ERROR: GMI_API_KEY is not set.", file=sys.stderr)
        return 2, None

    data = json.loads(_examples_path().read_text())
    examples = data["examples"]

    env = dict(os.environ)
    root = _repo_root()
    src_dir = root / "src"
    if src_dir.is_dir():
        env["PYTHONPATH"] = str(src_dir) + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gmi_security_mcp.server"],
        env=env,
        cwd=str(root),
    )
    results = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("tools:", ", ".join(names))
            if "triage_semgrep_finding" not in names or "estimate_cost" not in names:
                print("ERROR: expected tools missing.", file=sys.stderr)
                return 2, None

            total_length = sum(len(e["finding"]) for e in examples)
            est_raw = await session.call_tool(
                "estimate_cost",
                {
                    "model": model,
                    "text_length_chars": total_length,
                    "max_tokens": max_tokens,
                    "n_findings": len(examples),
                },
            )
            est = _tool_json(est_raw.content[0].text)
            print(
                "estimate for %d examples: typical $%.6f, max $%.6f"
                % (len(examples), est["typical_usd"], est["max_usd"])
            )
            if est["max_usd"] is None or est["max_usd"] > cap_usd:
                print(
                    "ERROR: estimated max $%s exceeds cap $%.2f, refusing."
                    % (est["max_usd"], cap_usd),
                    file=sys.stderr,
                )
                return 3, None

            for example in examples:
                call = await session.call_tool(
                    "triage_semgrep_finding",
                    {
                        "finding": example["finding"],
                        "code": example["finding"],
                        "check": example["check"],
                        "stage1_model": model,
                        "max_tokens": max_tokens,
                        "spend_cap_usd": cap_usd,
                    },
                )
                result = _tool_json(call.content[0].text)
                passed = result.get("verdict") == example["expected_verdict"]
                results.append(
                    {
                        "id": example["id"],
                        "n": example["n"],
                        "title": example["title"],
                        "expected_verdict": example["expected_verdict"],
                        "verdict": result.get("verdict"),
                        "severity": result.get("severity"),
                        "confidence": result.get("confidence"),
                        "unparsed": result.get("unparsed"),
                        "error": result.get("error"),
                        "cost_usd": result.get("cost_usd"),
                        "latency_seconds": result.get("latency_seconds"),
                        "usage": result.get("usage"),
                        "passed": passed,
                    }
                )
                print(
                    "%2d %-10s expected %-14s got %-14s %s $%.6f"
                    % (
                        example["n"],
                        example["id"],
                        example["expected_verdict"],
                        str(result.get("verdict")),
                        "PASS" if passed else "FAIL",
                        result.get("cost_usd") or 0,
                    )
                )

    passed_count = sum(1 for r in results if r["passed"])
    total_cost = sum(r["cost_usd"] or 0 for r in results)
    unparsed = sum(1 for r in results if r["unparsed"])
    print(
        "passed %d/%d, unparsed %d, total cost $%.6f"
        % (passed_count, len(results), unparsed, total_cost)
    )
    log = {
        "model": model,
        "max_tokens": max_tokens,
        "passed": passed_count,
        "total": len(results),
        "unparsed": unparsed,
        "total_cost_usd": total_cost,
        "results": results,
    }
    if out:
        text = json.dumps(log, indent=2)
        if key in text:
            print("ERROR: key found in log, refusing to write.", file=sys.stderr)
            return 4, log
        Path(out).write_text(text)
        print("log written to %s" % out)
    return 0 if passed_count == len(results) else 1, log


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the 12 examples through the live MCP server.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--cap-usd", type=float, default=1.00)
    parser.add_argument("--out", default=None)
    parser.add_argument("--max-tokens", type=int, default=2500)
    args = parser.parse_args(argv)
    code, _log = asyncio.run(
        run_examples(args.model, args.cap_usd, args.max_tokens, args.out))
    return code


if __name__ == "__main__":
    sys.exit(main())
