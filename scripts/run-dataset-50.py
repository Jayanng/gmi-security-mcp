#!/usr/bin/env python3
"""Live test: run the 50-finding dataset through the real MCP server.

Calls triage_semgrep_finding over stdio with the real GMI API, one
call per finding, model google/gemini-3.5-flash-lite unless --model
is given. Estimates the total cost first with estimate_cost and
refuses to run when the estimate exceeds --cap-usd (default $1.00).
Records accuracy, precision, recall, unparsed count, and cost.

Needs GMI_API_KEY in the environment. Writes a JSON results log to
--out when given. The key is never written to the log: the log is
checked for the key value before it is written.

Usage:
  GMI_API_KEY=... python3 scripts/run-dataset-50.py [--out FILE]
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

DEFAULT_MODEL = "google/gemini-3.5-flash-lite"

CATEGORY_TO_CHECK = {
    "sql-injection": "SQL injection",
    "xss": "Cross-site scripting (XSS)",
    "ssrf": "Server-side request forgery (SSRF)",
    "hardcoded-secret": "Hardcoded secrets",
    "weak-crypto": "Weak cryptography",
    "jwt": "Authentication and session flaws",
    "auth-bypass": "Authentication and session flaws",
    "path-traversal": "Path traversal",
}


async def main():
    parser = argparse.ArgumentParser(description="Run the 50-finding dataset live.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--cap-usd", type=float, default=1.00)
    parser.add_argument("--out", default=None)
    parser.add_argument("--max-tokens", type=int, default=2500)
    args = parser.parse_args()

    key = os.environ.get("GMI_API_KEY", "").strip()
    if not key:
        print("ERROR: GMI_API_KEY is not set.", file=sys.stderr)
        return 2

    data = json.loads((ROOT / "dataset.json").read_text())
    findings = data["findings"]

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "gmi_security_mcp.server"],
        env=env,
        cwd=str(ROOT),
    )
    results = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("tools:", ", ".join(names))
            if "triage_semgrep_finding" not in names:
                print("ERROR: triage_semgrep_finding missing.", file=sys.stderr)
                return 2

            total_length = sum(
                len(f["title"]) + len(f["code"]) + len(f["explanation"])
                for f in findings
            )
            est_raw = await session.call_tool(
                "estimate_cost",
                {
                    "model": args.model,
                    "text_length_chars": total_length,
                    "max_tokens": args.max_tokens,
                    "n_findings": len(findings),
                },
            )
            est = json.loads(est_raw.content[0].text)
            print(
                "estimate for %d findings: typical $%.6f, max $%.6f"
                % (len(findings), est["typical_usd"], est["max_usd"])
            )
            if est["max_usd"] is None or est["max_usd"] > args.cap_usd:
                print(
                    "ERROR: estimated max $%s exceeds cap $%.2f, refusing."
                    % (est["max_usd"], args.cap_usd),
                    file=sys.stderr,
                )
                return 3

            for finding in findings:
                call = await session.call_tool(
                    "triage_semgrep_finding",
                    {
                        "finding": "%s. %s"
                        % (finding["title"], finding["explanation"]),
                        "code": finding["code"],
                        "check": CATEGORY_TO_CHECK.get(finding["category"]),
                        "stage1_model": args.model,
                        "max_tokens": args.max_tokens,
                        "spend_cap_usd": args.cap_usd,
                    },
                )
                result = json.loads(call.content[0].text)
                passed = result.get("verdict") == finding["expected_label"]
                results.append(
                    {
                        "id": finding["id"],
                        "category": finding["category"],
                        "expected_label": finding["expected_label"],
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
                    "%s %-20s expected %-14s got %-14s %s $%.6f"
                    % (
                        finding["id"],
                        finding["category"],
                        finding["expected_label"],
                        str(result.get("verdict")),
                        "PASS" if passed else "FAIL",
                        result.get("cost_usd") or 0,
                    )
                )

    passed_count = sum(1 for r in results if r["passed"])
    total_cost = sum(r["cost_usd"] or 0 for r in results)
    unparsed = sum(1 for r in results if r["unparsed"])
    tp = sum(
        1
        for r in results
        if r["expected_label"] == "real" and r["verdict"] == "real"
    )
    fp = sum(
        1
        for r in results
        if r["expected_label"] == "false_positive" and r["verdict"] == "real"
    )
    fn = sum(
        1
        for r in results
        if r["expected_label"] == "real" and r["verdict"] != "real"
    )
    tn = sum(
        1
        for r in results
        if r["expected_label"] == "false_positive"
        and r["verdict"] == "false_positive"
    )
    accuracy = passed_count / len(results) if results else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    print(
        "passed %d/%d, accuracy %.3f, precision %.3f, recall %.3f, "
        "unparsed %d, total cost $%.6f"
        % (passed_count, len(results), accuracy, precision, recall,
           unparsed, total_cost)
    )
    log = {
        "model": args.model,
        "max_tokens": args.max_tokens,
        "passed": passed_count,
        "total": len(results),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "unparsed": unparsed,
        "total_cost_usd": total_cost,
        "results": results,
    }
    if args.out:
        text = json.dumps(log, indent=2)
        if key in text:
            print("ERROR: key found in log, refusing to write.", file=sys.stderr)
            return 4
        Path(args.out).write_text(text)
        print("log written to %s" % args.out)
    return 0 if passed_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
