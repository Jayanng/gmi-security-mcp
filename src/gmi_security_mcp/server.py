"""gmi-security-mcp: stdio MCP server for security triage on GMI Inference.

Phase 1 tools:
  triage_semgrep_finding - triage one finding with GMI, validated output
  estimate_cost          - cost estimate with no API call, no spend

Rules enforced here, from the build plan:
- No model is pre-selected. The caller must name the model.
- Estimate before every call. Refuse before any API call when the
  safe upper-bound estimate exceeds the spend cap (default $1.00,
  never above $5.00).
- Block unpriced models. Refuse with a clear error, do not invent a price.
- No POST retry. One retry on timeout only, inside gmi.chat.
- GMI key from GMI_API_KEY only. Never logged, never returned.
- Unparsed is no verdict, never clean. A timeout is the same.
- Two-stage: escalate to Stage 2 only when two_stage is true and
  Stage 1 confidence is below the threshold, or Stage 1 is unparsed,
  or Stage 1 errored. When Stage 2 fails, keep the Stage 1 verdict
  and flag escalation_failed.
"""

import argparse
import json
import sys

from mcp.server import MCPServer

from . import __version__
from . import cost as cost_mod
from . import gmi as gmi_mod
from . import prompts as prompts_mod
from . import redact as redact_mod
from . import validate as validate_mod

MAX_CODE_CHARS = 40000
ALLOWED_MAX_TOKENS = (800, 1200, 2500)
DEFAULT_THRESHOLD = 0.8

mcp = MCPServer(
    "gmi-security-mcp",
    instructions=(
        "Security triage tools backed by GMI Inference. "
        "Triage one semgrep finding, or estimate the cost of a run "
        "before spending anything. No model is pre-selected."
    ),
)


def _error_result(message, **extra):
    result = {
        "verdict": None,
        "severity": "low",
        "confidence": None,
        "reason": None,
        "fix": None,
        "line": None,
        "check": None,
        "model": None,
        "stage": None,
        "stage_used": None,
        "escalated": False,
        "escalation_failed": False,
        "latency_seconds": None,
        "usage": {},
        "cost_usd": None,
        "estimate_usd": None,
        "typical_usd": None,
        "max_usd": None,
        "unparsed": False,
        "error": message,
        "redacted": False,
        "redaction_count": 0,
    }
    result.update(extra)
    return result


def _call_stage(model, combined_text, max_tokens, chat_fn):
    system = prompts_mod.system_content(prompts_mod.TRIAGE_PROMPT)
    user = prompts_mod.wrap_user_text(combined_text)
    reply = chat_fn(
        model=model,
        system_content=system,
        user_content=user,
        max_tokens=max_tokens,
    )
    if reply.get("error"):
        return {
            "parsed": None,
            "unparsed": False,
            "error": reply["error"],
            "latency_seconds": reply.get("latency_seconds"),
            "usage": reply.get("usage", {}),
            "retried": reply.get("retried", False),
            "timeout": reply.get("timeout", False),
        }
    parsed = validate_mod.parse_triage(reply.get("content") or "")
    return {
        "parsed": parsed,
        "unparsed": parsed is None,
        "error": None,
        "latency_seconds": reply.get("latency_seconds"),
        "usage": reply.get("usage", {}),
        "retried": reply.get("retried", False),
        "timeout": reply.get("timeout", False),
    }


def triage_impl(
    finding,
    code,
    file=None,
    line=None,
    check=None,
    stage1_model=None,
    stage2_model=None,
    two_stage=False,
    threshold=DEFAULT_THRESHOLD,
    max_tokens=2500,
    spend_cap_usd=cost_mod.DEFAULT_SPEND_CAP_USD,
    chat_fn=None,
    pricing=None,
):
    """Core triage logic. chat_fn defaults to the real GMI client.

    Returns a dict with a validated verdict, or verdict None with an
    error or unparsed flag. Never invents a verdict.
    """
    chat_fn = chat_fn or gmi_mod.chat
    if not finding or not str(finding).strip():
        return _error_result("finding is required and must not be empty")
    if code is None:
        return _error_result("code is required and must not be empty")
    if len(str(code)) > MAX_CODE_CHARS:
        return _error_result(
            "code is %d characters, over the %d character cap"
            % (len(str(code)), MAX_CODE_CHARS)
        )
    if not stage1_model or not str(stage1_model).strip():
        return _error_result(
            "stage1_model is required. No model is pre-selected, "
            "name the model to run."
        )
    if two_stage and (not stage2_model or not str(stage2_model).strip()):
        return _error_result(
            "two_stage is true but stage2_model is missing. "
            "Name Stage 2 or set two_stage to false."
        )
    if max_tokens not in ALLOWED_MAX_TOKENS:
        return _error_result(
            "max_tokens must be one of 800, 1200, 2500, got %r" % (max_tokens,)
        )
    try:
        threshold = float(threshold)
    except (TypeError, ValueError):
        return _error_result("threshold must be a number between 0 and 1")
    if not 0 <= threshold <= 1:
        return _error_result("threshold must be between 0 and 1")
    try:
        spend_cap_usd = float(spend_cap_usd)
    except (TypeError, ValueError):
        return _error_result("spend_cap_usd must be a number")
    if spend_cap_usd <= 0 or spend_cap_usd > cost_mod.MAX_SPEND_CAP_USD:
        return _error_result(
            "spend_cap_usd must be above 0 and at most $%.2f"
            % cost_mod.MAX_SPEND_CAP_USD
        )

    prices = pricing if pricing is not None else cost_mod.load_pricing()
    combined = str(finding).strip()
    code_text = str(code).strip()
    if code_text and code_text not in combined:
        combined = combined + "\n\nCode:\n" + code_text

    redacted_text, redaction_count, _hits = redact_mod.redact(combined)

    estimate = cost_mod.estimate_cost(
        stage1_model, len(redacted_text), max_tokens, 1, pricing=prices
    )
    if not estimate["priced"]:
        return _error_result(
            "Model %s has no flat per-token pricing, so its cost cannot "
            "be estimated. Pick a priced model instead." % stage1_model,
            redacted=redaction_count > 0,
            redaction_count=redaction_count,
            estimate_usd=None,
        )
    if estimate["max_usd"] is not None and estimate["max_usd"] > spend_cap_usd:
        return _error_result(
            "Estimated maximum cost $%.6f exceeds the spend cap $%.2f. "
            "Refusing to run. Lower max_tokens or raise the cap."
            % (estimate["max_usd"], spend_cap_usd),
            redacted=redaction_count > 0,
            redaction_count=redaction_count,
            estimate_usd=estimate["typical_usd"],
            typical_usd=estimate["typical_usd"],
            max_usd=estimate["max_usd"],
        )
    if gmi_mod.get_api_key() is None:
        return _error_result(
            "GMI_API_KEY is not set. Set it in the environment before "
            "running a triage. The key is never read from a file.",
            redacted=redaction_count > 0,
            redaction_count=redaction_count,
            estimate_usd=estimate["typical_usd"],
            typical_usd=estimate["typical_usd"],
            max_usd=estimate["max_usd"],
        )
    if two_stage and stage2_model:
        estimate2 = cost_mod.estimate_cost(
            stage2_model, len(redacted_text), max_tokens, 1, pricing=prices
        )
        if not estimate2["priced"]:
            return _error_result(
                "Stage 2 model %s has no flat per-token pricing, so its "
                "cost cannot be estimated. Pick a priced model instead."
                % stage2_model,
                redacted=redaction_count > 0,
                redaction_count=redaction_count,
                estimate_usd=estimate["typical_usd"],
            )

    norm_line = validate_mod.norm_line(line)
    norm_check = validate_mod.norm_check(check) if check else None

    stage1 = _call_stage(stage1_model, redacted_text, max_tokens, chat_fn)
    total_cost = cost_mod.cost_from_usage(
        stage1["usage"], stage1_model, pricing=prices
    )
    total_latency = stage1["latency_seconds"] or 0

    needs_stage2 = False
    if two_stage and stage2_model:
        if stage1["error"] is not None:
            needs_stage2 = True
        elif stage1["unparsed"]:
            needs_stage2 = True
        elif stage1["parsed"] is not None:
            confidence = stage1["parsed"].get("confidence")
            if confidence is None or confidence < threshold:
                needs_stage2 = True

    if not needs_stage2:
        if stage1["error"] is not None:
            return _error_result(
                "Stage 1 call failed: %s. No verdict. This finding is "
                "NOT clean." % stage1["error"],
                model=stage1_model,
                stage="stage1",
                stage_used="stage1",
                latency_seconds=total_latency,
                usage=stage1["usage"],
                cost_usd=total_cost if not stage1["timeout"] else None,
                estimate_usd=estimate["typical_usd"],
                typical_usd=estimate["typical_usd"],
                max_usd=estimate["max_usd"],
                redacted=redaction_count > 0,
                redaction_count=redaction_count,
                line=norm_line,
                check=norm_check,
            )
        if stage1["parsed"] is None:
            return _error_result(
                "Unparsed, no verdict, this finding is NOT clean. "
                "The model reply contained no valid JSON verdict.",
                model=stage1_model,
                stage="stage1",
                stage_used="stage1",
                unparsed=True,
                latency_seconds=total_latency,
                usage=stage1["usage"],
                cost_usd=total_cost,
                estimate_usd=estimate["typical_usd"],
                typical_usd=estimate["typical_usd"],
                max_usd=estimate["max_usd"],
                redacted=redaction_count > 0,
                redaction_count=redaction_count,
                line=norm_line,
                check=norm_check,
            )
        parsed = stage1["parsed"]
        return {
            "verdict": parsed["verdict"],
            "severity": parsed["severity"],
            "confidence": parsed["confidence"],
            "reason": parsed["reason"],
            "fix": parsed["fix"],
            "line": norm_line if norm_line is not None else parsed.get("line"),
            "check": norm_check if norm_check else parsed.get("check"),
            "model": stage1_model,
            "stage": "stage1",
            "stage_used": "stage1",
            "escalated": False,
            "escalation_failed": False,
            "latency_seconds": total_latency,
            "usage": stage1["usage"],
            "cost_usd": total_cost,
            "estimate_usd": estimate["typical_usd"],
            "typical_usd": estimate["typical_usd"],
            "max_usd": estimate["max_usd"],
            "unparsed": False,
            "error": None,
            "redacted": redaction_count > 0,
            "redaction_count": redaction_count,
        }

    stage2 = _call_stage(stage2_model, redacted_text, max_tokens, chat_fn)
    total_cost += cost_mod.cost_from_usage(
        stage2["usage"], stage2_model, pricing=prices
    )
    total_latency += stage2["latency_seconds"] or 0
    if stage2["parsed"] is not None:
        parsed = stage2["parsed"]
        return {
            "verdict": parsed["verdict"],
            "severity": parsed["severity"],
            "confidence": parsed["confidence"],
            "reason": parsed["reason"],
            "fix": parsed["fix"],
            "line": norm_line if norm_line is not None else parsed.get("line"),
            "check": norm_check if norm_check else parsed.get("check"),
            "model": stage2_model,
            "stage": "stage2",
            "stage_used": "stage2",
            "escalated": True,
            "escalation_failed": False,
            "latency_seconds": total_latency,
            "usage": stage2["usage"],
            "cost_usd": total_cost,
            "estimate_usd": estimate["typical_usd"],
            "typical_usd": estimate["typical_usd"],
            "max_usd": estimate["max_usd"],
            "unparsed": False,
            "error": None,
            "redacted": redaction_count > 0,
            "redaction_count": redaction_count,
        }
    if stage1["parsed"] is not None:
        parsed = stage1["parsed"]
        return {
            "verdict": parsed["verdict"],
            "severity": parsed["severity"],
            "confidence": parsed["confidence"],
            "reason": parsed["reason"],
            "fix": parsed["fix"],
            "line": norm_line if norm_line is not None else parsed.get("line"),
            "check": norm_check if norm_check else parsed.get("check"),
            "model": stage1_model,
            "stage": "stage1",
            "stage_used": "stage1",
            "escalated": True,
            "escalation_failed": True,
            "latency_seconds": total_latency,
            "usage": stage1["usage"],
            "cost_usd": total_cost,
            "estimate_usd": estimate["typical_usd"],
            "typical_usd": estimate["typical_usd"],
            "max_usd": estimate["max_usd"],
            "unparsed": False,
            "error": (
                "Stage 2 failed (%s), keeping the Stage 1 verdict. "
                "This is not a two-stage verified result."
                % (stage2["error"] or "unparsed reply",)
            ),
            "redacted": redaction_count > 0,
            "redaction_count": redaction_count,
        }
    return _error_result(
        "Unparsed, no verdict, this finding is NOT clean. "
        "Stage 1 and Stage 2 both returned no valid JSON verdict.",
        model=stage1_model,
        stage="stage2",
        stage_used="stage2",
        escalated=True,
        escalation_failed=True,
        unparsed=True,
        latency_seconds=total_latency,
        usage=stage2["usage"],
        cost_usd=total_cost,
        estimate_usd=estimate["typical_usd"],
        typical_usd=estimate["typical_usd"],
        max_usd=estimate["max_usd"],
        redacted=redaction_count > 0,
        redaction_count=redaction_count,
        line=norm_line,
        check=norm_check,
    )


@mcp.tool()
def triage_semgrep_finding(
    finding: str,
    code: str,
    file: str | None = None,
    line: int | None = None,
    check: str | None = None,
    stage1_model: str | None = None,
    stage2_model: str | None = None,
    two_stage: bool = False,
    threshold: float = 0.8,
    max_tokens: int = 2500,
    spend_cap_usd: float = 1.00,
) -> str:
    """Triage one semgrep or scanner finding with GMI Inference.

    Returns one validated finding as JSON: verdict, severity,
    confidence, reason, fix, stage used, latency, tokens, cost, and
    the estimate made before the call. An unparsed reply returns
    verdict null and unparsed true. It never returns clean.
    """
    result = triage_impl(
        finding=finding,
        code=code,
        file=file,
        line=line,
        check=check,
        stage1_model=stage1_model,
        stage2_model=stage2_model,
        two_stage=two_stage,
        threshold=threshold,
        max_tokens=max_tokens,
        spend_cap_usd=spend_cap_usd,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def estimate_cost(
    model: str,
    text_length_chars: int,
    max_tokens: int = 2500,
    n_findings: int = 1,
) -> str:
    """Estimate the cost of a run with no API call and no spend.

    Returns typical and maximum cost in USD, the prompt token
    estimate, and the per-token pricing used. An unpriced model
    returns priced false and null costs.
    """
    if max_tokens not in ALLOWED_MAX_TOKENS:
        return json.dumps(
            {
                "model": model,
                "priced": False,
                "typical_usd": None,
                "max_usd": None,
                "error": "max_tokens must be one of 800, 1200, 2500",
            },
            indent=2,
        )
    result = cost_mod.estimate_cost(model, text_length_chars, max_tokens, n_findings)
    return json.dumps(result, indent=2)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="gmi-security-mcp",
        description="Security MCP server for coding agents, backed by GMI Inference.",
    )
    parser.add_argument("--version", action="store_true", help="Print the version and exit")
    parser.add_argument(
        "--list-tools", action="store_true", help="List the tool names and exit"
    )
    args = parser.parse_args(argv)
    if args.version:
        print("gmi-security-mcp %s" % __version__)
        return 0
    if args.list_tools:
        print("triage_semgrep_finding")
        print("estimate_cost")
        return 0
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
