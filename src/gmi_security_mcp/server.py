"""gmi-security-mcp: stdio MCP server for security triage on GMI Inference.

Phase 1 tools:
  triage_semgrep_finding - triage one finding with GMI, validated output
  estimate_cost          - cost estimate with no API call, no spend
Phase 2 tool:
  repo_scan              - semgrep a repo, two-stage triage, JSON+Markdown report
Phase 3 tools:
  check_osv_advisory     - lockfile parse plus osv-scanner, advisories as facts
  explain_cve            - OSV/GHSA advisory by exact id, refuse when not found
Phase 4 tool:
  draft_private_disclosure - Markdown disclosure draft from a real
    finding, drafts only, never sent, never PR, never fork, never push

Rules enforced here, from the build plan:
- No model is pre-selected. The caller must name the model.
- Estimate before every call. Refuse before any API call when the
  safe upper-bound estimate exceeds the spend cap (default $1.00,
  never above $5.00).
- Block unpriced models. Refuse with a clear error, do not invent a price.
- No POST retry. One retry on timeout only, inside gmi.chat.
- One retry with a shorter prompt on an unparsed answer, for
  non-reasoning models only, single-stage only. Reasoning-heavy
  models (DeepSeek, thinking, R1, reasoning) get no retry: the
  retry cost $0.004247 extra in live testing and failed the same
  way. Two-stage calls escalate to Stage 2 on unparsed instead.
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
from pathlib import Path

from mcp.server import MCPServer

from . import __version__
from . import cost as cost_mod
from . import disclosure as disclosure_mod
from . import gmi as gmi_mod
from . import lockfiles as lockfiles_mod
from . import osv as osv_mod
from . import prompts as prompts_mod
from . import redact as redact_mod
from . import report as report_mod
from . import scanners as scanners_mod
from . import validate as validate_mod

MAX_CODE_CHARS = 40000
ALLOWED_MAX_TOKENS = (800, 1200, 2500)
DEFAULT_THRESHOLD = 0.8
REASONING_WARN_PROMPT_TOKENS = 3000
UNPARSED_RETRY_MAX_CHARS = 4000

mcp = MCPServer(
    "gmi-security-mcp",
    instructions=(
        "Security triage tools backed by GMI Inference. "
        "Triage one semgrep finding, scan a repo, check a lockfile "
        "against OSV, or explain a CVE from its advisory. "
        "No model is pre-selected."
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
        "reasoning_model_warning": None,
        "retried_unparsed": False,
    }
    result.update(extra)
    return result


def _reasoning_warning(model, prompt_tokens):
    """Warning text when a reasoning-heavy model faces a large input.

    Regex-matched reasoning models warn above 3,000 prompt tokens.
    Models observed returning reasoning tokens despite an id with
    no reasoning marker (Qwen/Qwen3.8-Flash, 3,566 reasoning tokens
    and 53 s on one small finding, 2026-11-10) warn at any size,
    because the slowness showed up on a small input too.
    """
    if not model or not gmi_mod.is_reasoning_model(model):
        return None
    if gmi_mod.is_known_reasoning_model(model):
        return (
            "Reasoning model %s: it was observed returning reasoning "
            "tokens (3,566 tokens, 53 s) on a small finding, so expect "
            "a slow reply, and no automatic retry runs for reasoning "
            "models." % model
        )
    if (prompt_tokens or 0) > REASONING_WARN_PROMPT_TOKENS:
        return (
            "Reasoning model %s with about %d prompt tokens: it can "
            "spend its whole completion budget thinking and return no "
            "JSON, and no automatic retry runs for reasoning models."
            % (model, prompt_tokens)
        )
    return None


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
    if redaction_count > 0:
        # Tell the model a redaction happened, without revealing the
        # value. Without this note the model sees `API_KEY =
        # '[REDACTED]'` and cannot tell a real hardcoded secret from
        # a placeholder, so it triages hardcoded-secret findings as
        # false positives. Measured 2026-11-10 on the 50-finding
        # dataset: S10 and S11 failed that way before this note.
        redacted_text += (
            "\n\n[Note: %d secret-shaped value(s) in the code above "
            "were replaced with [REDACTED] before this call. A "
            "redacted value was present in the code shown.]"
            % redaction_count
        )

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
    estimate2 = None
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
    # Safe upper bound for the whole call: Stage 1, plus Stage 2
    # when two-stage, plus one shorter-prompt retry on an unparsed
    # answer when single-stage with a non-reasoning model.
    max_total = estimate["max_usd"] or 0
    if estimate2 is not None and estimate2["max_usd"] is not None:
        max_total += estimate2["max_usd"]
    retry_possible = not two_stage and not gmi_mod.is_reasoning_model(
        stage1_model
    )
    if retry_possible and estimate["max_usd"] is not None:
        max_total += estimate["max_usd"]
    if max_total > spend_cap_usd:
        return _error_result(
            "Estimated maximum cost $%.6f exceeds the spend cap $%.2f. "
            "Refusing to run. Lower max_tokens or raise the cap."
            % (max_total, spend_cap_usd),
            redacted=redaction_count > 0,
            redaction_count=redaction_count,
            estimate_usd=estimate["typical_usd"],
            typical_usd=estimate["typical_usd"],
            max_usd=max_total,
        )
    if gmi_mod.get_api_key() is None:
        return _error_result(
            "GMI_API_KEY is not set. Set it in the environment before "
            "running a triage. The key is never read from a file.",
            redacted=redaction_count > 0,
            redaction_count=redaction_count,
            estimate_usd=estimate["typical_usd"],
            typical_usd=estimate["typical_usd"],
            max_usd=max_total,
        )

    prompt_tokens = cost_mod.estimate_prompt_tokens(redacted_text)
    warning = _reasoning_warning(stage1_model, prompt_tokens)
    if two_stage and stage2_model:
        warning2 = _reasoning_warning(stage2_model, prompt_tokens)
        if warning2:
            warning = (warning + " " if warning else "") + warning2

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

    # Single-stage unparsed retry, non-reasoning models only, once,
    # with a shorter prompt. Two-stage calls escalate to Stage 2
    # instead, and reasoning models get no retry.
    retried_unparsed = False
    if not needs_stage2 and stage1["unparsed"] and retry_possible:
        short_text = redacted_text[:UNPARSED_RETRY_MAX_CHARS]
        retry = _call_stage(stage1_model, short_text, max_tokens, chat_fn)
        total_cost += cost_mod.cost_from_usage(
            retry["usage"], stage1_model, pricing=prices
        )
        total_latency += retry["latency_seconds"] or 0
        retried_unparsed = True
        stage1 = retry

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
                reasoning_model_warning=warning,
                retried_unparsed=retried_unparsed,
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
                reasoning_model_warning=warning,
                retried_unparsed=retried_unparsed,
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
            "reasoning_model_warning": warning,
            "retried_unparsed": retried_unparsed,
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
            "stage1_confidence": (
                stage1["parsed"].get("confidence")
                if stage1["parsed"] is not None
                else None
            ),
            "stage1_unparsed": stage1["unparsed"],
            "stage1_error": stage1["error"],
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
            "reasoning_model_warning": warning,
            "retried_unparsed": retried_unparsed,
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
            "stage1_confidence": (
                stage1["parsed"].get("confidence")
                if stage1["parsed"] is not None
                else None
            ),
            "stage1_unparsed": stage1["unparsed"],
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
            "reasoning_model_warning": warning,
            "retried_unparsed": retried_unparsed,
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
        reasoning_model_warning=warning,
        retried_unparsed=retried_unparsed,
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


def repo_scan_impl(
    repo_path,
    stage1_model=None,
    stage2_model=None,
    threshold=DEFAULT_THRESHOLD,
    max_tokens=2500,
    spend_cap_usd=cost_mod.DEFAULT_SPEND_CAP_USD,
    semgrep_config=None,
    include_tests=False,
    max_files=10,
    max_file_kb=40,
    max_total_kb=200,
    dry_run=False,
    write_report=None,
    chat_fn=None,
    pricing=None,
    semgrep_runner=None,
    osv_runner=None,
    semgrep_binary="semgrep",
    osv_binary="osv-scanner",
):
    """Repo-wide scan: semgrep plus osv-scanner, two-stage triage.

    Returns the report dict (see report.build_report). Findings in
    files over max_file_kb, findings past max_files distinct files,
    and findings past max_total_kb of snippets are skipped with a
    reason, never silently dropped. When the remaining budget cannot
    cover the next finding's safe upper-bound estimate, triage stops
    early and the report says so. A dry run runs the scanners and
    estimates the GMI cost with no API calls and no verdicts.
    """
    chat_fn = chat_fn or gmi_mod.chat
    errors = []
    warnings = []
    if not repo_path or not str(repo_path).strip():
        return report_mod.build_report(
            repo_path=repo_path, errors=["repo_path is required"]
        )
    root = Path(repo_path).expanduser()
    if not root.is_dir():
        return report_mod.build_report(
            repo_path=str(repo_path),
            errors=["repo_path is not an existing directory: %s" % repo_path],
        )
    root = root.resolve()
    if not stage1_model or not str(stage1_model).strip():
        return report_mod.build_report(
            repo_path=str(root),
            errors=["stage1_model is required. No model is pre-selected."],
        )
    if not stage2_model or not str(stage2_model).strip():
        return report_mod.build_report(
            repo_path=str(root),
            errors=["stage2_model is required. No model is pre-selected."],
        )
    try:
        threshold = float(threshold)
        spend_cap_usd = float(spend_cap_usd)
        max_files = int(max_files)
        max_file_kb = int(max_file_kb)
        max_total_kb = int(max_total_kb)
    except (TypeError, ValueError):
        return report_mod.build_report(
            repo_path=str(root),
            errors=["threshold, spend_cap_usd, max_files, max_file_kb, "
                    "and max_total_kb must be numbers"],
        )
    if not 0 <= threshold <= 1:
        return report_mod.build_report(
            repo_path=str(root), errors=["threshold must be between 0 and 1"]
        )
    if spend_cap_usd <= 0 or spend_cap_usd > cost_mod.MAX_SPEND_CAP_USD:
        return report_mod.build_report(
            repo_path=str(root),
            errors=["spend_cap_usd must be above 0 and at most $%.2f"
                    % cost_mod.MAX_SPEND_CAP_USD],
        )
    if max_tokens not in ALLOWED_MAX_TOKENS:
        return report_mod.build_report(
            repo_path=str(root),
            errors=["max_tokens must be one of 800, 1200, 2500"],
        )
    if max_files < 1 or max_file_kb < 1 or max_total_kb < 1:
        return report_mod.build_report(
            repo_path=str(root),
            errors=["max_files, max_file_kb, and max_total_kb must be 1 or above"],
        )
    try:
        configs = scanners_mod.parse_semgrep_config(
            semgrep_config or scanners_mod.DEFAULT_SEMGREP_CONFIG
        )
    except ValueError as err:
        return report_mod.build_report(repo_path=str(root), errors=[str(err)])
    config_label = ",".join(configs)

    prices = pricing if pricing is not None else cost_mod.load_pricing()
    for model in (stage1_model, stage2_model):
        if model not in prices:
            return report_mod.build_report(
                repo_path=str(root),
                stage1_model=stage1_model,
                stage2_model=stage2_model,
                threshold=threshold,
                semgrep_config=config_label,
                errors=[
                    "Model %s has no flat per-token pricing, so its cost "
                    "cannot be estimated. Pick a priced model instead."
                    % model
                ],
            )
    if not dry_run and gmi_mod.get_api_key() is None:
        return report_mod.build_report(
            repo_path=str(root),
            stage1_model=stage1_model,
            stage2_model=stage2_model,
            threshold=threshold,
            semgrep_config=config_label,
            errors=[
                "GMI_API_KEY is not set. Set it in the environment before "
                "running a scan. The key is never read from a file."
            ],
        )

    try:
        raw_findings, semgrep_errors = scanners_mod.run_semgrep(
            root, configs, runner=semgrep_runner, binary=semgrep_binary
        )
    except RuntimeError as err:
        return report_mod.build_report(
            repo_path=str(root),
            stage1_model=stage1_model,
            stage2_model=stage2_model,
            threshold=threshold,
            semgrep_config=config_label,
            errors=[str(err)],
        )
    errors.extend("semgrep: %s" % err for err in semgrep_errors)

    # Resolve semgrep paths to repo-relative paths, apply exclusions,
    # then deduplicate.
    findings = []
    for finding in raw_findings:
        raw_path = finding.get("file") or ""
        try:
            rel = str(Path(raw_path).resolve().relative_to(root))
        except (ValueError, OSError):
            rel = raw_path
            if rel.startswith(str(root)):
                rel = rel[len(str(root)):].lstrip("/")
        if scanners_mod.is_excluded_path(rel, include_tests):
            continue
        item = dict(finding)
        item["file"] = rel
        findings.append(item)
    findings = scanners_mod.deduplicate_findings(findings)

    # OSV section: one osv-scanner run per scannable lockfile found.
    # package.json and go.sum are parsed locally only: osv-scanner
    # has no extractor for them (package.json holds ranges, go.sum
    # holds hashes), so they are reported as parsed, not scanned.
    osv_sections = []
    lockfiles = scanners_mod.find_lockfiles(root)
    for lockfile in lockfiles:
        rel_lockfile = str(lockfile.relative_to(root))
        if lockfile.name in ("package.json", "go.sum"):
            try:
                parsed_lockfile = lockfiles_mod.parse_lockfile(lockfile)
                osv_sections.append(
                    {
                        "lockfile_path": rel_lockfile,
                        "packages_scanned": 0,
                        "packages_parsed": len(parsed_lockfile["packages"]),
                        "vulnerable_packages": 0,
                        "advisories": [],
                        "unresolved_packages": parsed_lockfile["unresolved"],
                        "error": None,
                        "note": "osv-scanner has no extractor for this "
                        "file; parsed locally only, no advisory lookup ran",
                    }
                )
            except (ValueError, OSError) as err:
                osv_sections.append(
                    {
                        "lockfile_path": rel_lockfile,
                        "packages_scanned": 0,
                        "vulnerable_packages": 0,
                        "advisories": [],
                        "error": str(err),
                    }
                )
            continue
        advisories, scanned, vulnerable, osv_error = (
            scanners_mod.run_osv_scanner(
                lockfile, runner=osv_runner, binary=osv_binary
            )
        )
        try:
            parsed_lockfile = lockfiles_mod.parse_lockfile(lockfile)
            packages_scanned = (
                len(parsed_lockfile["packages"]) if osv_error is None else scanned
            )
            unresolved = parsed_lockfile["unresolved"]
        except (ValueError, OSError):
            packages_scanned = scanned
            unresolved = []
        osv_sections.append(
            {
                "lockfile_path": rel_lockfile,
                "packages_scanned": packages_scanned,
                "vulnerable_packages": vulnerable,
                "advisories": advisories,
                "unresolved_packages": unresolved,
                "error": osv_error,
            }
        )
        if osv_error:
            errors.append("osv-scanner on %s: %s" % (lockfile.name, osv_error))

    # Caps: file size, distinct files, total snippet size.
    triageable = []
    skipped = []
    files_seen = set()
    total_snippet_kb = 0.0
    for finding in findings:
        rel = finding.get("file") or ""
        try:
            size_kb = (root / rel).stat().st_size / 1024
        except OSError:
            size_kb = 0
        if size_kb > max_file_kb:
            skipped.append(
                {
                    "file": rel,
                    "line": finding.get("line"),
                    "reason": "file is %.1f KB, over the %d KB per-file cap"
                    % (size_kb, max_file_kb),
                }
            )
            continue
        if rel not in files_seen and len(files_seen) >= max_files:
            skipped.append(
                {
                    "file": rel,
                    "line": finding.get("line"),
                    "reason": "over the %d distinct-file cap" % max_files,
                }
            )
            continue
        snippet = scanners_mod.read_snippet(
            root, rel, finding.get("line") or 1
        )
        snippet_kb = len(snippet or "") / 1024
        if total_snippet_kb + snippet_kb > max_total_kb:
            skipped.append(
                {
                    "file": rel,
                    "line": finding.get("line"),
                    "reason": "over the %d KB total snippet cap" % max_total_kb,
                }
            )
            continue
        files_seen.add(rel)
        total_snippet_kb += snippet_kb
        triageable.append((finding, snippet))

    # Estimates before any GMI call.
    estimate_typical = 0.0
    estimate_max = 0.0
    per_finding_max = []
    for finding, snippet in triageable:
        text = "%s\n\nCode:\n%s" % (
            finding.get("message") or finding.get("rule_id") or "",
            snippet or "",
        )
        est1 = cost_mod.estimate_cost(
            stage1_model, len(text), max_tokens, 1, pricing=prices
        )
        est2 = cost_mod.estimate_cost(
            stage2_model, len(text), max_tokens, 1, pricing=prices
        )
        finding_max = (est1["max_usd"] or 0) + (est2["max_usd"] or 0)
        per_finding_max.append(finding_max)
        estimate_typical += (est1["typical_usd"] or 0) + (
            est2["typical_usd"] or 0
        )
        estimate_max += finding_max

    results = []
    total_cost = 0.0
    remaining = spend_cap_usd
    stopped_early = False
    stopped_reason = None
    if dry_run:
        stopped_early = True
        stopped_reason = (
            "dry run: scanners ran, GMI cost estimated, no API calls made"
        )
    else:
        for index, (finding, snippet) in enumerate(triageable):
            if per_finding_max[index] > remaining:
                stopped_early = True
                stopped_reason = (
                    "spend cap reached: $%.6f remaining, next finding "
                    "needs up to $%.6f" % (remaining, per_finding_max[index])
                )
                skipped.append(
                    {
                        "file": finding.get("file"),
                        "line": finding.get("line"),
                        "reason": stopped_reason,
                    }
                )
                for later in triageable[index + 1:]:
                    skipped.append(
                        {
                            "file": later[0].get("file"),
                            "line": later[0].get("line"),
                            "reason": "not reached, scan stopped early",
                        }
                    )
                break
            finding_text = "Semgrep rule %s: %s" % (
                finding.get("rule_id"),
                finding.get("message") or "",
            )
            outcome = triage_impl(
                finding=finding_text,
                code=snippet or "",
                file=finding.get("file"),
                line=finding.get("line"),
                check=finding.get("check"),
                stage1_model=stage1_model,
                stage2_model=stage2_model,
                two_stage=True,
                threshold=threshold,
                max_tokens=max_tokens,
                spend_cap_usd=remaining,
                chat_fn=chat_fn,
                pricing=prices,
            )
            if outcome.get("cost_usd"):
                total_cost += outcome["cost_usd"]
                remaining -= outcome["cost_usd"]
            if outcome.get("reasoning_model_warning"):
                warnings.append(outcome["reasoning_model_warning"])
            item = {
                "file": finding.get("file"),
                "line": finding.get("line"),
                "rule_id": finding.get("rule_id"),
                "semgrep_severity": finding.get("semgrep_severity"),
                "check": outcome.get("check") or finding.get("check"),
                "verdict": outcome.get("verdict"),
                "severity": outcome.get("severity"),
                "confidence": outcome.get("confidence"),
                "reason": outcome.get("reason"),
                "fix": outcome.get("fix"),
                "stage_used": outcome.get("stage_used"),
                "stage": outcome.get("stage"),
                "escalated": outcome.get("escalated"),
                "escalation_failed": outcome.get("escalation_failed"),
                "unparsed": outcome.get("unparsed"),
                "error": outcome.get("error"),
                "latency_seconds": outcome.get("latency_seconds"),
                "usage": outcome.get("usage"),
                "cost_usd": outcome.get("cost_usd"),
                "redacted": outcome.get("redacted"),
                "redaction_count": outcome.get("redaction_count"),
            }
            results.append(item)
            if outcome.get("error") and outcome.get("verdict") is None:
                errors.append(
                    "%s:%s triage failed: %s"
                    % (
                        finding.get("file"),
                        finding.get("line"),
                        outcome.get("error"),
                    )
                )

    counts = {
        "real": sum(1 for r in results if r["verdict"] == "real"),
        "false_positive": sum(
            1 for r in results if r["verdict"] == "false_positive"
        ),
        "no_verdict": sum(1 for r in results if r["verdict"] is None),
    }
    report = report_mod.build_report(
        repo_path=str(root),
        stage1_model=stage1_model,
        stage2_model=stage2_model,
        threshold=threshold,
        semgrep_config=config_label,
        files_scanned=len(files_seen),
        findings_total=len(findings),
        findings_triaged=len(results),
        findings_real=counts["real"],
        findings_false_positive=counts["false_positive"],
        findings_no_verdict=counts["no_verdict"],
        findings=results,
        skipped=skipped,
        osv={"lockfiles": osv_sections} if lockfiles else {"lockfiles": []},
        total_cost_usd=total_cost,
        estimate_usd=estimate_typical,
        max_estimate_usd=estimate_max,
        stopped_early=stopped_early,
        stopped_reason=stopped_reason,
        dry_run=dry_run,
        errors=errors,
        warnings=list(dict.fromkeys(warnings)),
    )

    if write_report:
        try:
            Path(write_report).write_text(
                report_mod.report_to_markdown(report)
            )
            report["report_written_to"] = str(write_report)
        except OSError as err:
            report["errors"] = list(report["errors"]) + [
                "could not write report to %s: %s" % (write_report, err)
            ]
    return report


def check_osv_impl(
    lockfile_path,
    ecosystem=None,
    osv_runner=None,
    osv_binary="osv-scanner",
):
    """Check one lockfile against OSV via the local osv-scanner.

    Parses the lockfile first (exact versions only; ranges are
    reported unresolved, never given a verdict), then runs
    osv-scanner on it and returns its advisories as facts. No GMI
    call is made: an advisory is a fact from OSV, not a model
    opinion.
    """
    if not lockfile_path or not str(lockfile_path).strip():
        return {"error": "lockfile_path is required", "advisories": []}
    try:
        parsed = lockfiles_mod.parse_lockfile(lockfile_path, ecosystem)
    except (FileNotFoundError, ValueError) as err:
        return {
            "lockfile_path": str(lockfile_path),
            "error": str(err),
            "advisories": [],
        }
    except Exception as err:  # noqa: BLE001 - report any parse failure
        return {
            "lockfile_path": str(lockfile_path),
            "error": "could not parse lockfile: %s" % err,
            "advisories": [],
        }
    advisories, scanned, vulnerable, osv_error = (
        scanners_mod.run_osv_scanner(
            lockfile_path, runner=osv_runner, binary=osv_binary
        )
    )
    # osv-scanner JSON lists only vulnerable packages, so its own
    # count is not the scanned population. The scanned population
    # is the packages parsed from the lockfile.
    packages_scanned = len(parsed["packages"]) if osv_error is None else scanned
    return {
        "lockfile_path": str(lockfile_path),
        "ecosystem": parsed["ecosystem"],
        "packages_scanned": packages_scanned,
        "packages_parsed": len(parsed["packages"]),
        "vulnerable_packages": vulnerable,
        "advisories": advisories,
        "unresolved_packages": parsed["unresolved"],
        "error": osv_error,
    }


EXPLAIN_SYSTEM = (
    "You are a security explainer. Explain the advisory below in one "
    "short paragraph of plain language: what the flaw is, what it "
    "lets an attacker do, and which version fixes it. Use ONLY the "
    "advisory text given. Do not add facts from memory, do not invent "
    "versions, and cite the advisory id. Return ONLY the paragraph, "
    "no other text."
)


def explain_cve_impl(
    advisory_id,
    package=None,
    version=None,
    stage1_model=None,
    max_tokens=2500,
    spend_cap_usd=cost_mod.DEFAULT_SPEND_CAP_USD,
    chat_fn=None,
    pricing=None,
    fetcher=None,
):
    """Explain a CVE or GHSA id from its OSV advisory, with citations.

    Fetches the advisory by exact id and refuses with found false
    when no advisory with that id exists. The explanation comes
    from the retrieved advisory only. When stage1_model is named,
    GMI writes the plain-language paragraph from the advisory; when
    no model is named, the explanation is the advisory summary
    itself, marked as advisory text, not model-generated.
    """
    chat_fn = chat_fn or gmi_mod.chat
    try:
        record = osv_mod.fetch_advisory(advisory_id, fetcher=fetcher)
    except ValueError as err:
        return {"found": False, "advisory_id": advisory_id, "error": str(err)}
    except RuntimeError as err:
        return {"found": False, "advisory_id": advisory_id, "error": str(err)}
    if record is None:
        return {
            "found": False,
            "advisory_id": advisory_id,
            "error": "No advisory with id %s was found in OSV. "
            "This tool does not invent advisories." % advisory_id,
        }
    alias_records = []
    alias_errors = []
    for alias in record.get("aliases") or []:
        if alias == record.get("id"):
            continue
        try:
            alias_record = osv_mod.fetch_advisory(alias, fetcher=fetcher)
        except (ValueError, RuntimeError) as err:
            alias_errors.append(str(err))
            continue
        if alias_record is not None:
            alias_records.append(alias_record)
    advisory = osv_mod.summarize_advisory(
        record, alias_records, package=package
    )
    citations = [advisory["id"]] + list(advisory["aliases"])
    if advisory["fixed_versions"]:
        citations.append(
            "fixed in %s" % ", ".join(advisory["fixed_versions"])
        )
    citations.append(advisory["source_url"])
    result = {
        "found": True,
        "advisory_id": advisory["id"],
        "advisory": advisory,
        "citations": citations,
        "error": None,
    }
    if alias_errors:
        result["alias_errors"] = alias_errors
    if version:
        result["queried_version"] = version
        affected_versions = []
        for entry in advisory["affected"]:
            if package and entry["package"] != package:
                continue
            affected_versions.extend(entry.get("fixed_versions") or [])
        result["version_note"] = (
            "Version %s was given for context only; fixed versions "
            "come from the advisory ranges." % version
        )

    if not stage1_model:
        result["explanation"] = advisory.get("summary") or advisory.get(
            "details"
        )
        result["explanation_source"] = "advisory"
        result["cost_usd"] = 0.0
        return result

    prices = pricing if pricing is not None else cost_mod.load_pricing()
    advisory_text = json.dumps(advisory, indent=2)
    redacted_text, redaction_count, _hits = redact_mod.redact(advisory_text)
    estimate = cost_mod.estimate_cost(
        stage1_model, len(redacted_text), max_tokens, 1, pricing=prices
    )
    if not estimate["priced"]:
        result["explanation"] = advisory.get("summary") or advisory.get(
            "details"
        )
        result["explanation_source"] = "advisory"
        result["cost_usd"] = 0.0
        result["error"] = (
            "Model %s has no flat per-token pricing, so no GMI "
            "explanation was generated. The advisory summary is "
            "returned instead." % stage1_model
        )
        return result
    if max_tokens not in ALLOWED_MAX_TOKENS:
        result["explanation"] = advisory.get("summary")
        result["explanation_source"] = "advisory"
        result["cost_usd"] = 0.0
        result["error"] = "max_tokens must be one of 800, 1200, 2500"
        return result
    if estimate["max_usd"] is not None and estimate["max_usd"] > spend_cap_usd:
        result["explanation"] = advisory.get("summary")
        result["explanation_source"] = "advisory"
        result["cost_usd"] = 0.0
        result["error"] = (
            "Estimated maximum cost $%.6f exceeds the spend cap $%.2f, "
            "so no GMI explanation was generated. The advisory "
            "summary is returned instead."
            % (estimate["max_usd"], spend_cap_usd)
        )
        return result
    if gmi_mod.get_api_key() is None:
        result["explanation"] = advisory.get("summary")
        result["explanation_source"] = "advisory"
        result["cost_usd"] = 0.0
        result["error"] = (
            "GMI_API_KEY is not set, so no GMI explanation was "
            "generated. The advisory summary is returned instead."
        )
        return result
    reply = chat_fn(
        model=stage1_model,
        system_content=EXPLAIN_SYSTEM,
        user_content="Advisory %s:\n%s" % (advisory["id"], redacted_text),
        max_tokens=max_tokens,
    )
    if reply.get("error"):
        result["explanation"] = advisory.get("summary")
        result["explanation_source"] = "advisory"
        result["cost_usd"] = cost_mod.cost_from_usage(
            reply.get("usage", {}), stage1_model, pricing=prices
        )
        result["error"] = (
            "GMI explanation failed: %s. The advisory summary is "
            "returned instead." % reply["error"]
        )
        return result
    text = (reply.get("content") or "").strip()
    result["explanation"] = text[:2000] if text else advisory.get("summary")
    result["explanation_source"] = "gmi" if text else "advisory"
    result["cost_usd"] = cost_mod.cost_from_usage(
        reply.get("usage", {}), stage1_model, pricing=prices
    )
    result["estimate_usd"] = estimate["typical_usd"]
    result["usage"] = reply.get("usage", {})
    result["latency_seconds"] = reply.get("latency_seconds")
    return result


@mcp.tool()
def repo_scan(
    repo_path: str,
    stage1_model: str,
    stage2_model: str,
    threshold: float = 0.8,
    max_tokens: int = 2500,
    spend_cap_usd: float = 1.00,
    semgrep_config: str | None = None,
    include_tests: bool = False,
    max_files: int = 10,
    max_file_kb: int = 40,
    max_total_kb: int = 200,
    dry_run: bool = False,
    write_report: str | None = None,
) -> str:
    """Scan a repo with semgrep and osv-scanner, then two-stage triage.

    Returns a JSON report: per-finding verdicts with stage and cost,
    totals, skipped findings with reasons, the OSV section, and the
    estimate versus actual cost. A dry run runs the scanners and
    estimates the cost with no GMI calls. Files over max_file_kb are
    skipped unless the caller raises the cap.
    """
    result = repo_scan_impl(
        repo_path=repo_path,
        stage1_model=stage1_model,
        stage2_model=stage2_model,
        threshold=threshold,
        max_tokens=max_tokens,
        spend_cap_usd=spend_cap_usd,
        semgrep_config=semgrep_config,
        include_tests=include_tests,
        max_files=max_files,
        max_file_kb=max_file_kb,
        max_total_kb=max_total_kb,
        dry_run=dry_run,
        write_report=write_report,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def check_osv_advisory(
    lockfile_path: str,
    ecosystem: str | None = None,
) -> str:
    """Check one lockfile against OSV with the local osv-scanner.

    Parses the lockfile locally, then runs osv-scanner on it and
    returns advisories as facts: id, package, installed version,
    fixed version, severity, summary, and link. Packages with only
    a version range and no exact version are reported unresolved,
    never given a verdict. No GMI call is made.
    """
    result = check_osv_impl(
        lockfile_path=lockfile_path,
        ecosystem=ecosystem,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def explain_cve(
    advisory_id: str,
    package: str | None = None,
    version: str | None = None,
    stage1_model: str | None = None,
    max_tokens: int = 2500,
    spend_cap_usd: float = 1.00,
) -> str:
    """Explain a CVE, GHSA, or OSV id from its advisory, with citations.

    Fetches the advisory from OSV by exact id. When no advisory with
    that id exists, returns found false and invents nothing. When a
    model is named, GMI writes one plain-language paragraph from the
    retrieved advisory only. When no model is named, the explanation
    is the advisory summary itself.
    """
    result = explain_cve_impl(
        advisory_id=advisory_id,
        package=package,
        version=version,
        stage1_model=stage1_model,
        max_tokens=max_tokens,
        spend_cap_usd=spend_cap_usd,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def draft_private_disclosure(
    finding: dict,
    repo: str,
    maintainer_contact: str | None = None,
    include_fix: bool = True,
    confirm_low_confidence: bool = False,
    write_path: str | None = None,
) -> str:
    """Draft a private disclosure from a confirmed real finding.

    Uses the GitHub Security Lab report template, with the
    ssh-mcp-server host-key draft as the worked example of the
    format. Refuses when the verdict is not real, or when confidence
    is below 0.8 without explicit confirmation. Returns the draft
    as Markdown and writes it only when write_path is given. It is
    never sent, never opened as a PR, never forked, never pushed,
    never emailed. sent is always false.
    """
    result = disclosure_mod.draft_private_disclosure_impl(
        finding=finding,
        repo=repo,
        maintainer_contact=maintainer_contact,
        include_fix=include_fix,
        confirm_low_confidence=confirm_low_confidence,
        write_path=write_path,
    )
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
        print("repo_scan")
        print("check_osv_advisory")
        print("explain_cve")
        print("draft_private_disclosure")
        print("estimate_cost")
        return 0
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
