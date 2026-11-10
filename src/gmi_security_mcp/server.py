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
Phase A1 tool (v0.5.0):
  verify_finding           - verify one finding with a deterministic
    oracle, PoV-is-truth; GMI only writes the PoC
Phase A2 tools (v0.5.0):
  list_findings, get_finding, update_finding, mark_fp,
  mark_confirmed           - read and update the SQLite findings
    store; a finding is confirmed only with a reproduced
    verification, never on a model verdict alone

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
import shlex
import sqlite3
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
from . import store as store_mod
from . import validate as validate_mod
from . import verify as verify_mod

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
        "against OSV, explain a CVE from its advisory, verify a "
        "finding with a deterministic oracle, list and update "
        "stored findings, or draft a "
        "private disclosure. No model "
        "is pre-selected."
    ),
)


def _store_triage(db_path, finding_text, code_text, result, file=None,
                  line=None, check=None):
    """Store one triaged verdict in the findings store.

    db_path None means no store: the caller did not ask for
    storage. Returns (finding_id or None, db_warning or None,
    store_error or None). The code is redacted before it is
    stored. A storage failure never discards the verdict: it is
    reported as store_error on the result instead.
    """
    if db_path is None:
        return None, None, None
    path, warning = store_mod.resolve_db_path(db_path)
    redacted_code, _count, _hits = redact_mod.redact(code_text or "")
    # The evidence text is the finding plus the code, so it is
    # redacted too: an unredacted copy here would put a secret
    # into the database even though the stored code is redacted.
    redacted_evidence, _ecount, _ehits = redact_mod.redact(
        finding_text or ""
    )
    try:
        with store_mod.connect(path) as conn:
            finding_id, _reopened = store_mod.insert_finding(
                conn,
                scan_id=None,
                check=result.get("check") or check or "",
                file=file or "",
                line=result.get("line") if result.get("line") is not None else line,
                code=redacted_code,
                verdict=result.get("verdict"),
                severity=result.get("severity"),
                confidence=result.get("confidence"),
                reason=result.get("reason"),
                fix=result.get("fix"),
                status="triaged",
                evidence={"finding": redacted_evidence[:500]},
            )
            store_mod.insert_verdict(
                conn,
                finding_id,
                model=result.get("model"),
                stage=result.get("stage_used"),
                verdict=result.get("verdict"),
                severity=result.get("severity"),
                confidence=result.get("confidence"),
                reason=result.get("reason"),
                fix=result.get("fix"),
                latency_seconds=result.get("latency_seconds"),
                usage=result.get("usage"),
                cost_usd=result.get("cost_usd"),
            )
        return finding_id, warning, None
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        return None, warning, "findings store failed: %s" % err


def _attach_store(result, db_path, finding_text, code_text, file=None,
                  line=None, check=None):
    """Attach finding_id to a successful triage result, storing
    the verdict first. Returns the result dict."""
    finding_id, warning, store_error = _store_triage(
        db_path, finding_text, code_text, result, file=file, line=line,
        check=check,
    )
    result["finding_id"] = finding_id
    result["db_warning"] = warning
    if store_error is not None:
        result["store_error"] = store_error
    return result


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
    db_path=None,
):
    """Core triage logic. chat_fn defaults to the real GMI client.

    Returns a dict with a validated verdict, or verdict None with an
    error or unparsed flag. Never invents a verdict. When db_path
    is given, a successful verdict is stored in the findings store
    and the result carries finding_id; db_path None stores nothing.
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
        result = {
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
        return _attach_store(result, db_path, combined, code_text,
                           file=file, line=norm_line, check=norm_check)

    stage2 = _call_stage(stage2_model, redacted_text, max_tokens, chat_fn)
    total_cost += cost_mod.cost_from_usage(
        stage2["usage"], stage2_model, pricing=prices
    )
    total_latency += stage2["latency_seconds"] or 0
    if stage2["parsed"] is not None:
        parsed = stage2["parsed"]
        result = {
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
        return _attach_store(result, db_path, combined, code_text,
                           file=file, line=norm_line, check=norm_check)
    if stage1["parsed"] is not None:
        parsed = stage1["parsed"]
        result = {
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
        return _attach_store(result, db_path, combined, code_text,
                           file=file, line=norm_line, check=norm_check)
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
    db_path: str | None = None,
) -> str:
    """Triage one semgrep or scanner finding with GMI Inference.

    Returns one validated finding as JSON: verdict, severity,
    confidence, reason, fix, stage used, latency, tokens, cost, and
    the estimate made before the call. An unparsed reply returns
    verdict null and unparsed true. It never returns clean. The
    verdict is stored in the findings store (per-user
    ~/.gmi-security-mcp/findings.db by default) and the result
    carries finding_id. An explicit db_path is allowed, with a
    warning that the caller is responsible for not committing it.
    """
    path, _warning = store_mod.resolve_db_path(db_path)
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
        db_path=path,
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
    db_path=None,
):
    """Repo-wide scan: semgrep plus osv-scanner, two-stage triage.

    Returns the report dict (see report.build_report). Findings in
    files over max_file_kb, findings past max_files distinct files,
    and findings past max_total_kb of snippets are skipped with a
    reason, never silently dropped. When the remaining budget cannot
    cover the next finding's safe upper-bound estimate, triage stops
    early and the report says so. A dry run runs the scanners and
    estimates the GMI cost with no API calls and no verdicts.
    When db_path is given, every triaged finding is stored and the
    report carries scan_id; db_path None stores nothing. A dry
    run never writes to the store.
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

    # Findings store: one scan row for this run, unless this is a
    # dry run or the caller passed no db_path. A store failure is
    # recorded as an error and the scan continues without storage,
    # so a DB problem never blocks triage.
    store_path = None
    store_warning = None
    scan_id = None
    if db_path is not None and not dry_run:
        store_path, store_warning = store_mod.resolve_db_path(db_path)
        try:
            with store_mod.connect(store_path) as conn:
                scan_id = store_mod.insert_scan(
                    conn,
                    str(root),
                    stage1_model,
                    stage2_model,
                    spend_cap_usd,
                )
                store_mod.upsert_target(conn, str(root))
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
            errors.append("findings store failed: %s" % err)
            store_path = None

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
            # Store every triaged finding under this scan. The
            # snippet is redacted before it is stored. A finding
            # with no verdict is stored as new, never as clean.
            if store_path is not None:
                redacted_snippet, _c, _h = redact_mod.redact(
                    snippet or ""
                )
                try:
                    with store_mod.connect(store_path) as conn:
                        stored_id, _reopened = store_mod.insert_finding(
                            conn,
                            scan_id=scan_id,
                            check=outcome.get("check")
                            or finding.get("check")
                            or "",
                            file=finding.get("file") or "",
                            line=finding.get("line"),
                            code=redacted_snippet,
                            verdict=outcome.get("verdict"),
                            severity=outcome.get("severity"),
                            confidence=outcome.get("confidence"),
                            reason=outcome.get("reason"),
                            fix=outcome.get("fix"),
                            status=(
                                "triaged"
                                if outcome.get("verdict") is not None
                                else "new"
                            ),
                            evidence={
                                "rule_id": finding.get("rule_id"),
                                "semgrep_severity": finding.get(
                                    "semgrep_severity"
                                ),
                                "message": finding.get("message") or "",
                            },
                        )
                        if outcome.get("verdict") is not None:
                            store_mod.insert_verdict(
                                conn,
                                stored_id,
                                model=outcome.get("model"),
                                stage=outcome.get("stage_used"),
                                verdict=outcome.get("verdict"),
                                severity=outcome.get("severity"),
                                confidence=outcome.get("confidence"),
                                reason=outcome.get("reason"),
                                fix=outcome.get("fix"),
                                latency_seconds=outcome.get(
                                    "latency_seconds"
                                ),
                                usage=outcome.get("usage"),
                                cost_usd=outcome.get("cost_usd"),
                            )
                    item["finding_id"] = stored_id
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
                    errors.append(
                        "findings store failed for %s:%s: %s"
                        % (
                            finding.get("file"),
                            finding.get("line"),
                            err,
                        )
                    )
                    item["finding_id"] = None
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
    if store_path is not None and scan_id is not None:
        try:
            with store_mod.connect(store_path) as conn:
                store_mod.finish_scan(
                    conn,
                    scan_id,
                    total_cost_usd=total_cost,
                    files_scanned=len(files_seen),
                    findings_total=len(findings),
                    status="completed",
                )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
            report["errors"] = list(report["errors"]) + [
                "findings store failed to finish scan: %s" % err
            ]
    report["scan_id"] = scan_id
    report["db_warning"] = store_warning

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
    db_path: str | None = None,
) -> str:
    """Scan a repo with semgrep and osv-scanner, then two-stage triage.

    Returns a JSON report: per-finding verdicts with stage and cost,
    totals, skipped findings with reasons, the OSV section, and the
    estimate versus actual cost. A dry run runs the scanners and
    estimates the cost with no GMI calls. Files over max_file_kb are
    skipped unless the caller raises the cap. Every triaged finding
    is stored in the findings store (per-user
    ~/.gmi-security-mcp/findings.db by default) and the report
    carries scan_id, with one finding_id per finding.
    """
    path, _warning = store_mod.resolve_db_path(db_path)
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
        db_path=path,
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
    finding_id: str | None = None,
    db_path: str | None = None,
) -> str:
    """Draft a private disclosure from a confirmed real finding.

    Uses the GitHub Security Lab report template, with the
    ssh-mcp-server host-key draft as the worked example of the
    format. Refuses when the verdict is not real, or when confidence
    is below 0.8 without explicit confirmation. When finding_id is
    given, the finding must be in the store with status confirmed,
    or triaged with verdict real and confidence at or above 0.8;
    otherwise the draft is refused and the result says why.
    Returns the draft as Markdown and writes it only when
    write_path is given. It is never sent, never opened as a PR,
    never forked, never pushed, never emailed. sent is always false.
    """
    finding_for_draft = finding
    db_warning = None
    if finding_id is not None:
        path, db_warning = store_mod.resolve_db_path(db_path)
        try:
            with store_mod.connect(path) as conn:
                stored = store_mod.get_finding(conn, str(finding_id))
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
            return json.dumps(
                {
                    "draft_markdown": None,
                    "written_to": None,
                    "sent": False,
                    "next_steps": [],
                    "error": "findings store failed: %s" % err,
                },
                indent=2,
            )
        if stored is None:
            return json.dumps(
                {
                    "draft_markdown": None,
                    "written_to": None,
                    "sent": False,
                    "next_steps": [],
                    "error": (
                        "Refusing to draft a disclosure: finding %s "
                        "is not in the findings store. Store it with "
                        "triage_semgrep_finding or repo_scan first."
                        % finding_id
                    ),
                },
                indent=2,
            )
        confidence = validate_mod.norm_confidence(stored.get("confidence"))
        allowed = stored["status"] == "confirmed" or (
            stored["status"] == "triaged"
            and stored.get("verdict") == "real"
            and confidence is not None
            and confidence >= 0.8
        )
        if not allowed:
            return json.dumps(
                {
                    "draft_markdown": None,
                    "written_to": None,
                    "sent": False,
                    "next_steps": [],
                    "error": (
                        "Refusing to draft a disclosure: finding %s "
                        "is in the store with status %s, verdict %s, "
                        "confidence %s. A disclosure needs status "
                        "confirmed, or triaged with verdict real and "
                        "confidence at or above 0.8. Verify the "
                        "finding first, or triage it again."
                        % (
                            finding_id,
                            stored["status"],
                            stored.get("verdict"),
                            confidence,
                        )
                    ),
                },
                indent=2,
            )
        finding_for_draft = stored
    result = disclosure_mod.draft_private_disclosure_impl(
        finding=finding_for_draft,
        repo=repo,
        maintainer_contact=maintainer_contact,
        include_fix=include_fix,
        confirm_low_confidence=confirm_low_confidence,
        write_path=write_path,
    )
    if db_warning is not None:
        result["db_warning"] = db_warning
    return json.dumps(result, indent=2)


def _verify_result(**over):
    """Build a VerificationResult dict and validate it.

    Defaults are the empty result: status error, confirmed False,
    no assertions, no artifacts, poc_before not run. Callers
    override the fields they know. The schema rules (confirmed
    only on reproduced, assertions non-empty on reproduced) are
    enforced by validate.norm_verification_result, not here.
    """
    result = {
        "finding_id": None,
        "status": "error",
        "confirmed": False,
        "assertions": [],
        "artifacts": [],
        "poc_before": {
            "command": None,
            "exit_code": None,
            "output_hash": None,
            "ran": False,
        },
        "poc_after": None,
        "model": None,
        "usage": {},
        "cost_usd": 0.0,
        "estimate_usd": 0.0,
        "unparsed": False,
        "error": None,
        "regression_check": False,
        "patch_passed": None,
        "warning": None,
        "poc": None,
    }
    result.update(over)
    clean = validate_mod.norm_verification_result(result)
    if clean is None:
        # Our own construction broke a schema rule. Return the raw
        # result as an error rather than inventing a verdict.
        result["status"] = "error"
        result["confirmed"] = False
        result["error"] = (
            "internal error: verification result failed validation"
        )
        return result
    return clean


def _verify_error(message, **over):
    return _verify_result(status="error", error=message, **over)


def verify_impl(
    finding=None,
    finding_id=None,
    repo_path=None,
    poc=None,
    test_command=None,
    stage1_model=None,
    spend_cap_usd=cost_mod.DEFAULT_SPEND_CAP_USD,
    run_poc=False,
    regression_check=False,
    executor="host",
    fix_candidate=None,
    max_tokens=2500,
    chat_fn=None,
    pricing=None,
    poc_timeout=verify_mod.POC_TIMEOUT_SECONDS,
    code=None,
    db_path=None,
):
    """Verify one finding with a deterministic oracle, PoV-is-truth.

    The oracle runs the PoC. GMI only writes the PoC, when poc is
    null. A model verdict alone never sets confirmed: confirmed is
    true only when the oracle reproduces the finding, and never on
    a regression check. A PoC that was not run is skipped, a PoC
    that ran and did not reproduce is not_reproduced, and a PoC
    that timed out or could not run is error. A generated PoC is
    untrusted code until reviewed: it is returned for review and
    only runs when run_poc is true. When db_path is given, a
    finding_id is resolved from the findings store, the
    verification result is stored there, and a reproduced result
    moves the finding to verified; db_path None stores nothing.
    """
    chat_fn = chat_fn or gmi_mod.chat
    stored = None
    if finding_id is not None:
        finding_id = str(finding_id)
        if db_path is not None:
            store_path, _w = store_mod.resolve_db_path(db_path)
            try:
                with store_mod.connect(store_path) as conn:
                    stored = store_mod.get_finding(conn, finding_id)
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
                return _verify_error(
                    "findings store failed: %s" % err,
                    finding_id=finding_id,
                )
            if stored is None:
                return _verify_error(
                    "finding %s was not found in the findings store. "
                    "Store the finding with triage_semgrep_finding "
                    "or repo_scan first, or pass the finding inline."
                    % finding_id,
                    finding_id=finding_id,
                )
            if finding is None:
                finding = {
                    "verdict": stored.get("verdict"),
                    "severity": stored.get("severity"),
                    "confidence": stored.get("confidence"),
                    "reason": stored.get("reason"),
                    "fix": stored.get("fix"),
                    "check": stored.get("check"),
                    "line": stored.get("line"),
                }
            if code is None:
                code = stored.get("code")
        elif finding is None:
            return _verify_error(
                "finding_id %r cannot be resolved without the findings "
                "store (Phase A2). Pass the finding inline instead."
                % (finding_id,),
                finding_id=str(finding_id),
            )

    def _record_verification(result):
        """Store a verification result and, when reproduced, move
        the finding toward verified. Attaches verification_id.
        No-op without a store or a stored finding."""
        if db_path is None or finding_id is None:
            result["verification_id"] = None
            return result
        path, _warning = store_mod.resolve_db_path(db_path)
        try:
            with store_mod.connect(path) as conn:
                current = store_mod.get_finding(conn, finding_id)
                if current is None:
                    result["verification_id"] = None
                    return result
                verification_id = store_mod.insert_verification(
                    conn, finding_id, result
                )
                if result.get("status") == "reproduced" and not (
                    result.get("regression_check")
                ):
                    if current["status"] == "new":
                        store_mod.update_finding_status(
                            conn,
                            finding_id,
                            "triaged",
                            "Verification reproduced; finding triaged.",
                            actor="server",
                        )
                    store_mod.update_finding_status(
                        conn,
                        finding_id,
                        "verified",
                        "Oracle reproduced the finding.",
                        actor="server",
                    )
                else:
                    store_mod.insert_event(
                        conn,
                        finding_id,
                        "verification",
                        "Verification %s: status %s."
                        % (verification_id, result.get("status")),
                        actor="server",
                    )
            result["verification_id"] = verification_id
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
            result["verification_id"] = None
            result["store_error"] = "findings store failed: %s" % err
        return result
    norm = validate_mod.norm_finding(finding) if finding is not None else None
    if norm is None:
        return _verify_error(
            "finding is required and must have verdict real or "
            "false_positive, with severity, confidence, reason, and fix",
            finding_id=str(finding_id) if finding_id is not None else None,
        )
    if finding_id is not None:
        finding_id = str(finding_id)
    if norm["verdict"] == "false_positive" and not regression_check:
        return _verify_error(
            "Finding verdict is false_positive. verify_finding refuses "
            "false positives. Pass regression_check true to verify it "
            "as a regression check; the result is then labelled "
            "regression, not confirmation.",
            finding_id=finding_id,
        )
    category = verify_mod.category_for_check(norm["check"])
    if category is None:
        return _verify_result(
            status="skipped",
            error="no oracle for this category",
            assertions=[
                {
                    "name": "oracle_available",
                    "passed": False,
                    "detail": "no oracle for this category",
                }
            ],
            finding_id=finding_id,
            regression_check=bool(regression_check),
        )
    root = verify_mod.validate_repo_path(repo_path)
    if root is None:
        return _verify_error(
            "repo_path is not an existing directory: %s" % repo_path,
            finding_id=finding_id,
            regression_check=bool(regression_check),
        )
    if executor not in ("host", "docker"):
        return _verify_error(
            "executor must be host or docker, got %r" % (executor,),
            finding_id=finding_id,
            regression_check=bool(regression_check),
        )
    if max_tokens not in ALLOWED_MAX_TOKENS:
        return _verify_error(
            "max_tokens must be one of 800, 1200, 2500, got %r"
            % (max_tokens,),
            finding_id=finding_id,
            regression_check=bool(regression_check),
        )
    try:
        spend_cap_usd = float(spend_cap_usd)
    except (TypeError, ValueError):
        return _verify_error(
            "spend_cap_usd must be a number",
            finding_id=finding_id,
            regression_check=bool(regression_check),
        )
    if spend_cap_usd <= 0 or spend_cap_usd > cost_mod.MAX_SPEND_CAP_USD:
        return _verify_error(
            "spend_cap_usd must be above 0 and at most $%.2f"
            % cost_mod.MAX_SPEND_CAP_USD,
            finding_id=finding_id,
            regression_check=bool(regression_check),
        )
    if fix_candidate is not None:
        if not isinstance(fix_candidate, dict):
            return _verify_error(
                "fix_candidate must be an object with path and content",
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )
        fix_path = fix_candidate.get("path")
        fix_content = fix_candidate.get("content")
        if not fix_path or not isinstance(fix_content, str):
            return _verify_error(
                "fix_candidate needs a repo-relative path and content",
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )
        try:
            fix_target = (root / str(fix_path)).resolve()
        except (OSError, RuntimeError):
            return _verify_error(
                "fix_candidate path cannot be resolved: %r" % (fix_path,),
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )
        if fix_target != root and root not in fix_target.parents:
            return _verify_error(
                "fix_candidate path escapes the repo, refused: %r"
                % (fix_path,),
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )
        if not fix_target.is_file():
            return _verify_error(
                "fix_candidate path is not an existing file in the repo: %r"
                % (fix_path,),
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )

    # Validate test_command before any GMI call, so a bad command
    # is refused without spending anything. The {poc} placeholder
    # is substituted with the written PoC file path later.
    raw_command = None
    if test_command is not None:
        try:
            raw_command = shlex.split(str(test_command))
        except ValueError as err:
            return _verify_error(
                "test_command could not be parsed: %s" % err,
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )
        command_error = verify_mod.validate_poc_command(raw_command, root)
        if command_error:
            return _verify_error(
                command_error,
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )

    # PoC generation, only when no PoC was supplied.
    poc_text = poc
    poc_language = "python"
    model_used = None
    usage = {}
    cost_usd = 0.0
    estimate_usd = 0.0
    if poc_text is None and test_command is None:
        if not stage1_model or not str(stage1_model).strip():
            return _verify_error(
                "stage1_model is required to generate a PoC. No model "
                "is pre-selected, name the model to run, or supply poc.",
                finding_id=finding_id,
                regression_check=bool(regression_check),
            )
        prompt_text = (
            "Category: %s\nCheck: %s\nSeverity: %s\nReason: %s\nFix: %s\n"
            "Repo path: %s\n%s\n"
            % (
                category,
                norm["check"],
                norm["severity"],
                norm["reason"],
                norm["fix"],
                str(root),
                verify_mod.evidence_contract(category),
            )
        )
        if code:
            prompt_text += "\nCode:\n%s\n" % str(code)
        redacted_text, redaction_count, _hits = redact_mod.redact(prompt_text)
        if redaction_count > 0:
            redacted_text += (
                "\n\n[Note: %d secret-shaped value(s) in the finding above "
                "were replaced with [REDACTED] before this call.]"
                % redaction_count
            )
        prices = pricing if pricing is not None else cost_mod.load_pricing()
        estimate = cost_mod.estimate_cost(
            stage1_model, len(redacted_text), max_tokens, 1, pricing=prices
        )
        if not estimate["priced"]:
            return _verify_error(
                "Model %s has no flat per-token pricing, so its cost "
                "cannot be estimated. Pick a priced model instead."
                % stage1_model,
                finding_id=finding_id,
                estimate_usd=None,
                regression_check=bool(regression_check),
            )
        estimate_usd = estimate["typical_usd"]
        if estimate["max_usd"] is not None and estimate["max_usd"] > spend_cap_usd:
            return _verify_error(
                "Estimated maximum cost $%.6f exceeds the spend cap "
                "$%.2f. Refusing to run. Lower max_tokens or raise "
                "the cap." % (estimate["max_usd"], spend_cap_usd),
                finding_id=finding_id,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
            )
        if gmi_mod.get_api_key() is None:
            return _verify_error(
                "GMI_API_KEY is not set. Set it in the environment "
                "before generating a PoC. The key is never read from "
                "a file.",
                finding_id=finding_id,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
            )
        system = prompts_mod.system_content(prompts_mod.POC_PROMPT)
        user = prompts_mod.wrap_user_text(redacted_text)
        reply = chat_fn(
            model=stage1_model,
            system_content=system,
            user_content=user,
            max_tokens=max_tokens,
        )
        usage = reply.get("usage", {}) or {}
        cost_usd = cost_mod.cost_from_usage(
            usage, stage1_model, pricing=prices
        )
        model_used = stage1_model
        if reply.get("error"):
            return _verify_error(
                "PoC generation failed: %s. No verdict. This finding "
                "is NOT clean." % reply["error"],
                finding_id=finding_id,
                model=model_used,
                usage=usage,
                cost_usd=cost_usd,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
            )
        parsed_poc = verify_mod.parse_poc_generation(reply.get("content") or "")
        if parsed_poc is None:
            return _verify_result(
                status="error",
                unparsed=True,
                error=(
                    "Unparsed PoC generation, no PoC, this finding is "
                    "NOT clean. The model reply contained no valid "
                    "JSON PoC."
                ),
                finding_id=finding_id,
                model=model_used,
                usage=usage,
                cost_usd=cost_usd,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
            )
        poc_text = parsed_poc["poc"]
        poc_language = parsed_poc["language"]
    elif poc_text is not None:
        poc_text = str(poc_text)
    # When test_command is given and no poc was supplied, there is
    # no PoC text to generate or redact: the command runs a PoC
    # file that already exists in the repo.

    # The PoC text is NOT redacted here. Redaction before the
    # generation call already removed secrets from the finding, so
    # the model never saw one, and a supplied PoC is the caller's
    # own text. Redacting the PoC itself mangled a generated test
    # token in live testing (the assigned_secret pattern matches
    # `token = "..."`, so the token became the bare word
    # [REDACTED] and the PoC crashed with NameError). PoC output
    # is never returned in full, only as a sha256 hash, so no
    # secret can leak through the result that way.
    artifacts = []
    if poc_text is not None:
        artifacts.append(
            {
                "name": "poc",
                "sha256": verify_mod.sha256_hex(poc_text),
                "path": None,
            }
        )

    if not run_poc:
        return _record_verification(_verify_result(
            status="skipped",
            error=(
                "PoC was not run. The PoC is returned for review; pass "
                "run_poc true to run it. A PoC that was not run is "
                "never reproduced."
            ),
            assertions=[
                {
                    "name": "poc_run",
                    "passed": False,
                    "detail": "PoC was not run",
                }
            ],
            artifacts=artifacts,
            finding_id=finding_id,
            model=model_used,
            usage=usage,
            cost_usd=cost_usd,
            estimate_usd=estimate_usd,
            regression_check=bool(regression_check),
            warning=(
                "Generated PoC is untrusted code until reviewed. "
                "It was not run."
            ),
            poc=poc_text,
        ))

    # Work out the command. The PoC text, supplied or generated, is
    # written to a temp file in the repo. A supplied test_command
    # runs a PoC file that already exists in the repo, or the written
    # PoC when it names {poc}, for example pytest {poc} -k host_key.
    # Without a test_command the PoC runs as python3 <poc file>.
    # The temp file stays until patch validation is done, because
    # the same command runs again after the fix candidate.
    poc_path = None
    if poc_text is not None:
        try:
            poc_path = verify_mod.write_poc_file(poc_text, root)
        except (ValueError, OSError) as err:
            return _verify_error(
                "could not write the PoC file: %s" % err,
                finding_id=finding_id,
                model=model_used,
                usage=usage,
                cost_usd=cost_usd,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
                poc=poc_text,
                artifacts=artifacts,
            )

    def _remove_poc_file():
        if poc_path is not None:
            try:
                poc_path.unlink()
            except OSError:
                pass

    if test_command is not None:
        if "{poc}" in raw_command and poc_path is None:
            _remove_poc_file()
            return _verify_error(
                "{poc} in test_command needs a poc to run. Supply poc "
                "or drop {poc} from the command.",
                finding_id=finding_id,
                model=model_used,
                usage=usage,
                cost_usd=cost_usd,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
                poc=poc_text,
                artifacts=artifacts,
            )
        command = [
            str(poc_path) if tok == "{poc}" else tok for tok in raw_command
        ]
        command_error = verify_mod.validate_poc_command(command, root)
        if command_error:
            _remove_poc_file()
            return _verify_error(
                command_error,
                finding_id=finding_id,
                model=model_used,
                usage=usage,
                cost_usd=cost_usd,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
                poc=poc_text,
                artifacts=artifacts,
            )
    elif poc_path is not None:
        command = [sys.executable, str(poc_path)]
    else:
        return _verify_error(
            "no PoC to run and no test_command given",
            finding_id=finding_id,
            model=model_used,
            usage=usage,
            cost_usd=cost_usd,
            estimate_usd=estimate_usd,
            regression_check=bool(regression_check),
            poc=poc_text,
            artifacts=artifacts,
        )

    warning = None
    if executor == "host":
        warning = (
            "PoC ran on the host, not in an isolated container. "
            "Review the PoC before running it."
        )

    before = verify_mod.run_poc(
        command, root, timeout=poc_timeout, executor=executor
    )

    poc_before = {
        "command": list(command),
        "exit_code": before["exit_code"],
        "output_hash": before["output_hash"],
        "ran": bool(before["ran"]),
    }
    if before["output_hash"]:
        artifacts.append(
            {
                "name": "poc_output",
                "sha256": before["output_hash"],
                "path": None,
            }
        )
    if not before["ran"]:
        _remove_poc_file()
        return _record_verification(_verify_result(
            status="error",
            error=before["error"],
            assertions=[
                {
                    "name": "poc_run",
                    "passed": False,
                    "detail": before["error"] or "PoC could not run",
                }
            ],
            artifacts=artifacts,
            poc_before=poc_before,
            finding_id=finding_id,
            model=model_used,
            usage=usage,
            cost_usd=cost_usd,
            estimate_usd=estimate_usd,
            regression_check=bool(regression_check),
            warning=warning,
            poc=poc_text,
        ))

    output = before["output"] or ""
    evidence = verify_mod._evidence_from_output(output)
    if before["exit_code"] not in (0, None) and evidence is None:
        _remove_poc_file()
        return _record_verification(_verify_result(
            status="error",
            error=(
                "PoC exited with code %s and produced no JSON evidence "
                "object, so the run cannot be judged. This is not a "
                "not_reproduced result." % before["exit_code"]
            ),
            assertions=[
                {
                    "name": "poc_run",
                    "passed": False,
                    "detail": "PoC exited %s with no evidence object"
                    % before["exit_code"],
                }
            ],
            artifacts=artifacts,
            poc_before=poc_before,
            finding_id=finding_id,
            model=model_used,
            usage=usage,
            cost_usd=cost_usd,
            estimate_usd=estimate_usd,
            regression_check=bool(regression_check),
            warning=warning,
            poc=poc_text,
        ))

    status, assertions = verify_mod.run_oracle(
        category, norm, output, before["exit_code"]
    )

    # Patch validation: same PoC, before and after a fix candidate.
    poc_after = None
    patch_passed = None
    if fix_candidate is not None:
        fix_target = (root / str(fix_candidate["path"])).resolve()
        try:
            original = fix_target.read_bytes()
        except OSError as err:
            _remove_poc_file()
            return _verify_result(
                status="error",
                error="could not read the fix target: %s" % err,
                assertions=assertions,
                artifacts=artifacts,
                poc_before=poc_before,
                finding_id=finding_id,
                model=model_used,
                usage=usage,
                cost_usd=cost_usd,
                estimate_usd=estimate_usd,
                regression_check=bool(regression_check),
                warning=warning,
                poc=poc_text,
            )
        try:
            fix_target.write_bytes(
                str(fix_candidate["content"]).encode()
            )
            after = verify_mod.run_poc(
                command, root, timeout=poc_timeout, executor=executor
            )
        finally:
            try:
                fix_target.write_bytes(original)
            except OSError:
                pass
        poc_after = {
            "command": list(command),
            "exit_code": after["exit_code"],
            "output_hash": after["output_hash"],
            "ran": bool(after["ran"]),
        }
        if after["output_hash"]:
            artifacts.append(
                {
                    "name": "poc_output_after_fix",
                    "sha256": after["output_hash"],
                    "path": None,
                }
            )
        if not after["ran"]:
            patch_passed = False
        else:
            after_status, _after_assertions = verify_mod.run_oracle(
                category, norm, after["output"] or "", after["exit_code"]
            )
            patch_passed = status == "reproduced" and after_status != "reproduced"

    _remove_poc_file()
    return _record_verification(_verify_result(
        status=status,
        assertions=assertions,
        artifacts=artifacts,
        poc_before=poc_before,
        poc_after=poc_after,
        finding_id=finding_id,
        model=model_used,
        usage=usage,
        cost_usd=cost_usd,
        estimate_usd=estimate_usd,
        regression_check=bool(regression_check),
        patch_passed=patch_passed,
        warning=warning,
        poc=poc_text,
    ))


@mcp.tool()
def verify_finding(
    finding: dict | None = None,
    finding_id: str | None = None,
    repo_path: str | None = None,
    poc: str | None = None,
    test_command: str | None = None,
    stage1_model: str | None = None,
    spend_cap_usd: float = 1.00,
    run_poc: bool = False,
    regression_check: bool = False,
    executor: str = "host",
    fix_candidate: dict | None = None,
    max_tokens: int = 2500,
    code: str | None = None,
    db_path: str | None = None,
) -> str:
    """Verify one finding with a deterministic oracle, PoV-is-truth.

    A finding stays a candidate until an oracle reproduces it.
    GMI only writes the PoC, when poc is null; the local oracle
    decides. code is the audited code and harness description
    sent with the finding when a PoC is generated. A generated PoC is returned for review and only runs
    when run_poc is true. A false_positive finding is refused
    unless regression_check is true, and then the result is
    labelled regression, not confirmation. Categories without an
    oracle return skipped with "no oracle for this category".
    test_command runs a PoC file already in the repo, or the
    written PoC when it names {poc}, for example
    pytest {poc} -k host_key. The PoC runs on the host by default,
    with a warning; pass executor docker for a disposable
    container when Docker is available. verify_finding never
    applies a fix; a fix_candidate is run through patch
    validation and then restored.
    """
    path, _warning = store_mod.resolve_db_path(db_path)
    result = verify_impl(
        finding=finding,
        finding_id=finding_id,
        repo_path=repo_path,
        poc=poc,
        test_command=test_command,
        stage1_model=stage1_model,
        spend_cap_usd=spend_cap_usd,
        run_poc=run_poc,
        regression_check=regression_check,
        executor=executor,
        fix_candidate=fix_candidate,
        max_tokens=max_tokens,
        code=code,
        db_path=path,
    )
    return json.dumps(result, indent=2)


# --- Findings store tools, Phase A2 (v0.5.0) --------------------
# db_path None in these impls means the per-user default DB.
# An explicit db_path always carries a warning in the result.


def list_findings_impl(status=None, check=None, severity=None,
                       repo_path=None, limit=20, cursor=None,
                       db_path=None):
    """List finding summaries from the store. No code in the
    output, only in get_finding."""
    path, warning = store_mod.resolve_db_path(db_path)
    try:
        limit = int(limit) if limit is not None else 20
    except (TypeError, ValueError):
        return {
            "findings": [],
            "next_cursor": None,
            "total": 0,
            "db_path": str(path),
            "db_warning": warning,
            "error": "limit must be a number",
        }
    if status is not None and status not in validate_mod.FINDING_STATUSES:
        return {
            "findings": [],
            "next_cursor": None,
            "total": 0,
            "db_path": str(path),
            "db_warning": warning,
            "error": "unknown finding status %r" % (status,),
        }
    if severity is not None:
        severity = validate_mod.norm_severity(severity)
    try:
        with store_mod.connect(path) as conn:
            summaries, next_cursor, total = store_mod.list_findings(
                conn,
                status=status,
                check=check,
                severity=severity,
                repo_path=repo_path,
                limit=limit,
                cursor=cursor,
            )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        return {
            "findings": [],
            "next_cursor": None,
            "total": 0,
            "db_path": str(path),
            "db_warning": warning,
            "error": "findings store failed: %s" % err,
        }
    return {
        "findings": summaries,
        "next_cursor": next_cursor,
        "total": total,
        "db_path": str(path),
        "db_warning": warning,
        "error": None,
    }


def get_finding_impl(finding_id, db_path=None):
    """Full finding: code, evidence, verdict history, pipeline
    events, verification results, business impact, and matching
    triage memories."""
    path, warning = store_mod.resolve_db_path(db_path)
    if not finding_id:
        return {
            "finding": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "finding_id is required",
        }
    try:
        with store_mod.connect(path) as conn:
            finding = store_mod.get_finding_full(conn, str(finding_id))
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        return {
            "finding": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "findings store failed: %s" % err,
        }
    if finding is None:
        return {
            "finding": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "finding %s was not found in the store"
            % finding_id,
        }
    return {
        "finding": finding,
        "db_path": str(path),
        "db_warning": warning,
        "error": None,
    }


def update_finding_impl(finding_id, business_impact=None, status=None,
                        reason=None, force=False, db_path=None,
                        actor="operator"):
    """Update a finding: business impact, status, or both.

    reason is required. A status change that skips a state is
    refused. Business impact changes business impact only, never
    technical severity, verification, review gates, or patch
    permissions.
    """
    path, warning = store_mod.resolve_db_path(db_path)
    if not finding_id:
        return {
            "finding": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "finding_id is required",
        }
    if not reason or not str(reason).strip():
        return {
            "finding": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "reason is required for update_finding",
        }
    try:
        with store_mod.connect(path) as conn:
            finding = None
            error = None
            if status is not None:
                # Validate the status change before applying a
                # business-impact edit in the same call, so a
                # refused status change does not leave a partial
                # update behind. The suppression guard is checked
                # again inside update_finding_status, against the
                # impact that will be in force.
                current = store_mod.get_finding(conn, str(finding_id))
                if current is None:
                    return {
                        "finding": None,
                        "db_path": str(path),
                        "db_warning": warning,
                        "error": "finding %s was not found in the store"
                        % finding_id,
                    }
                _ok, transition_error = (
                    validate_mod.validate_status_transition(
                        current["status"],
                        status,
                        has_verification=bool(
                            store_mod.has_reproduced_verification(
                                conn, str(finding_id)
                            )
                        ),
                    )
                )
                if transition_error is not None:
                    return {
                        "finding": None,
                        "db_path": str(path),
                        "db_warning": warning,
                        "error": transition_error,
                    }
            if business_impact is not None:
                finding, error = store_mod.update_business_impact(
                    conn,
                    str(finding_id),
                    business_impact,
                    str(reason),
                    actor=actor,
                )
                if error is not None:
                    return {
                        "finding": None,
                        "db_path": str(path),
                        "db_warning": warning,
                        "error": error,
                    }
            if status is not None:
                has_verification = bool(
                    store_mod.has_reproduced_verification(
                        conn, str(finding_id)
                    )
                )
                finding, error = store_mod.update_finding_status(
                    conn,
                    str(finding_id),
                    status,
                    str(reason),
                    actor=actor,
                    force=bool(force),
                    has_verification=has_verification,
                )
                if error is not None:
                    # The suppression guard can still refuse here
                    # (it sees the new business impact). Roll the
                    # business-impact edit back so a refused call
                    # leaves nothing behind.
                    conn.rollback()
                    return {
                        "finding": None,
                        "db_path": str(path),
                        "db_warning": warning,
                        "error": error,
                    }
                    return {
                        "finding": None,
                        "db_path": str(path),
                        "db_warning": warning,
                        "error": error,
                    }
            if finding is None:
                finding = store_mod.get_finding(conn, str(finding_id))
            if finding is None:
                return {
                    "finding": None,
                    "db_path": str(path),
                    "db_warning": warning,
                    "error": "finding %s was not found in the store"
                    % finding_id,
                }
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        return {
            "finding": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "findings store failed: %s" % err,
        }
    return {
        "finding": finding,
        "db_path": str(path),
        "db_warning": warning,
        "error": None,
    }


def mark_fp_impl(finding_id, reason, scope="target", db_path=None,
                 actor="human"):
    """Mark a finding false_positive and create a triage memory.

    Memories are created only by this human call, never by the
    server alone, and a memory never auto-rejects a future
    finding: it is shown as a hint only.
    """
    path, warning = store_mod.resolve_db_path(db_path)
    if not finding_id:
        return {
            "finding": None,
            "memory_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "finding_id is required",
        }
    if not reason or not str(reason).strip():
        return {
            "finding": None,
            "memory_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "reason is required for mark_fp",
        }
    if scope not in ("global", "package", "target"):
        return {
            "finding": None,
            "memory_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "scope must be global, package, or target",
        }
    try:
        with store_mod.connect(path) as conn:
            finding, error = store_mod.update_finding_status(
                conn,
                str(finding_id),
                "false_positive",
                str(reason),
                actor=actor,
            )
            if error is not None:
                return {
                    "finding": None,
                    "memory_id": None,
                    "db_path": str(path),
                    "db_warning": warning,
                    "error": error,
                }
            repo_path = None
            if finding.get("scan_id"):
                scan = store_mod.get_scan(conn, finding["scan_id"])
                if scan:
                    repo_path = scan.get("repo_path")
            package = None
            file_path = (finding.get("file") or "").strip("/")
            parts = [p for p in file_path.split("/") if p]
            if len(parts) > 1:
                package = parts[0]
            memory_id = store_mod.insert_memory(
                conn,
                scope=scope,
                package=package if scope == "package" else None,
                target=repo_path if scope == "target" else None,
                rule_id=None,
                check=finding.get("check"),
                verdict="false_positive",
                reason=str(reason),
                created_by="human",
            )
            store_mod.insert_event(
                conn,
                str(finding_id),
                "marked_false_positive",
                "Marked false_positive by %s. Triage memory %s "
                "created with scope %s. The memory is a hint only "
                "and never auto-rejects a future finding."
                % (actor, memory_id, scope),
                actor=actor,
            )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        return {
            "finding": None,
            "memory_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "findings store failed: %s" % err,
        }
    return {
        "finding": finding,
        "memory_id": memory_id,
        "db_path": str(path),
        "db_warning": warning,
        "error": None,
    }


def mark_confirmed_impl(finding_id, reason, db_path=None,
                        actor="operator"):
    """Mark a finding confirmed, only when a verification result
    with status reproduced exists for it. An LLM verdict alone
    cannot set confirmation."""
    path, warning = store_mod.resolve_db_path(db_path)
    if not finding_id:
        return {
            "finding": None,
            "verification_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "finding_id is required",
        }
    if not reason or not str(reason).strip():
        return {
            "finding": None,
            "verification_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "reason is required for mark_confirmed",
        }
    try:
        with store_mod.connect(path) as conn:
            verification_id = store_mod.has_reproduced_verification(
                conn, str(finding_id)
            )
            if verification_id is None:
                return {
                    "finding": None,
                    "verification_id": None,
                    "db_path": str(path),
                    "db_warning": warning,
                    "error": (
                        "Refusing to mark finding %s confirmed: no "
                        "verification result with status reproduced "
                        "exists for it. An LLM verdict alone cannot "
                        "set confirmation. Run verify_finding first."
                        % finding_id
                    ),
                }
            finding, error = store_mod.update_finding_status(
                conn,
                str(finding_id),
                "confirmed",
                str(reason),
                actor=actor,
                has_verification=True,
            )
            if error is not None:
                return {
                    "finding": None,
                    "verification_id": verification_id,
                    "db_path": str(path),
                    "db_warning": warning,
                    "error": error,
                }
            store_mod.insert_event(
                conn,
                str(finding_id),
                "marked_confirmed",
                "Marked confirmed by %s, on verification %s. Reason: %s"
                % (actor, verification_id, reason),
                actor=actor,
            )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        return {
            "finding": None,
            "verification_id": None,
            "db_path": str(path),
            "db_warning": warning,
            "error": "findings store failed: %s" % err,
        }
    return {
        "finding": finding,
        "verification_id": verification_id,
        "db_path": str(path),
        "db_warning": warning,
        "error": None,
    }


@mcp.tool()
def list_findings(
    status: str | None = None,
    check: str | None = None,
    severity: str | None = None,
    repo_path: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
    db_path: str | None = None,
) -> str:
    """List stored finding summaries, newest first.

    Filters: status, check, severity, repo_path. limit defaults
    to 20 and is capped at 100. cursor pages through results.
    Summaries only: no code in list output, only in get_finding.
    """
    result = list_findings_impl(
        status=status,
        check=check,
        severity=severity,
        repo_path=repo_path,
        limit=limit,
        cursor=cursor,
        db_path=db_path,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def get_finding(
    finding_id: str,
    db_path: str | None = None,
) -> str:
    """Get one stored finding in full: code, evidence, verdict
    history, pipeline events, verification results, business
    impact, and matching triage memories."""
    result = get_finding_impl(finding_id=finding_id, db_path=db_path)
    return json.dumps(result, indent=2)


@mcp.tool()
def update_finding(
    finding_id: str,
    business_impact: dict | None = None,
    status: str | None = None,
    reason: str | None = None,
    force: bool = False,
    db_path: str | None = None,
) -> str:
    """Update a stored finding. reason is required.

    business_impact changes business impact only, never technical
    severity, verification, review gates, or patch permissions.
    status moves one step at a time and is refused when it skips a
    state, for example new to confirmed without a reproduced
    verification. Suppressing a critical/high finding with business
    impact Urgent/High is refused unless force is true with a
    reason, and is then recorded with that reason and actor.
    """
    result = update_finding_impl(
        finding_id=finding_id,
        business_impact=business_impact,
        status=status,
        reason=reason,
        force=force,
        db_path=db_path,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def mark_fp(
    finding_id: str,
    reason: str,
    scope: str = "target",
    db_path: str | None = None,
) -> str:
    """Mark a stored finding false_positive. reason is required.

    Creates a triage memory with the given scope (global, package,
    or target, default target). The memory is a hint only: it never
    auto-rejects a future finding, and the agent must still triage
    it. Memories are created only by this human call.
    """
    result = mark_fp_impl(
        finding_id=finding_id,
        reason=reason,
        scope=scope,
        db_path=db_path,
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def mark_confirmed(
    finding_id: str,
    reason: str,
    db_path: str | None = None,
) -> str:
    """Mark a stored finding confirmed. reason is required.

    Only when a verification result with status reproduced exists
    for the finding. Otherwise the call is refused, and an LLM
    verdict alone cannot set confirmation.
    """
    result = mark_confirmed_impl(
        finding_id=finding_id,
        reason=reason,
        db_path=db_path,
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
        print("verify_finding")
        print("list_findings")
        print("get_finding")
        print("update_finding")
        print("mark_fp")
        print("mark_confirmed")
        return 0
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
