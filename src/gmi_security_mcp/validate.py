"""Validation ported from the Security Audit Tool.

Source: ~/workspace/gmi-clouder/security-benchmark-push/index.html,
lines 596-605: esc, normSeverity, normConfidence, normLine, normCheck,
normShortText, extractBalancedJson, normFinding, and parseTriage.

Rules that must not change:
- A verdict that is not exactly "real" or "false_positive" is dropped.
  Substring matches do not count.
- Severity outside the allowlist becomes "low".
- Confidence is clamped to 0-1, null when not a number.
- Reason and fix are capped at 500 characters.
- JSON is extracted with a string- and escape-aware balanced-brace scan,
  not a greedy first "{" to last "}" match.
- An unparsed answer is no verdict, never clean.
"""

import json
import re

SEVERITIES = ["critical", "high", "medium", "low"]

KNOWN_CHECKS = [
    "SQL injection",
    "Cross-site scripting (XSS)",
    "Authentication and session flaws",
    "Hardcoded secrets",
    "Weak cryptography",
    "Server-side request forgery (SSRF)",
    "Path traversal",
]

_CHECK_SANITISE_RE = re.compile(r"[^A-Za-z0-9 \-()]")
_MAX_SHORT_TEXT = 500
_MAX_CHECK_LEN = 60


def esc(value):
    """Escape text for safe rendering, including quotes."""
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def norm_severity(value):
    text = str(value or "").lower().strip()
    return text if text in SEVERITIES else "low"


def norm_confidence(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return max(0.0, min(1.0, number))


def norm_line(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if isinstance(value, bool):
        return None
    return number if number >= 1 else None


def norm_check(value):
    text = str("" if value is None else value)[:_MAX_CHECK_LEN]
    if text in KNOWN_CHECKS:
        return text
    return _CHECK_SANITISE_RE.sub("", text).strip()


def norm_short_text(value):
    return str("" if value is None else value)[:_MAX_SHORT_TEXT]


def extract_balanced_json(content):
    """Return the first balanced {...} object in text, or None.

    String- and escape-aware: braces inside quoted strings do not
    change the depth, and an escaped quote does not end a string.
    """
    text = str(content or "")
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
    return None


def norm_finding(finding):
    """Validate one finding dict. Returns a clean dict, or None."""
    if not isinstance(finding, dict):
        return None
    verdict = finding.get("verdict")
    if verdict != "real" and verdict != "false_positive":
        return None
    return {
        "line": norm_line(finding.get("line")),
        "check": norm_check(finding.get("check")),
        "verdict": verdict,
        "severity": norm_severity(finding.get("severity")),
        "confidence": norm_confidence(finding.get("confidence")),
        "reason": norm_short_text(finding.get("reason")),
        "fix": norm_short_text(finding.get("fix")),
    }


def parse_triage(content):
    """Parse one model reply into a validated finding, or None.

    Returns None when no JSON can be extracted, when the JSON is not
    an object, or when the verdict is not exactly real or false_positive.
    A None here means no verdict, and the finding is NOT clean.
    """
    if not content:
        return None
    raw = extract_balanced_json(content)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("verdict") != "real" and data.get("verdict") != "false_positive":
        return None
    return {
        "verdict": data.get("verdict"),
        "severity": norm_severity(data.get("severity")),
        "confidence": norm_confidence(data.get("confidence")),
        "reason": norm_short_text(data.get("reason")),
        "fix": norm_short_text(data.get("fix")),
    }




# --- VerificationResult, Phase A1 (v0.5.0) -------------------------
# Shape adapted from 0sec-labs/0 VerificationResultSchema
# (https://github.com/0sec-labs/0, commit a891ba1, docs
# verification-result.md): statuses reproduced, not_reproduced,
# skipped, error, with declared assertions and hashed artifact
# descriptors. Written in Python from the shape, not copied.
# Rules enforced here, not in prose:
# - confirmed is true only when status is reproduced.
# - assertions must be non-empty when status is reproduced.
# - a PoC that did not run is skipped, never reproduced.
# - an unparsed PoC generation is an error, never a pass.

VERIFICATION_STATUSES = ["reproduced", "not_reproduced", "skipped", "error"]


def _norm_assertion(item):
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()[:200]
    if not name:
        return None
    passed = item.get("passed")
    if not isinstance(passed, bool):
        return None
    return {
        "name": name,
        "passed": passed,
        "detail": str(item.get("detail") or "")[:500],
    }


def _norm_artifact(item):
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()[:200]
    if not name:
        return None
    sha256 = str(item.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return None
    path = item.get("path")
    return {
        "name": name,
        "sha256": sha256,
        "path": str(path)[:500] if path is not None else None,
    }


def _norm_poc_run(item):
    """Validate one poc_before / poc_after object, or None."""
    if not isinstance(item, dict):
        return None
    command = item.get("command")
    if command is not None and (
        not isinstance(command, list)
        or not all(isinstance(tok, str) for tok in command)
    ):
        return None
    exit_code = item.get("exit_code")
    if exit_code is not None:
        try:
            exit_code = int(exit_code)
        except (TypeError, ValueError):
            return None
        if isinstance(item.get("exit_code"), bool):
            return None
    output_hash = item.get("output_hash")
    if output_hash is not None:
        output_hash = str(output_hash).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", output_hash):
            return None
    return {
        "command": list(command) if command is not None else None,
        "exit_code": exit_code,
        "output_hash": output_hash,
        "ran": bool(item.get("ran")),
    }


def _norm_cost_number(value):
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number < 0:
        return None
    return number


def norm_verification_result(result):
    """Validate one VerificationResult dict. Returns a clean dict, or None.

    confirmed is forced to (status == reproduced): a caller cannot
    set confirmed true on any other status. A reproduced result with
    empty assertions is invalid and returns None, because a
    confirmation with no evidence is not a confirmation.
    """
    if not isinstance(result, dict):
        return None
    status = result.get("status")
    if status not in VERIFICATION_STATUSES:
        return None
    assertions = result.get("assertions")
    if assertions is None:
        assertions = []
    if not isinstance(assertions, list):
        return None
    clean_assertions = []
    for item in assertions:
        clean = _norm_assertion(item)
        if clean is None:
            return None
        clean_assertions.append(clean)
    if status == "reproduced" and not clean_assertions:
        return None
    # A reproduced result needs every assertion to pass: a
    # confirmation with a failing assertion is not a
    # confirmation.
    if status == "reproduced" and not all(
        a["passed"] for a in clean_assertions
    ):
        return None
    artifacts = result.get("artifacts")
    if artifacts is None:
        artifacts = []
    if not isinstance(artifacts, list):
        return None
    clean_artifacts = []
    for item in artifacts:
        clean = _norm_artifact(item)
        if clean is None:
            return None
        clean_artifacts.append(clean)
    poc_before = _norm_poc_run(result.get("poc_before"))
    if poc_before is None:
        return None
    poc_after_raw = result.get("poc_after")
    poc_after = None
    if poc_after_raw is not None:
        poc_after = _norm_poc_run(poc_after_raw)
        if poc_after is None:
            return None
    usage = result.get("usage")
    if usage is None:
        usage = {}
    if not isinstance(usage, dict):
        return None
    clean_usage = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens",
                "reasoning_tokens"):
        value = usage.get(key)
        if value is None:
            continue
        try:
            clean_usage[key] = int(value)
        except (TypeError, ValueError):
            return None
        if isinstance(value, bool):
            return None
    finding_id = result.get("finding_id")
    if finding_id is not None:
        finding_id = str(finding_id)[:200]
    model = result.get("model")
    if model is not None:
        model = str(model)[:200]
    error = result.get("error")
    if error is not None:
        error = str(error)[:500]
    # Regression check: a false_positive finding verified as a
    # regression check is labelled, not confirmed, even when the
    # PoC reproduces. confirmed stays true only on reproduced,
    # and never on a regression check.
    regression_check = bool(result.get("regression_check"))
    patch_passed = result.get("patch_passed")
    if patch_passed is not None and not isinstance(patch_passed, bool):
        return None
    warning = result.get("warning")
    if warning is not None:
        warning = str(warning)[:500]
    poc = result.get("poc")
    if poc is not None:
        poc = str(poc)[:20000]
    return {
        "finding_id": finding_id,
        "status": status,
        # confirmed is derived, never taken from the caller.
        "confirmed": status == "reproduced" and not regression_check,
        "assertions": clean_assertions,
        "artifacts": clean_artifacts,
        "poc_before": poc_before,
        "poc_after": poc_after,
        "model": model,
        "usage": clean_usage,
        "cost_usd": _norm_cost_number(result.get("cost_usd")),
        "estimate_usd": _norm_cost_number(result.get("estimate_usd")),
        "unparsed": bool(result.get("unparsed")),
        "error": error,
        "regression_check": regression_check,
        "patch_passed": patch_passed,
        "warning": warning,
        "poc": poc,
    }
