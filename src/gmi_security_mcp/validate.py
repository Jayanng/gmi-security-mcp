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
