"""Secret redaction before any text is sent to GMI Inference.

Every code snippet is scanned first. Values that look like keys,
tokens, or passwords are replaced with [REDACTED] and the redaction
is noted in the tool result. The raw snippet is never sent when a
secret-shaped value is present.
"""

import re

_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat_classic", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_pat_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_oauth_token", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "assigned_secret",
        re.compile(
            r"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|password|passwd|secret|private[_-]?key)"
            r"(\s*[:=]\s*)([\"'][^\"']+[\"']|[^\s,;]+)"
        ),
    ),
]

_REDACTED = "[REDACTED]"


def redact(text):
    """Redact secret-shaped values in text.

    Returns (redacted_text, redacted_count, pattern_names_hit).
    The count is the number of values replaced.
    """
    if text is None:
        return "", 0, []
    result = str(text)
    count = 0
    hits = []
    for name, pattern in _PATTERNS:
        if name == "assigned_secret":
            def _replace(match):
                return match.group(1) + match.group(2) + _REDACTED

            result, made = pattern.subn(_replace, result)
            if made:
                count += made
                hits.append(name)
        else:
            result, made = pattern.subn(_REDACTED, result)
            if made:
                count += made
                hits.append(name)
    return result, count, hits
