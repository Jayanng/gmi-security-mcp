"""Secret redaction before any text is sent to GMI Inference.

Every code snippet is scanned first. Values that look like keys,
tokens, or passwords are replaced with [REDACTED] and the redaction
is noted in the tool result. The raw snippet is never sent when a
secret-shaped value is present. Bare JWTs are redacted too
(v0.5.6, narrow eyJ three-segment rule); bare high-entropy
literals with no secret shape are not, they cannot be told
apart from a public hash or id.
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
    # v0.5.4: Bearer tokens were not redacted. The assigned_secret
    # pattern needs a key name like api_key or password, so
    # "Authorization: Bearer <token>" passed through with 0 hits
    # in a deterministic check, and a real bearer token in audited
    # code would have been sent to the model. Bearer tokens are
    # credentials, redact the token, keep the scheme word.
    (
        "bearer_token",
        re.compile(
            r"(?i)(Bearer\s+)([A-Za-z0-9\-._~+/=]{10,})"
        ),
    ),
    (
        "assigned_secret",
        re.compile(
            r"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|password|passwd|secret|private[_-]?key)"
            r"(\s*[:=]\s*)([\"'][^\"']+[\"']|[^\s,;]+)"
        ),
    ),
    # v0.5.6: bare JWTs were not redacted. Bearer fixed the
    # "Authorization: Bearer <token>" case in v0.5.4, but a JWT
    # sitting bare in code, for example token = "eyJ...", passed
    # through with 0 hits: the assigned_secret pattern needs a
    # key name, and plain "token" is not one. A JWT is a
    # credential, so it is redacted. The rule is narrow on
    # purpose: the first segment must start eyJ (base64url of
    # '{"'), there must be exactly the two dots of a three
    # segment JWT, the match must start a token (not inside a
    # longer base64 run), and the match must be at least 20
    # characters, so a header-only fragment or a short dotted
    # word is left alone. Bare high-entropy literals with no
    # JWT shape, a 40-char hex git SHA, a 64-char hex digest,
    # a colon-hex fingerprint, a bare base64 value, are NOT
    # redacted by this rule: with no key name and no shape
    # they cannot be told apart from a public hash or id, and
    # redacting them would destroy evidence the oracles read
    # (PoC output hashes are sha256 hex). See DECISIONS.md
    # section 27.
    (
        "jwt_token",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*"
            r"\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
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
        if name == "bearer_token":
            def _replace_bearer(match):
                return match.group(1) + _REDACTED

            result, made = pattern.subn(_replace_bearer, result)
            if made:
                count += made
                hits.append(name)
        elif name == "assigned_secret":
            # A value already replaced by an earlier pattern
            # (e.g. Bearer) is exactly "[REDACTED]" once quotes
            # are stripped, and must not be counted a second
            # time: the secret was one value, so the count must
            # stay 1. The test is exact, not a substring test:
            # a real secret that merely contains the word
            # [REDACTED] inside a longer value is still
            # redacted. subn counts even a replacement that
            # returns the text unchanged, so count from the
            # replace callback instead.
            made = []

            def _replace(match):
                value = match.group(3).strip("\"'")
                if value.removeprefix("Bearer ") == _REDACTED:
                    return match.group(0)
                made.append(1)
                return match.group(1) + match.group(2) + _REDACTED

            result = pattern.sub(_replace, result)
            if made:
                count += len(made)
                hits.append(name)
        elif name == "jwt_token":
            # Only a JWT-shaped match of 20 characters or more
            # is a credential. A short dotted word or a header
            # fragment is left alone, and the count must reflect
            # only values actually replaced, so short matches
            # return unchanged and are not counted.
            made = []

            def _replace_jwt(match):
                if len(match.group(0)) >= 20:
                    made.append(1)
                    return _REDACTED
                return match.group(0)

            result = pattern.sub(_replace_jwt, result)
            if made:
                count += len(made)
                hits.append(name)
        else:
            result, made = pattern.subn(_REDACTED, result)
            if made:
                count += made
                hits.append(name)
    return result, count, hits
