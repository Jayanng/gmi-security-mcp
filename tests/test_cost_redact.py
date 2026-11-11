"""Unit tests for cost.py and redact.py. No API calls."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import cost as c
from gmi_security_mcp import redact as r

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "free/model": (0.0, 0.0),
}


def test_load_pricing_from_repo_file():
    pricing = c.load_pricing()
    assert "google/gemini-3.5-flash-lite" in pricing
    assert pricing["google/gemini-3.5-flash-lite"] == (0.0000003, 0.0000025)
    assert "gmicloud/Ripple-65B-Preview" not in pricing
    # Floor, not an exact count: the live model list rotates.
    # Re-checked 2026-11-10 before the v0.5.0 release, the file
    # holds 73 models, 72 priced (Ripple is unpriced), down from
    # 80. A file with fewer than 70 priced models would mean the
    # pricing data is truncated, not rotated.
    assert len(pricing) >= 70


def test_estimate_prompt_tokens():
    assert c.estimate_prompt_tokens("") == 150
    assert c.estimate_prompt_tokens("x" * 400) == 250


def test_typical_and_max_cost():
    typical = c.typical_cost_usd(
        "google/gemini-3.5-flash-lite", "x" * 400, 2500, pricing=PRICING
    )
    assert typical == 250 * 0.0000003 + 250 * 0.0000025
    maximum = c.max_cost_usd(
        "google/gemini-3.5-flash-lite", "x" * 400, 2500, pricing=PRICING
    )
    assert maximum == 250 * 0.0000003 + 2500 * 0.0000025
    assert maximum > typical


def test_unpriced_model_returns_none():
    assert (
        c.typical_cost_usd("gmicloud/Ripple-65B-Preview", "x", 2500, pricing=PRICING)
        is None
    )
    assert (
        c.max_cost_usd("gmicloud/Ripple-65B-Preview", "x", 2500, pricing=PRICING)
        is None
    )
    assert c.estimate_cost("gmicloud/Ripple-65B-Preview", 100, 2500, 1, pricing=PRICING)[
        "priced"
    ] is False


def test_unknown_model_returns_none():
    assert c.typical_cost_usd("nope/model", "x", 2500, pricing=PRICING) is None


def test_estimate_cost_shape():
    out = c.estimate_cost(
        "google/gemini-3.5-flash-lite", 400, 2500, 1, pricing=PRICING
    )
    assert out["priced"] is True
    assert out["typical_usd"] is not None and out["max_usd"] is not None
    assert out["prompt_tokens_estimate"] == 250


def test_safe_upper_bound():
    bound = c.safe_upper_bound_usd(
        "google/gemini-3.5-flash-lite", 1, pricing=PRICING
    )
    assert bound == 250 * 0.0000003 + 2500 * 0.0000025


def test_cost_from_usage():
    usage = {"prompt_tokens": 1000, "completion_tokens": 10}
    assert c.cost_from_usage(
        usage, "google/gemini-3.5-flash-lite", pricing=PRICING
    ) == 1000 * 0.0000003 + 10 * 0.0000025
    assert c.cost_from_usage({}, "google/gemini-3.5-flash-lite", pricing=PRICING) == 0.0


def test_redact_aws_key():
    text, count, hits = r.redact("key = AKIAIOSFODNN7EXAMPLE here")
    assert "[REDACTED]" in text and "AKIAIOSFODNN7EXAMPLE" not in text
    assert count == 1 and "aws_access_key" in hits


def test_redact_github_pat():
    text, count, hits = r.redact("token ghp_" + "a" * 36 + " end")
    assert "ghp_" not in text and count == 1
    assert "github_pat_classic" in hits


def test_redact_bearer_assigned_double_count():
    """v0.5.6: api_key = "Bearer <token>" counted 2 before this
    fix (bearer_token, then assigned_secret on the already
    redacted value). One secret value must count once."""
    text, count, hits = r.redact(
        'api_key = "Bearer abcdefghij1234567890"'
    )
    assert count == 1
    assert hits == ["bearer_token"]
    assert text == 'api_key = "Bearer [REDACTED]"'


def test_redact_value_containing_redacted_word_still_redacted():
    """Audit follow-up: the already-redacted skip is exact,
    not a substring test. A real secret that merely contains
    the word [REDACTED] inside a longer value is still
    redacted, not left through."""
    text, count, hits = r.redact('api_key = "abc[REDACTED]def"')
    assert count == 1
    assert "assigned_secret" in hits
    assert "abc[REDACTED]def" not in text


def test_redact_assigned_secret():
    text, count, hits = r.redact('api_key = "supersecretvalue"')
    assert "supersecretvalue" not in text and "[REDACTED]" in text
    assert "assigned_secret" in hits


def test_redact_clean_text_unchanged():
    text, count, hits = r.redact("SELECT * FROM users WHERE id = ?")
    assert text == "SELECT * FROM users WHERE id = ?"
    assert count == 0 and hits == []


def test_redact_bearer_token():
    """v0.5.4: Authorization Bearer tokens are redacted.

    Deterministic proof before the fix: redact() returned
    0 hits for 'Authorization: Bearer <token>', so a real
    bearer token in audited code would have been sent to
    the model. The scheme word stays, the token is replaced.
    """
    text, count, hits = r.redact(
        'headers = {"Authorization": "Bearer abcdef1234567890XYZ"}'
    )
    assert count == 1
    assert "bearer_token" in hits
    assert "abcdef1234567890XYZ" not in text
    assert "Bearer [REDACTED]" in text


def test_redact_bearer_short_value_not_flagged():
    # A short Bearer value is a placeholder or word, not a
    # credential: do not redact it and break the finding text.
    text, count, _hits = r.redact("Bearer short")
    assert count == 0
    assert text == "Bearer short"


# jwt.io public example token: shape-identical to a real JWT,
# a public test vector, not a secret. Used so the tests prove
# the shape rule without holding a real credential.
JWT_IO_EXAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_redact_bare_jwt():
    """v0.5.6 gap 5(a): a bare JWT was not redacted before this fix.

    Deterministic proof: redact() returned 0 hits for a JWT
    assigned to plain "token" (assigned_secret needs a key name
    like api_key, and plain token is not one) and for a bare
    JWT with no key name at all. A JWT is a credential, so the
    narrow eyJ three-segment rule redacts it, keeping the
    surrounding code.
    """
    text, count, hits = r.redact('token = "%s"' % JWT_IO_EXAMPLE)
    assert count == 1
    assert hits == ["jwt_token"]
    assert JWT_IO_EXAMPLE not in text
    assert 'token = "[REDACTED]"' in text
    text, count, hits = r.redact("auth = %s" % JWT_IO_EXAMPLE)
    assert count == 1
    assert "jwt_token" in hits
    assert JWT_IO_EXAMPLE not in text


def test_redact_bearer_jwt_single_count():
    """A Bearer JWT is redacted once, by bearer_token, not twice.

    jwt_token runs after bearer_token in the pattern order, so
    by the time it runs the token is already [REDACTED] and
    there is nothing left for it to count.
    """
    text, count, hits = r.redact(
        'headers = {"Authorization": "Bearer %s"}' % JWT_IO_EXAMPLE
    )
    assert count == 1
    assert hits == ["bearer_token"]
    assert JWT_IO_EXAMPLE not in text
    assert "Bearer [REDACTED]" in text


def test_redact_assigned_jwt_single_count():
    """A JWT assigned to api_key is redacted once, by assigned_secret."""
    text, count, hits = r.redact('api_key = "%s"' % JWT_IO_EXAMPLE)
    assert count == 1
    assert hits == ["assigned_secret"]
    assert JWT_IO_EXAMPLE not in text


def test_redact_jwt_short_or_fragment_not_flagged():
    """The JWT rule is narrow: short dotted words and a
    header-only fragment (no dots, just the eyJ header) are not
    credentials and are left alone, so the count stays exact."""
    text, count, _hits = r.redact("host = eyJ.example.com")
    assert count == 0
    assert text == "host = eyJ.example.com"
    text, count, _hits = r.redact("header = eyJhbGciOiJIUzI1NiJ9")
    assert count == 0
    assert text == "header = eyJhbGciOiJIUzI1NiJ9"


def test_redact_bare_hex_and_base64_not_redacted():
    """v0.5.6 gap 5(a), wont-do half: bare high-entropy literals
    with no secret shape are NOT redacted, by design.

    A 40-char hex value is a git SHA-1, a 64-char hex value is
    a SHA-256 digest (PoC output hashes are sha256 hex, and the
    oracles read them), a colon-hex value is a host-key
    fingerprint, and a bare base64 value is often a nonce or
    id. With no key name and no distinctive shape they cannot
    be told apart from a public hash or identifier, so
    redacting them would destroy evidence. Secret-shaped
    values are still caught by their prefix (AKIA, ghp_, sk-)
    or by an assigned key name.
    """
    import hashlib

    sha1 = hashlib.sha1(b"x").hexdigest()
    sha256 = hashlib.sha256(b"x").hexdigest()
    text, count, hits = r.redact(
        'commit = "%s"\ndigest = "%s"\n'
        'seen = "b9:4d:1a:2c:3d:4e:5f:6a:7b:8c:9d:0e:1f:2a:3b:4c"\n'
        'value = "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1u"\n' % (sha1, sha256)
    )
    assert count == 0 and hits == []
    assert sha1 in text and sha256 in text
    assert "b9:4d:1a:2c" in text
    assert "MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1u" in text
