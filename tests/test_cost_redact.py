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


def test_redact_assigned_secret():
    text, count, hits = r.redact('api_key = "supersecretvalue"')
    assert "supersecretvalue" not in text and "[REDACTED]" in text
    assert "assigned_secret" in hits


def test_redact_clean_text_unchanged():
    text, count, hits = r.redact("SELECT * FROM users WHERE id = ?")
    assert text == "SELECT * FROM users WHERE id = ?"
    assert count == 0 and hits == []
