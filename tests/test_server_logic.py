"""Unit tests for the triage flow in server.py.

No API calls here. The chat function is replaced with a small local
stub so the validation, cap, escalation, and unparsed rules can be
tested without spending anything. Live behaviour is tested separately
in scripts/run-12-examples.py, which calls the real GMI API.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import server as srv

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
    "gmicloud/Ripple-65B-Preview": None,
}
# Drop the None entry: load_pricing skips unpriced models, so the stub
# pricing dict must not contain it either.
PRICING = {k: v for k, v in PRICING.items() if v is not None}

CHEAP = "google/gemini-3.5-flash-lite"
QWEN = "Qwen/Qwen3.8-Flash"

os.environ["GMI_API_KEY"] = "test-key-never-sent"


def _stub_reply(content, usage=None):
    def _call(model, system_content, user_content, max_tokens=2500):
        return {
            "content": content,
            "latency_seconds": 0.5,
            "usage": usage or {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    return _call


def _stub_error(message="HTTP 500: boom"):
    def _call(model, system_content, user_content, max_tokens=2500):
        return {
            "content": None,
            "latency_seconds": 0.5,
            "usage": {},
            "error": message,
            "retried": False,
            "timeout": False,
        }

    return _call


def _base(**over):
    args = {
        "finding": "Semgrep finding: SQL injection",
        "code": "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
        "stage1_model": CHEAP,
        "pricing": PRICING,
    }
    args.update(over)
    return args


def test_missing_model_refused_without_call():
    calls = []
    result = srv.triage_impl(
        **_base(stage1_model=None, chat_fn=lambda **k: calls.append(k))
    )
    assert result["verdict"] is None
    assert "required" in result["error"]
    assert calls == []


def test_unpriced_model_refused_without_call():
    calls = []
    result = srv.triage_impl(
        **_base(
            stage1_model="gmicloud/Ripple-65B-Preview",
            chat_fn=lambda **k: calls.append(k),
        )
    )
    assert result["verdict"] is None
    assert "no flat per-token pricing" in result["error"]
    assert calls == []


def test_cap_exceeded_refused_without_call():
    calls = []
    result = srv.triage_impl(
        **_base(spend_cap_usd=0.000001, chat_fn=lambda **k: calls.append(k))
    )
    assert result["verdict"] is None
    assert "exceeds the spend cap" in result["error"]
    assert calls == []


def test_cap_above_5_refused():
    result = srv.triage_impl(**_base(spend_cap_usd=6.0, chat_fn=_stub_reply("{}")))
    assert result["verdict"] is None
    assert "at most $5.00" in result["error"]


def test_bad_max_tokens_refused():
    result = srv.triage_impl(**_base(max_tokens=999, chat_fn=_stub_reply("{}")))
    assert result["verdict"] is None


def test_missing_key_refused_without_call():
    old = os.environ.pop("GMI_API_KEY", None)
    try:
        calls = []
        result = srv.triage_impl(
            **_base(chat_fn=lambda **k: calls.append(k))
        )
        assert result["verdict"] is None
        assert "GMI_API_KEY" in result["error"]
        assert calls == []
    finally:
        if old is not None:
            os.environ["GMI_API_KEY"] = old


def test_real_verdict_returned():
    reply = (
        '{"verdict": "real", "severity": "high", "confidence": 0.9, '
        '"reason": "Input reaches the sink.", "fix": "Use parameters."}'
    )
    result = srv.triage_impl(**_base(chat_fn=_stub_reply(reply)))
    assert result["verdict"] == "real"
    assert result["severity"] == "high"
    assert result["confidence"] == 0.9
    assert result["stage_used"] == "stage1"
    assert result["cost_usd"] is not None and result["cost_usd"] > 0
    assert result["estimate_usd"] is not None


def test_unparsed_returns_no_verdict_not_clean():
    result = srv.triage_impl(**_base(chat_fn=_stub_reply("I think this is fine.")))
    assert result["verdict"] is None
    assert result["unparsed"] is True
    assert "NOT clean" in result["error"]


def test_stage1_error_returns_no_verdict():
    result = srv.triage_impl(**_base(chat_fn=_stub_error()))
    assert result["verdict"] is None
    assert "Stage 1 call failed" in result["error"]


def test_low_confidence_escalates_to_stage2():
    calls = []

    def _call(model, system_content, user_content, max_tokens=2500):
        calls.append(model)
        if model == CHEAP:
            return {
                "content": '{"verdict": "real", "severity": "high", '
                '"confidence": 0.5, "reason": "Unsure.", "fix": "Check."}',
                "latency_seconds": 0.5,
                "usage": {"prompt_tokens": 200, "completion_tokens": 20},
                "error": None,
                "retried": False,
                "timeout": False,
            }
        return {
            "content": '{"verdict": "false_positive", "severity": "low", '
            '"confidence": 0.95, "reason": "Mitigated.", "fix": "None."}',
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(
        **_base(two_stage=True, stage2_model=QWEN, chat_fn=_call)
    )
    assert calls == [CHEAP, QWEN]
    assert result["verdict"] == "false_positive"
    assert result["stage_used"] == "stage2"
    assert result["escalated"] is True


def test_stage2_failure_keeps_stage1_verdict():
    def _call(model, system_content, user_content, max_tokens=2500):
        if model == CHEAP:
            return {
                "content": '{"verdict": "real", "severity": "high", '
                '"confidence": 0.5, "reason": "Unsure.", "fix": "Check."}',
                "latency_seconds": 0.5,
                "usage": {"prompt_tokens": 200, "completion_tokens": 20},
                "error": None,
                "retried": False,
                "timeout": False,
            }
        return {
            "content": None,
            "latency_seconds": 0.5,
            "usage": {},
            "error": "HTTP 500: boom",
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(
        **_base(two_stage=True, stage2_model=QWEN, chat_fn=_call)
    )
    assert result["verdict"] == "real"
    assert result["escalated"] is True
    assert result["escalation_failed"] is True


def test_secret_in_code_is_redacted_and_noted():
    reply = (
        '{"verdict": "real", "severity": "high", "confidence": 0.9, '
        '"reason": "Leaked key.", "fix": "Rotate it."}'
    )
    seen = {}

    def _call(model, system_content, user_content, max_tokens=2500):
        seen["user"] = user_content
        return {
            "content": reply,
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(
        **_base(code="api_key = 'AKIAIOSFODNN7EXAMPLE'", chat_fn=_call)
    )
    assert result["redacted"] is True
    assert result["redaction_count"] >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in seen["user"]
    assert "[REDACTED]" in seen["user"]


def test_estimate_cost_tool_no_key_needed():
    import json

    old = os.environ.pop("GMI_API_KEY", None)
    try:
        out = json.loads(srv.estimate_cost(CHEAP, 400))
        assert out["priced"] is True
        out2 = json.loads(srv.estimate_cost("gmicloud/Ripple-65B-Preview", 400))
        assert out2["priced"] is False
        assert out2["typical_usd"] is None
    finally:
        if old is not None:
            os.environ["GMI_API_KEY"] = old
