"""Unit tests for the unparsed retry and reasoning-model warning.

No API calls. The chat function is a stub.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import server as srv

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
    "deepseek-ai/DeepSeek-R1": (0.000000500, 0.000002000),
}
CHEAP = "google/gemini-3.5-flash-lite"
QWEN = "Qwen/Qwen3.8-Flash"
R1 = "deepseek-ai/DeepSeek-R1"

os.environ["GMI_API_KEY"] = "test-key-never-sent"

GOOD = (
    '{"verdict": "real", "severity": "high", "confidence": 0.9, '
    '"reason": "Input reaches the sink.", "fix": "Use parameters."}'
)


def _base(**over):
    args = {
        "finding": "Semgrep finding: SQL injection",
        "code": "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
        "stage1_model": CHEAP,
        "pricing": PRICING,
    }
    args.update(over)
    return args


def test_unparsed_retries_once_with_shorter_prompt_then_parses():
    calls = []
    long_code = "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"\n" * 200

    def _call(model, system_content, user_content, max_tokens=2500):
        calls.append(len(user_content))
        content = "not json" if len(calls) == 1 else GOOD
        return {
            "content": content,
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(**_base(code=long_code, chat_fn=_call))
    assert len(calls) == 2
    assert calls[1] < calls[0]
    assert result["verdict"] == "real"
    assert result["retried_unparsed"] is True
    assert result["unparsed"] is False


def test_unparsed_twice_returns_no_verdict():
    def _call(model, system_content, user_content, max_tokens=2500):
        return {
            "content": "still not json",
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(**_base(chat_fn=_call))
    assert result["verdict"] is None
    assert result["unparsed"] is True
    assert result["retried_unparsed"] is True


def test_reasoning_model_gets_no_unparsed_retry():
    calls = []

    def _call(model, system_content, user_content, max_tokens=2500):
        calls.append(model)
        return {
            "content": "not json",
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(**_base(stage1_model=R1, chat_fn=_call))
    assert calls == [R1]
    assert result["retried_unparsed"] is False
    assert result["unparsed"] is True


def test_reasoning_model_warns_on_large_input():
    big_code = "x = 1  # padding\n" * 1500

    def _call(model, system_content, user_content, max_tokens=2500):
        return {
            "content": GOOD,
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 4000, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(
        **_base(stage1_model=R1, code=big_code, chat_fn=_call)
    )
    assert result["verdict"] == "real"
    assert result["reasoning_model_warning"]
    assert "DeepSeek-R1" in result["reasoning_model_warning"]


def test_reasoning_model_no_warning_on_small_input():
    def _call(model, system_content, user_content, max_tokens=2500):
        return {
            "content": GOOD,
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.triage_impl(
        **_base(stage1_model=R1, chat_fn=_call)
    )
    assert result["reasoning_model_warning"] is None


def test_two_stage_unparsed_escalates_instead_of_retry():
    calls = []

    def _call(model, system_content, user_content, max_tokens=2500):
        calls.append(model)
        if model == CHEAP:
            return {
                "content": "not json",
                "latency_seconds": 0.5,
                "usage": {"prompt_tokens": 200, "completion_tokens": 20},
                "error": None,
                "retried": False,
                "timeout": False,
            }
        return {
            "content": GOOD,
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
    assert result["verdict"] == "real"
    assert result["stage_used"] == "stage2"
    assert result["retried_unparsed"] is False
