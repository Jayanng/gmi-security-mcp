"""Unit tests for validate.py. No API calls."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import validate as v


def test_extract_balanced_json_basic():
    assert v.extract_balanced_json('prefix {"a": 1} suffix') == '{"a": 1}'


def test_extract_balanced_json_nested_and_escaped():
    text = 'x {"a": {"b": "} not a brace \\" still string"}, "c": 2} y'
    assert v.extract_balanced_json(text) == (
        '{"a": {"b": "} not a brace \\" still string"}, "c": 2}'
    )


def test_extract_balanced_json_trailing_brace_text():
    text = '{"verdict": "real"} some trailing } text'
    assert v.extract_balanced_json(text) == '{"verdict": "real"}'


def test_extract_balanced_json_none():
    assert v.extract_balanced_json("no json here") is None
    assert v.extract_balanced_json("") is None


def test_norm_finding_rejects_bad_verdict():
    assert v.norm_finding({"verdict": "not_real"}) is None
    assert v.norm_finding({"verdict": "real-ish"}) is None
    assert v.norm_finding({"verdict": "real"}) is not None


def test_norm_severity_allowlist():
    assert v.norm_severity("critical") == "critical"
    assert v.norm_severity("HIGH") == "high"
    assert v.norm_severity("low' onmouseover='alert(1)") == "low"
    assert v.norm_severity("banana") == "low"
    assert v.norm_severity(None) == "low"


def test_norm_confidence_clamp():
    assert v.norm_confidence(2) == 1
    assert v.norm_confidence(-1) == 0
    assert v.norm_confidence(0.5) == 0.5
    assert v.norm_confidence("nope") is None
    assert v.norm_confidence(None) is None


def test_norm_line():
    assert v.norm_line(3) == 3
    assert v.norm_line(0) is None
    assert v.norm_line(-2) is None
    assert v.norm_line("7") == 7
    assert v.norm_line("x") is None


def test_norm_short_text_caps_500():
    assert len(v.norm_short_text("x" * 600)) == 500
    assert v.norm_short_text(None) == ""


def test_norm_check_known_and_sanitised():
    assert v.norm_check("SQL injection") == "SQL injection"
    out = v.norm_check("SQL injection <script>alert(1)</script>")
    assert "<" not in out and ">" not in out
    assert len(v.norm_check("x" * 100)) <= 60


def test_parse_triage_valid_and_invalid():
    good = '{"verdict": "real", "severity": "critical", "confidence": 0.9, "reason": "r", "fix": "f"}'
    parsed = v.parse_triage("Here is the result: " + good)
    assert parsed and parsed["verdict"] == "real"
    assert parsed["severity"] == "critical"
    assert v.parse_triage('{"verdict": "real-ish"}') is None
    assert v.parse_triage("no json at all") is None
    assert v.parse_triage("") is None


def test_esc_quotes():
    assert v.esc('a"b\'c<d>&') == "a&quot;b&#39;c&lt;d&gt;&amp;"
