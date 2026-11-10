"""Unit tests for mcp_test._tool_json, the non-JSON tool-result guard.

No GMI calls here. The guard is the only thing that stands between
a server error (a tool returning plain text instead of JSON) and a
crash in the live test scripts: it reports the bad result and exits
with code 4 instead of raising json.JSONDecodeError uncaught.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import mcp_test as mcp_test_mod


def test_tool_json_valid_object_parses():
    assert mcp_test_mod._tool_json('{"verdict": "real", "cost_usd": 0.001}') == {
        "verdict": "real",
        "cost_usd": 0.001,
    }


def test_tool_json_valid_array_parses():
    assert mcp_test_mod._tool_json("[1, 2, 3]") == [1, 2, 3]


def test_tool_json_non_json_reports_and_exits_4(capsys):
    with pytest.raises(SystemExit) as exc:
        mcp_test_mod._tool_json("server exploded, not json at all")
    assert exc.value.code == 4
    err = capsys.readouterr().err
    assert "ERROR: tool returned non-JSON result" in err
    assert "server exploded" in err


def test_tool_json_empty_string_reports_and_exits_4(capsys):
    with pytest.raises(SystemExit) as exc:
        mcp_test_mod._tool_json("")
    assert exc.value.code == 4
    assert "non-JSON" in capsys.readouterr().err


def test_tool_json_truncates_long_non_json_result(capsys):
    with pytest.raises(SystemExit):
        mcp_test_mod._tool_json("x" * 2000)
    err = capsys.readouterr().err
    assert len(err) < 2000
    assert "x" * 500 in err


def test_tool_json_default_model_is_named_not_preselected_by_tools():
    """mcp-test defaults to one model for the test run only. The
    server tools still refuse until the caller names a model;
    the default lives in the test script, not in any tool."""
    assert mcp_test_mod.DEFAULT_MODEL == "google/gemini-3.5-flash-lite"
    import inspect

    from gmi_security_mcp import server as srv

    params = inspect.signature(srv.triage_semgrep_finding).parameters
    assert params["stage1_model"].default is None
