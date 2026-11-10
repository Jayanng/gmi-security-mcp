"""Unit tests for the scope plugin, Phase A3. No GMI calls.

Covers scope-file parsing, hostname and CIDR matching,
exclusion-wins, empty-allowlist denies-all, IPv6 refusal,
explicit-enable-only, the --allow-apply double gate, the
--require-scope fail-closed gate, and the Docker-unavailable
refusal. The live-target matching is tested at the module level:
in v0.5.0 there is no live web tool, so scope is a repo-path and
PoC boundary, and the tools below enforce that.
"""

import inspect
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import scope as scope_mod  # noqa: E402
from gmi_security_mcp import server as srv  # noqa: E402
from gmi_security_mcp import verify as verify_mod  # noqa: E402

os.environ["GMI_API_KEY"] = "test-key-never-sent"


@pytest.fixture(autouse=True)
def _reset_scope(monkeypatch):
    """Scope state is process-level: reset it for every test."""
    scope_mod.clear_scope_state()
    scope_mod.set_require_scope(False)
    scope_mod.set_allow_apply(False)
    scope_mod.set_profile("standard")
    monkeypatch.delenv("GMI_REQUIRE_SCOPE", raising=False)
    monkeypatch.delenv("GMI_ALLOW_APPLY", raising=False)
    yield
    scope_mod.clear_scope_state()
    scope_mod.set_require_scope(False)
    scope_mod.set_allow_apply(False)
    scope_mod.set_profile("standard")


def _write_scope(tmp_path, in_scope, out_of_scope):
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({"in_scope": in_scope, "out_of_scope": out_of_scope})
    )
    return path


def _policy(tmp_path, in_scope, out_of_scope):
    path = _write_scope(tmp_path, in_scope, out_of_scope)
    policy, error = scope_mod.parse_scope_file(str(path))
    assert error is None
    return policy


def test_scope_in_scope_hostname_passes(tmp_path):
    policy = _policy(tmp_path, ["example.com"], [])
    assert scope_mod.is_allowed(policy, "example.com") is True


def test_scope_hostname_is_case_insensitive(tmp_path):
    policy = _policy(tmp_path, ["Example.COM"], [])
    assert scope_mod.is_allowed(policy, "EXAMPLE.com") is True


def test_scope_out_of_scope_hostname_refused(tmp_path):
    policy = _policy(tmp_path, ["example.com"], ["bad.example.com"])
    assert scope_mod.is_allowed(policy, "bad.example.com") is False
    assert scope_mod.is_allowed(policy, "example.com") is True


def test_scope_exclusion_wins_over_inclusion(tmp_path):
    policy = _policy(
        tmp_path, ["*.example.com"], ["secret.example.com"]
    )
    assert scope_mod.is_allowed(policy, "secret.example.com") is False
    assert scope_mod.is_allowed(policy, "other.example.com") is True


def test_scope_empty_allowlist_denies_all(tmp_path):
    policy = _policy(tmp_path, [], [])
    assert scope_mod.is_allowed(policy, "example.com") is False
    assert scope_mod.is_allowed(policy, "anything.example") is False


def test_scope_ipv4_cidr_in_scope_passes(tmp_path):
    policy = _policy(tmp_path, ["10.0.0.0/8"], [])
    assert scope_mod.is_allowed(policy, "10.1.2.3") is True
    assert scope_mod.is_allowed(policy, "192.168.1.1") is False


def test_scope_ipv6_cidr_refused_with_clear_message(tmp_path):
    path = _write_scope(tmp_path, ["2001:db8::/32"], [])
    policy, error = scope_mod.parse_scope_file(str(path))
    assert policy is None
    assert error is not None
    assert "IPv6" in error


def test_scope_host_with_port_refused_plainly_not_as_ipv6(tmp_path):
    """A scope entry with a port (example.com:443) is refused with
    a plain port message, not the misleading IPv6 message: an
    exact-host rule already allows any port, so the fix is to
    drop the port."""
    path = _write_scope(tmp_path, ["example.com:443"], [])
    policy, error = scope_mod.parse_scope_file(str(path))
    assert policy is None
    assert error is not None
    assert "IPv6" not in error
    assert "port" in error.lower()
    assert "example.com" in error
    assert "without the port" in error


def test_scope_wildcard_matches_subdomains_only(tmp_path):
    policy = _policy(tmp_path, ["*.example.com"], [])
    assert scope_mod.is_allowed(policy, "api.example.com") is True
    assert scope_mod.is_allowed(policy, "example.com") is False
    assert scope_mod.is_allowed(policy, "notexample.com") is False


def test_scope_exact_host_allows_any_path_and_port(tmp_path):
    policy = _policy(tmp_path, ["example.com"], [])
    assert scope_mod.is_allowed(policy, "https://example.com/admin") is True
    assert scope_mod.is_allowed(policy, "example.com:8443") is True
    assert scope_mod.is_allowed(
        policy, "https://example.com:8443/a/b?x=1"
    ) is True


def test_scope_file_alone_does_not_activate_checks(tmp_path):
    """A scope file on disk activates nothing. Only scope_enable
    does, and only then does --require-scope refuse."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_scope(tmp_path, ["example.com"], [])
    scope_mod.set_require_scope(True)
    assert scope_mod.is_scope_enabled(str(repo)) is False
    assert scope_mod.check_repo_scope(str(repo)) is not None
    assert "scope_enable" in scope_mod.check_repo_scope(str(repo))


def test_scope_enable_and_disable(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope_file = _write_scope(
        tmp_path, ["example.com"], ["bad.example.com"]
    )
    result, error = scope_mod.enable_scope(str(scope_file), str(repo))
    assert error is None
    assert result["enabled"] is True
    assert result["in_scope"] == ["example.com"]
    assert result["out_of_scope"] == ["bad.example.com"]
    assert "not authorisation" in result["warning"]
    assert scope_mod.is_scope_enabled(str(repo)) is True
    scope_mod.set_require_scope(True)
    assert scope_mod.check_repo_scope(str(repo)) is None
    result, error = scope_mod.disable_scope(str(repo))
    assert error is None
    assert result["enabled"] is False
    assert "refuse" in result["warning"]
    assert scope_mod.is_scope_enabled(str(repo)) is False
    assert scope_mod.check_repo_scope(str(repo)) is not None


def test_scope_enable_tools_mockllm(tmp_path):
    """scope_enable and scope_disable as MCP tools."""
    repo = tmp_path / "repo"
    repo.mkdir()
    scope_file = _write_scope(tmp_path, ["example.com"], [])
    enabled = json.loads(
        srv.scope_enable(scope_file=str(scope_file), repo_path=str(repo))
    )
    assert enabled["error"] is None
    assert enabled["enabled"] is True
    assert enabled["in_scope"] == ["example.com"]
    disabled = json.loads(srv.scope_disable(repo_path=str(repo)))
    assert disabled["error"] is None
    assert disabled["enabled"] is False


def test_scope_enable_refuses_ipv6_scope_file(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    scope_file = _write_scope(tmp_path, ["2001:db8::/32"], [])
    result = json.loads(
        srv.scope_enable(scope_file=str(scope_file), repo_path=str(repo))
    )
    assert result["error"] is not None
    assert "IPv6" in result["error"]
    assert scope_mod.is_scope_enabled(str(repo)) is False


def test_require_scope_refuses_repo_scan_without_policy(tmp_path):
    """With --require-scope set, repo_scan refuses a repo with no
    enabled scope policy, and makes no GMI call."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    calls = []

    def _chat(*args, **kwargs):
        calls.append(1)
        raise AssertionError("no GMI call may happen on refusal")

    scope_mod.set_require_scope(True)
    result = srv.repo_scan_impl(
        repo_path=str(repo),
        stage1_model="google/gemini-3.5-flash-lite",
        stage2_model="Qwen/Qwen3.8-Flash",
        pricing={
            "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
            "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
        },
        chat_fn=_chat,
    )
    assert calls == []
    assert any(
        "--require-scope" in err for err in result["errors"]
    )


def test_require_scope_env_flag_refuses_verify(tmp_path, monkeypatch):
    """GMI_REQUIRE_SCOPE=1 refuses verify_finding with no policy."""
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("GMI_REQUIRE_SCOPE", "1")
    result = srv.verify_impl(
        finding={
            "verdict": "real",
            "severity": "high",
            "confidence": 0.9,
            "reason": "x",
            "fix": "y",
            "check": "Path traversal",
        },
        repo_path=str(repo),
        poc="print('x')",
    )
    assert result["status"] == "error"
    assert "--require-scope" in (result.get("error") or "")


def test_allow_apply_double_gate_draft_write(tmp_path, monkeypatch):
    """A disclosure write without --allow-apply is refused and no
    file is created. With --allow-apply and the exact write_path
    in the call, the draft is written."""
    target = tmp_path / "draft.md"
    finding = {
        "verdict": "real",
        "severity": "medium",
        "confidence": 0.9,
        "reason": "SSH client accepts any host key.",
        "fix": "Verify the host key against known_hosts.",
        "check": "Missing SSH host key verification",
        "file": "src/services/ssh-connection-manager.ts",
        "line": 1710,
    }
    refused = json.loads(
        srv.draft_private_disclosure(
            finding=finding,
            repo="classfang/ssh-mcp-server",
            write_path=str(target),
        )
    )
    assert refused["error"] is not None
    assert "--allow-apply" in refused["error"]
    assert refused["written_to"] is None
    assert not target.exists()

    scope_mod.set_allow_apply(True)
    written = json.loads(
        srv.draft_private_disclosure(
            finding=finding,
            repo="classfang/ssh-mcp-server",
            write_path=str(target),
        )
    )
    assert written["error"] is None
    assert written["written_to"] == str(target)
    assert target.exists()
    assert "host key" in target.read_text().lower()


def test_allow_apply_double_gate_verify_fix_candidate(tmp_path):
    """verify_finding with a fix candidate needs --allow-apply."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "vuln.py"
    target.write_text("x = 1\n")
    finding = {
        "verdict": "real",
        "severity": "medium",
        "confidence": 0.9,
        "reason": "Path traversal.",
        "fix": "Check the base directory.",
        "check": "Path traversal",
    }
    refused = json.loads(
        srv.verify_finding(
            finding=finding,
            repo_path=str(repo),
            poc="print('x')",
            fix_candidate={"path": "vuln.py", "content": "x = 2\n"},
        )
    )
    assert refused["status"] == "error"
    assert "--allow-apply" in (refused.get("error") or "")

    scope_mod.set_allow_apply(True)
    passed = json.loads(
        srv.verify_finding(
            finding=finding,
            repo_path=str(repo),
            poc="print('x')",
            fix_candidate={"path": "vuln.py", "content": "x = 2\n"},
        )
    )
    assert "--allow-apply" not in (passed.get("error") or "")


def test_allow_apply_double_gate_repo_scan_write(tmp_path):
    """repo_scan with write_report needs --allow-apply."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    refused = json.loads(
        srv.repo_scan(
            repo_path=str(repo),
            stage1_model="google/gemini-3.5-flash-lite",
            stage2_model="Qwen/Qwen3.8-Flash",
            write_report=str(tmp_path / "report.md"),
        )
    )
    assert any(
        "--allow-apply" in err for err in refused.get("errors") or []
    )
    assert not (tmp_path / "report.md").exists()


def test_allow_apply_cannot_be_granted_by_workflow_json():
    """The tools take no allow_apply parameter: a flag inside
    portable workflow JSON cannot grant the double gate. Only the
    server command line or the environment can."""
    for fn in (
        srv.draft_private_disclosure,
        srv.verify_finding,
        srv.repo_scan,
    ):
        assert "allow_apply" not in inspect.signature(fn).parameters
    assert scope_mod.allow_apply_enabled() is False


def test_allow_apply_env_flag_grants_it(monkeypatch):
    monkeypatch.setenv("GMI_ALLOW_APPLY", "1")
    assert scope_mod.allow_apply_enabled() is True


def test_docker_unavailable_refuses_never_silently_chooses_host(tmp_path):
    """executor docker with no Docker refuses clearly and never
    falls back to the host."""
    repo = tmp_path / "repo"
    repo.mkdir()
    result = verify_mod.run_poc(
        ["echo", "hi"],
        str(repo),
        executor="docker",
        docker_available=False,
    )
    assert result["ran"] is False
    assert "Docker is not available" in (result.get("error") or "")
    assert "Refusing" in (result.get("error") or "")


def test_engagement_profiles_rate_limits():
    """Standard 5 rps (0.2 s), conservative 1 rps (1.0 s)."""
    assert scope_mod.rate_limit_interval("standard") == 0.2
    assert scope_mod.rate_limit_interval("conservative") == 1.0
    assert scope_mod.rate_limit_interval("nope") is None
    assert scope_mod.set_profile("conservative") is None
    assert scope_mod.get_profile() == "conservative"
    assert scope_mod.set_profile("nope") is not None
    assert scope_mod.get_profile() == "conservative"


def test_rate_limiter_full_jitter_no_sleep_on_first_call():
    """The limiter waits after a call, with jitter, and never
    sleeps before the first call. Fake clock, no real sleeping."""
    now = [1000.0]
    slept = []

    def _time():
        return now[0]

    def _sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    limiter = scope_mod.RateLimiter(
        0.2, time_fn=_time, sleep_fn=_sleep, random_fn=lambda a, b: 0.1
    )
    assert limiter.wait_before_call() == 0.0
    assert slept == []
    now[0] += 0.01
    waited = limiter.wait_before_call()
    assert waited > 0
    assert waited <= 0.4
    assert len(slept) == 1


def test_scope_invalid_file_errors(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    missing = tmp_path / "nope.json"
    result, error = scope_mod.enable_scope(str(missing), str(repo))
    assert result is None
    assert "does not exist" in error
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    result, error = scope_mod.enable_scope(str(bad), str(repo))
    assert result is None
    assert "does not parse" in error
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"in_scope": "example.com"}))
    result, error = scope_mod.enable_scope(str(wrong), str(repo))
    assert result is None
    assert "must be arrays" in error
