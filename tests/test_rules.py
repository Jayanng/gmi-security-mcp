"""Unit tests for the custom semgrep rules pack, Phase A3.

No GMI calls. The rule fixture tests run the real semgrep binary
(1.184.0) against the vulnerable and fixed fixtures in rules/.
The MockLLM repo_scan test uses stub runners and a stub chat
function, labelled mockllm in the test name.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import rules as rules_mod  # noqa: E402
from gmi_security_mcp import scanners as scanners_mod  # noqa: E402
from gmi_security_mcp import server as srv  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
FIXTURES = RULES_DIR / "fixtures"

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
}
CHEAP = "google/gemini-3.5-flash-lite"
QWEN = "Qwen/Qwen3.8-Flash"

os.environ["GMI_API_KEY"] = "test-key-never-sent"


def _semgrep_binary():
    """Semgrep binary for the fixture tests, or None to skip."""
    env = os.environ.get("SEMGREP_BINARY", "").strip()
    if env and shutil.which(env):
        return env
    found = shutil.which("semgrep")
    if found:
        return found
    scratch = (
        Path.home() / "workspace" / "gmi-clouder" / ".scratch"
        / "scanner-venv" / "bin" / "semgrep"
    )
    if scratch.is_file():
        return str(scratch)
    return None


SEMGREP = _semgrep_binary()


def _run_rule(rule_file, *targets):
    """Run one rule file on target files. Returns (hits, errors).

    Hits are (rule_id, path, line) with the config prefix stripped.
    """
    import subprocess

    proc = subprocess.run(
        [SEMGREP, "scan", "--config", str(rule_file), "--json",
         "--quiet"] + [str(t) for t in targets],
        capture_output=True, text=True, timeout=300,
    )
    data = json.loads(proc.stdout)
    hits = [
        (
            rules_mod.strip_rule_prefix(item.get("check_id")),
            item.get("path"),
            (item.get("start") or {}).get("line"),
        )
        for item in data.get("results") or []
    ]
    return hits, data.get("errors") or []


@pytest.mark.skipif(SEMGREP is None, reason="semgrep binary not found")
def test_rules_registry_matches_yaml():
    """Every registry entry has a YAML file with the same id."""
    rules, error = rules_mod.load_rules(RULES_DIR)
    assert error is None
    assert len(rules) == 8
    for entry in rules:
        assert entry["id"] in rules_mod.RULE_IDS
        assert entry["enabled"] is True
        assert entry["category"]
        assert entry["severity"] in ("WARNING", "ERROR")
        assert entry["description"]


def test_list_rules_returns_8_rules_mockllm():
    """list_rules returns all 8 rules, no GMI call."""
    result = srv.list_rules_impl()
    assert result["error"] is None
    assert len(result["rules"]) == 8
    ids = [rule["id"] for rule in result["rules"]]
    assert ids == list(rules_mod.RULE_IDS)
    for rule in result["rules"]:
        assert rule["enabled"] is True
        assert rule["category"]
        assert rule["severity"]
        assert rule["description"]


def test_list_rules_category_filter_mockllm():
    result = srv.list_rules_impl(category="SQL injection")
    assert result["error"] is None
    assert [r["id"] for r in result["rules"]] == [
        "custom.sqli-user-input-to-query"
    ]
    bad = srv.list_rules_impl(category="No such check")
    assert bad["error"] is not None
    assert bad["rules"] == []


def test_map_rule_to_check_custom_rules():
    """Custom rule ids map to their checks, with or without prefix."""
    assert scanners_mod.map_rule_to_check(
        "custom.ssh-missing-host-key-verification"
    ) == "Missing SSH host key verification"
    assert scanners_mod.map_rule_to_check(
        "rules.custom.ssh-missing-host-key-verification"
    ) == "Missing SSH host key verification"
    assert scanners_mod.map_rule_to_check(
        "custom.missing-auth"
    ) == "Authentication and session flaws"
    assert scanners_mod.map_rule_to_check(
        "custom.missing-crypto-verification"
    ) == "Weak cryptography"
    assert scanners_mod.map_rule_to_check(
        "custom.hardcoded-secret"
    ) == "Hardcoded secrets"
    assert scanners_mod.map_rule_to_check(
        "custom.ssrf-user-input-to-fetch"
    ) == "Server-side request forgery (SSRF)"
    assert scanners_mod.map_rule_to_check(
        "custom.path-traversal-user-input-to-file"
    ) == "Path traversal"
    assert scanners_mod.map_rule_to_check(
        "custom.sqli-user-input-to-query"
    ) == "SQL injection"
    assert scanners_mod.map_rule_to_check(
        "custom.xss-user-input-to-html-sink"
    ) == "Cross-site scripting (XSS)"


# (rule file, rule id, vulnerable fixtures, fixed fixtures)
RULE_CASES = [
    ("ssh-host-key.yaml", "custom.ssh-missing-host-key-verification",
     ["ssh-host-key-vuln.ts", "ssh-host-key-vuln.py"],
     ["ssh-host-key-fixed.ts", "ssh-host-key-fixed.py"]),
    ("auth.yaml", "custom.missing-auth",
     ["auth-vuln.js"], ["auth-fixed.js"]),
    ("crypto-verify.yaml", "custom.missing-crypto-verification",
     ["crypto-verify-vuln.js", "crypto-verify-vuln.py"],
     ["crypto-verify-fixed.js", "crypto-verify-fixed.py"]),
    ("secret.yaml", "custom.hardcoded-secret",
     ["secret-vuln.py", "secret-vuln.js"],
     ["secret-fixed.py", "secret-fixed.js"]),
    ("ssrf.yaml", "custom.ssrf-user-input-to-fetch",
     ["ssrf-vuln.js", "ssrf-vuln.py"],
     ["ssrf-fixed.js", "ssrf-fixed.py"]),
    ("path-traversal.yaml", "custom.path-traversal-user-input-to-file",
     ["path-traversal-vuln.py", "path-traversal-vuln.js"],
     ["path-traversal-fixed.py", "path-traversal-fixed.js"]),
    ("sqli.yaml", "custom.sqli-user-input-to-query",
     ["sqli-vuln.py", "sqli-vuln.js"],
     ["sqli-fixed.py", "sqli-fixed.js"]),
    ("xss.yaml", "custom.xss-user-input-to-html-sink",
     ["xss-vuln.js"], ["xss-fixed.js"]),
]


@pytest.mark.skipif(SEMGREP is None, reason="semgrep binary not found")
@pytest.mark.parametrize(
    "rule_file,rule_id,vuln_fixed, fixed_files",
    [
        (name, rid, vuln, fixed)
        for name, rid, vuln, fixed in RULE_CASES
    ],
)
def test_rule_fires_on_vulnerable_not_fixed(
    rule_file, rule_id, vuln_fixed, fixed_files
):
    """Each rule fires on its vulnerable fixtures, silent on fixed."""
    vuln_paths = [FIXTURES / name for name in vuln_fixed]
    fixed_paths = [FIXTURES / name for name in fixed_files]
    vuln_hits, vuln_errors = _run_rule(
        RULES_DIR / rule_file, *vuln_paths
    )
    assert vuln_errors == []
    matched = [hit for hit in vuln_hits if hit[0] == rule_id]
    assert matched, "rule %s fired on no vulnerable fixture" % rule_id
    for target in vuln_paths:
        assert any(
            hit[0] == rule_id and hit[1] == str(target)
            for hit in matched
        ), "rule %s did not fire on %s" % (rule_id, target)
    fixed_hits, fixed_errors = _run_rule(
        RULES_DIR / rule_file, *fixed_paths
    )
    assert fixed_errors == []
    assert [
        hit for hit in fixed_hits if hit[0] == rule_id
    ] == [], "rule %s fired on a fixed fixture: %s" % (
        rule_id,
        fixed_hits,
    )


@pytest.mark.skipif(SEMGREP is None, reason="semgrep binary not found")
def test_host_key_rule_fires_on_build_client_config():
    """The host-key rule fires on the ssh-mcp-server vulnerable
    buildClientConfig code and not on the fixed code with strict
    host key verification against known_hosts."""
    vuln_hits, errors = _run_rule(
        RULES_DIR / "ssh-host-key.yaml",
        FIXTURES / "ssh-host-key-vuln.ts",
    )
    assert errors == []
    assert any(
        hit[0] == "custom.ssh-missing-host-key-verification"
        for hit in vuln_hits
    )
    fixed_hits, fixed_errors = _run_rule(
        RULES_DIR / "ssh-host-key.yaml",
        FIXTURES / "ssh-host-key-fixed.ts",
    )
    assert fixed_errors == []
    assert fixed_hits == []


@pytest.mark.skipif(SEMGREP is None, reason="semgrep binary not found")
def test_auth_rule_public_route_is_a_known_false_positive():
    """The auth rule flags a public route by design: it cannot
    tell a public route from an unprotected admin route. The
    finding needs triage. Recorded, not hidden."""
    hits, errors = _run_rule(
        RULES_DIR / "auth.yaml", FIXTURES / "auth-public.js"
    )
    assert errors == []
    assert any(hit[0] == "custom.missing-auth" for hit in hits)


def _chat_real(model, system_content, user_content, max_tokens=2500):
    return {
        "content": '{"verdict": "real", "severity": "medium", '
        '"confidence": 0.9, "reason": "SSH client accepts any host '
        'key.", "fix": "Verify the host key against known_hosts."}',
        "latency_seconds": 0.5,
        "usage": {"prompt_tokens": 200, "completion_tokens": 20},
        "error": None,
        "retried": False,
        "timeout": False,
    }


CUSTOM_SEMGREP_JSON = {
    "version": "1.184.0",
    "results": [
        {
            "check_id": "rules.custom.ssh-missing-host-key-verification",
            "path": "src/services/ssh-connection-manager.ts",
            "start": {"line": 1710},
            "extra": {
                "message": "SSH client configuration has no host key verification",
                "severity": "WARNING",
            },
        }
    ],
    "errors": [],
}


def test_repo_scan_returns_host_key_custom_rule_mockllm(tmp_path):
    """repo_scan on ssh-mcp-server code, MockLLM, returns the
    host-key finding with source custom-rule, and stores it."""
    repo = tmp_path / "ssh-mcp-server"
    target = repo / "src" / "services"
    target.mkdir(parents=True)
    (target / "ssh-connection-manager.ts").write_text(
        (FIXTURES / "ssh-host-key-vuln.ts").read_text()
    )

    def _default_runner(cmd, timeout):
        return 0, json.dumps(
            {"version": "1.184.0", "results": [], "errors": []}
        ), ""

    def _custom_runner(cmd, timeout):
        assert "--config" in cmd
        assert str(RULES_DIR) in cmd
        return 0, json.dumps(CUSTOM_SEMGREP_JSON), ""

    db_path = tmp_path / "findings.db"
    result = srv.repo_scan_impl(
        repo_path=str(repo),
        stage1_model=CHEAP,
        stage2_model=QWEN,
        pricing=PRICING,
        semgrep_runner=_default_runner,
        semgrep_custom_runner=_custom_runner,
        chat_fn=_chat_real,
        db_path=str(db_path),
        rules_dir=str(RULES_DIR),
        max_files=10,
        max_file_kb=200,
    )
    assert result["errors"] == []
    assert result["custom_rules"]["enabled"] is True
    assert result["custom_rules"]["findings"] == 1
    assert result["findings_total"] == 1
    assert result["findings_triaged"] == 1
    assert result["findings_real"] == 1
    finding = result["findings"][0]
    assert finding["source"] == "custom-rule"
    assert finding["rule_id"] == (
        "custom.ssh-missing-host-key-verification"
    )
    assert finding["check"] == "Missing SSH host key verification"
    assert finding["verdict"] == "real"
    assert finding["finding_id"] is not None
    stored = srv.get_finding_impl(
        finding["finding_id"], db_path=str(db_path)
    )
    assert stored["error"] is None
    assert stored["finding"]["check"] == (
        "Missing SSH host key verification"
    )


def test_repo_scan_custom_pack_missing_warns_mockllm(tmp_path):
    """A missing rules pack warns and the default scan still runs."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")

    def _runner(cmd, timeout):
        return 0, json.dumps(
            {"version": "1.184.0", "results": [], "errors": []}
        ), ""

    result = srv.repo_scan_impl(
        repo_path=str(repo),
        stage1_model=CHEAP,
        stage2_model=QWEN,
        pricing=PRICING,
        semgrep_runner=_runner,
        chat_fn=_chat_real,
        rules_dir=str(tmp_path / "no-such-rules"),
        dry_run=True,
    )
    assert result["errors"] == []
    assert result["custom_rules"]["enabled"] is False
    assert any(
        "custom rules pack not found" in warning
        for warning in result["warnings"]
    )


@pytest.mark.skipif(SEMGREP is None, reason="semgrep binary not found")
def test_custom_rules_run_reports_config_errors(tmp_path):
    """A custom-rules run with an invalid config reports errors,
    never an empty finding list passed off as clean."""
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "bad.yaml").write_text("rules: [unclosed\n")
    findings, errors = scanners_mod.run_semgrep_custom_rules(
        str(tmp_path), str(pack), binary=SEMGREP
    )
    assert findings == []
    assert errors, "an invalid custom config must report errors"


def test_tool_count_is_15_mockllm(capsys):
    """15 tools after Phase A3: 6 original, verify_finding,
    5 store tools, list_rules, scope_enable, scope_disable.
    Counted, not guessed."""
    assert srv.main(["--list-tools"]) == 0
    names = capsys.readouterr().out.split()
    assert len(names) == 15
    assert names == [
        "triage_semgrep_finding",
        "repo_scan",
        "check_osv_advisory",
        "explain_cve",
        "draft_private_disclosure",
        "estimate_cost",
        "verify_finding",
        "list_findings",
        "get_finding",
        "update_finding",
        "mark_fp",
        "mark_confirmed",
        "list_rules",
        "scope_enable",
        "scope_disable",
    ]
