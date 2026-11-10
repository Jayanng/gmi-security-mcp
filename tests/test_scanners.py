"""Unit tests for semgrep/osv-scanner runners and rule mapping.

No real scanners run here. The runner is replaced with a stub
serving canned semgrep JSON copied from the real output shape.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from gmi_security_mcp import scanners

SEMGREP_FIXTURE = {
    "version": "1.184.0",
    "results": [
        {
            "check_id": "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal",
            "path": "src/server.js",
            "start": {"line": 42},
            "extra": {
                "message": "Path traversal via path.join",
                "severity": "WARNING",
            },
        },
        {
            "check_id": "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal",
            "path": "src/server.js",
            "start": {"line": 42},
            "extra": {
                "message": "Path traversal via path.join",
                "severity": "WARNING",
            },
        },
        {
            "check_id": "html.security.audit.missing-integrity.missing-integrity",
            "path": "index.html",
            "start": {"line": 10},
            "extra": {
                "message": "Missing integrity attribute",
                "severity": "WARNING",
            },
        },
        {
            "check_id": "python.lang.security.audit.sql-string-format.sql-string-format",
            "path": "app.py",
            "start": {"line": 7},
            "extra": {
                "message": "SQL string format",
                "severity": "ERROR",
            },
        },
    ],
    "errors": [],
}


def _stub_runner(payload, returncode=0):
    def _run(cmd, timeout):
        assert cmd[0] == "semgrep"
        assert "--json" in cmd
        # One --config flag per config, never a comma-joined one.
        configs = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--config"]
        assert all("," not in c for c in configs)
        return returncode, json.dumps(payload), ""

    return _run


def test_parse_semgrep_config_splits_commas():
    assert scanners.parse_semgrep_config(
        "p/default,p/security-audit,p/python,p/javascript,p/secrets"
    ) == [
        "p/default",
        "p/security-audit",
        "p/python",
        "p/javascript",
        "p/secrets",
    ]
    assert scanners.parse_semgrep_config(["p/default"]) == ["p/default"]
    with pytest.raises(ValueError):
        scanners.parse_semgrep_config("")
    with pytest.raises(ValueError):
        scanners.parse_semgrep_config("p/default; rm -rf /")


def test_run_semgrep_parses_findings():
    findings, errors = scanners.run_semgrep(
        "/tmp/repo", runner=_stub_runner(SEMGREP_FIXTURE)
    )
    assert len(findings) == 4
    assert errors == []
    assert findings[0]["rule_id"].startswith("javascript.lang.security")
    assert findings[0]["check"] == "Path traversal"
    assert findings[0]["line"] == 42
    assert findings[2]["check"] == "other"


def test_run_semgrep_nonzero_without_json_is_error():
    def _run(cmd, timeout):
        return 2, "", "semgrep: boom"

    with pytest.raises(RuntimeError, match="exited 2"):
        scanners.run_semgrep("/tmp/repo", runner=_run)


def test_run_semgrep_missing_binary_is_error():
    def _run(cmd, timeout):
        raise RuntimeError("scanner binary not found: semgrep")

    with pytest.raises(RuntimeError, match="not found"):
        scanners.run_semgrep("/tmp/repo", runner=_run)


def test_deduplicate_findings():
    findings, _ = scanners.run_semgrep(
        "/tmp/repo", runner=_stub_runner(SEMGREP_FIXTURE)
    )
    deduped = scanners.deduplicate_findings(findings)
    assert len(deduped) == 3


def test_map_rule_to_check():
    assert (
        scanners.map_rule_to_check(
            "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal"
        )
        == "Path traversal"
    )
    assert (
        scanners.map_rule_to_check("python.sqlalchemy.sql-injection")
        == "SQL injection"
    )
    assert scanners.map_rule_to_check("weird.rule.with.no.meaning") == "other"
    assert scanners.map_rule_to_check(None) == "other"
    assert (
        scanners.map_rule_to_check("javascript.lang.security.audit.sqli")
        == "SQL injection"
    )


def test_is_excluded_path():
    assert scanners.is_excluded_path("node_modules/pkg/index.js") is True
    assert scanners.is_excluded_path(".git/config") is True
    assert scanners.is_excluded_path("vendor/lib.php") is True
    assert scanners.is_excluded_path("src/server.js") is False
    assert scanners.is_excluded_path("tests/test_app.py") is True
    assert scanners.is_excluded_path("tests/test_app.py", include_tests=True) is False
    assert scanners.is_excluded_path("src/app.test.js") is True


def test_read_snippet_bounds_lines(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("\n".join("line %d" % n for n in range(1, 101)))
    snippet = scanners.read_snippet(tmp_path, "app.py", 50, context_lines=2)
    assert "line 48" in snippet
    assert "line 52" in snippet
    assert "line 1" not in snippet
    assert scanners.read_snippet(tmp_path, "missing.py", 1) is None


def test_count_field_occurrences_counts_each_field(tmp_path):
    target = tmp_path / "ssh.ts"
    target.write_text(
        "const sshConfig = {host: 'x'};\n"
        "hostVerifier = null;\n"
        "// knownHosts mentioned once\n"
    )
    counts = scanners.count_field_occurrences(
        tmp_path, "ssh.ts", ["hostVerifier", "knownHosts", "trustedHostKey"]
    )
    assert counts == {
        "hostVerifier": 1,
        "knownHosts": 1,
        "trustedHostKey": 0,
    }


def test_count_field_occurrences_missing_file_is_none_not_zero(tmp_path):
    assert scanners.count_field_occurrences(
        tmp_path, "missing.ts", ["hostVerifier"]
    ) is None
    assert scanners.count_field_occurrences(tmp_path, "missing.ts", []) == {}


def test_find_lockfiles(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "requirements.txt").write_text("")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").write_text("{}")
    found = scanners.find_lockfiles(tmp_path)
    names = [p.name for p in found]
    assert names == ["package-lock.json", "requirements.txt"]


def test_run_osv_scanner_exit_1_is_vulns_not_error():
    def _run(cmd, timeout):
        assert cmd[0] == "osv-scanner"
        assert "--lockfile" in cmd
        return 1, json.dumps({"results": []}), ""

    advisories, scanned, vulnerable, error = scanners.run_osv_scanner(
        "/tmp/package-lock.json", runner=_run
    )
    assert error is None
    assert advisories == []


def test_run_osv_scanner_exit_2_is_error():
    def _run(cmd, timeout):
        return 2, "", "osv-scanner: bad flag"

    _, _, _, error = scanners.run_osv_scanner("/tmp/x.json", runner=_run)
    assert error and "exited 2" in error
