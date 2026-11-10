"""Unit tests for repo_scan. No API calls, no real scanners.

The semgrep runner and the GMI chat function are stubs. Live
behaviour is tested separately in scripts/run-repo-scan.py.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import server as srv

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
}
CHEAP = "google/gemini-3.5-flash-lite"
QWEN = "Qwen/Qwen3.8-Flash"

os.environ["GMI_API_KEY"] = "test-key-never-sent"

SEMGREP_JSON = {
    "version": "1.184.0",
    "results": [
        {
            "check_id": "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal",
            "path": "src/server.js",
            "start": {"line": 5},
            "extra": {"message": "Path traversal via path.join", "severity": "WARNING"},
        },
        {
            "check_id": "html.security.audit.missing-integrity.missing-integrity",
            "path": "index.html",
            "start": {"line": 3},
            "extra": {"message": "Missing integrity attribute", "severity": "WARNING"},
        },
    ],
    "errors": [],
}


def _semgrep_runner(payload=None):
    def _run(cmd, timeout):
        return 0, json.dumps(payload or SEMGREP_JSON), ""

    return _run


def _chat_real(model, system_content, user_content, max_tokens=2500):
    return {
        "content": '{"verdict": "real", "severity": "high", "confidence": 0.9, '
        '"reason": "Input reaches the sink.", "fix": "Use parameters."}',
        "latency_seconds": 0.5,
        "usage": {"prompt_tokens": 200, "completion_tokens": 20},
        "error": None,
        "retried": False,
        "timeout": False,
    }


def _make_repo(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.js").write_text(
        "const path = require('path');\n"
        "const fs = require('fs');\n"
        "function read(name) {\n"
        "  const p = path.join('/data', name);\n"
        "  return fs.readFileSync(p);\n"
        "}\n"
    )
    (tmp_path / "index.html").write_text("<html><head></head><body>x</body></html>\n")
    return tmp_path


def _base(tmp_path, **over):
    args = {
        "repo_path": str(tmp_path),
        "stage1_model": CHEAP,
        "stage2_model": QWEN,
        "pricing": PRICING,
        "semgrep_runner": _semgrep_runner(),
        "chat_fn": _chat_real,
    }
    args.update(over)
    return args


def test_repo_scan_triages_findings(tmp_path):
    repo = _make_repo(tmp_path)
    result = srv.repo_scan_impl(**_base(repo))
    assert result["errors"] == []
    assert result["findings_total"] == 2
    assert result["findings_triaged"] == 2
    assert result["findings_real"] == 2
    assert result["findings_no_verdict"] == 0
    assert result["stopped_early"] is False
    assert result["total_cost_usd"] > 0
    first = result["findings"][0]
    assert first["file"] == "src/server.js"
    assert first["check"] == "Path traversal"
    assert first["stage_used"] in ("stage1", "stage2")
    assert result["osv"] == {"lockfiles": []}


def test_repo_scan_dry_run_makes_no_calls(tmp_path):
    repo = _make_repo(tmp_path)
    calls = []

    def _chat(*args, **kwargs):
        calls.append(1)
        return _chat_real(*args, **kwargs)

    result = srv.repo_scan_impl(**_base(repo, dry_run=True, chat_fn=_chat))
    assert calls == []
    assert result["dry_run"] is True
    assert result["findings_triaged"] == 0
    assert result["total_cost_usd"] == 0
    assert result["estimate_usd"] is not None
    assert result["max_estimate_usd"] is not None
    assert result["stopped_early"] is True


def test_repo_scan_oversize_file_skipped(tmp_path):
    repo = _make_repo(tmp_path)
    result = srv.repo_scan_impl(**_base(repo, max_file_kb=1))
    # index.html is small here, so force the skip via a tiny cap on
    # the server.js file by making it big instead.
    assert result["findings_total"] == 2
    big = repo / "src" / "server.js"
    big.write_text("x\n" * 3000)
    result = srv.repo_scan_impl(**_base(repo, max_file_kb=1))
    assert result["findings_triaged"] == 1
    assert len(result["skipped"]) == 1
    assert "over the 1 KB" in result["skipped"][0]["reason"]


def test_repo_scan_stops_early_on_tiny_cap(tmp_path):
    repo = _make_repo(tmp_path)
    result = srv.repo_scan_impl(**_base(repo, spend_cap_usd=0.000001))
    assert result["findings_triaged"] == 0
    assert result["stopped_early"] is True
    assert "spend cap" in (result["stopped_reason"] or "")
    assert result["skipped"]


def test_repo_scan_missing_dir_is_error(tmp_path):
    result = srv.repo_scan_impl(
        repo_path=str(tmp_path / "nope"),
        stage1_model=CHEAP,
        stage2_model=QWEN,
        pricing=PRICING,
    )
    assert result["errors"]
    assert result["findings_total"] == 0


def test_repo_scan_missing_stage2_is_error(tmp_path):
    repo = _make_repo(tmp_path)
    result = srv.repo_scan_impl(**_base(repo, stage2_model=None))
    assert result["errors"]
    assert "stage2_model is required" in result["errors"][0]


def test_repo_scan_semgrep_failure_is_error(tmp_path):
    repo = _make_repo(tmp_path)

    def _run(cmd, timeout):
        return 2, "", "semgrep: boom"

    result = srv.repo_scan_impl(**_base(repo, semgrep_runner=_run))
    assert result["errors"]
    assert result["findings_total"] == 0


def test_repo_scan_keeps_stage1_when_stage2_fails(tmp_path):
    repo = _make_repo(tmp_path)

    def _chat(model, system_content, user_content, max_tokens=2500):
        if model == CHEAP:
            return {
                "content": '{"verdict": "real", "severity": "medium", '
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

    result = srv.repo_scan_impl(**_base(repo, chat_fn=_chat))
    assert result["findings_real"] == 2
    assert all(f["escalation_failed"] is True for f in result["findings"])
    assert all(f["stage_used"] == "stage1" for f in result["findings"])


def test_repo_scan_osv_section_from_lockfile(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{'
        '"node_modules/deepmerge":{"version":"4.3.1"}}}'
    )

    def _osv(cmd, timeout):
        payload = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": "deepmerge",
                                "version": "4.3.1",
                                "ecosystem": "npm",
                            },
                            "groups": [
                                {
                                    "ids": ["GHSA-gcqx-w48m-w2h4"],
                                    "aliases": ["CVE-2026-93753"],
                                    "max_severity": "5.3",
                                }
                            ],
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-gcqx-w48m-w2h4",
                                    "aliases": ["CVE-2026-93753"],
                                    "summary": "prototype poisoning",
                                    "affected": [
                                        {
                                            "package": {
                                                "ecosystem": "npm",
                                                "name": "deepmerge",
                                            },
                                            "ranges": [
                                                {
                                                    "type": "SEMVER",
                                                    "events": [
                                                        {"introduced": "4.2.0"},
                                                        {"last_affected": "4.3.1"},
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        return 1, json.dumps(payload), ""

    result = srv.repo_scan_impl(**_base(repo, osv_runner=_osv))
    sections = result["osv"]["lockfiles"]
    assert len(sections) == 1
    assert sections[0]["packages_scanned"] == 1
    assert sections[0]["vulnerable_packages"] == 1
    assert sections[0]["advisories"][0]["id"] == "CVE-2026-93753"


def test_repo_scan_package_json_parsed_not_scanned(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / "package.json").write_text(
        '{"dependencies":{"exact-pkg":"1.2.3","range-pkg":"^2.0.0"}}'
    )
    calls = []

    def _osv(cmd, timeout):
        calls.append(cmd)
        return 0, '{"results": []}', ""

    result = srv.repo_scan_impl(**_base(repo, osv_runner=_osv))
    assert calls == []
    sections = result["osv"]["lockfiles"]
    assert len(sections) == 1
    assert sections[0]["lockfile_path"] == "package.json"
    assert sections[0]["packages_parsed"] == 1
    assert sections[0]["advisories"] == []
    assert sections[0]["note"]
    assert result["errors"] == []


def test_repo_scan_write_report(tmp_path):
    repo = _make_repo(tmp_path)
    out = tmp_path / "report.md"
    result = srv.repo_scan_impl(**_base(repo, write_report=str(out)))
    assert out.is_file()
    text = out.read_text()
    assert "src/server.js" in text
    assert "Path traversal" in text
    assert result.get("report_written_to") == str(out)


def test_repo_scan_custom_host_key_gets_absence_evidence(tmp_path):
    """The host-key custom finding reaches triage with a factual
    count of its verification fields in the file. A MockLLM that
    only calls it real when the count is present proves the
    evidence reaches the model call; a mock without the count
    would call it false_positive, as the live model did twice."""
    repo = tmp_path
    src = repo / "src"
    src.mkdir()
    (src / "ssh.ts").write_text(
        "async function buildClientConfig(config) {\n"
        "  const sshConfig = {\n"
        "    host: config.host,\n"
        "    port: config.port,\n"
        "    username: config.username,\n"
        "    readyTimeout: 30000,\n"
        "  };\n"
        "  return sshConfig;\n"
        "}\n"
    )
    custom_payload = {
        "version": "1.184.0",
        "results": [
            {
                "check_id": "rules.custom.ssh-missing-host-key-verification",
                "path": "src/ssh.ts",
                "start": {"line": 2},
                "extra": {
                    "message": "SSH client configuration has no host "
                    "key verification: no hostVerifier, knownHosts, "
                    "or trustedHostKey.",
                    "severity": "WARNING",
                },
            }
        ],
        "errors": [],
    }
    empty_payload = {"version": "1.184.0", "results": [], "errors": []}

    def _runner(cmd, timeout):
        # The custom run passes the rules dir as its --config.
        if any("rules" in str(part) for part in cmd):
            return 0, json.dumps(custom_payload), ""
        return 0, json.dumps(empty_payload), ""

    seen = {}

    def _chat(model, system_content, user_content, max_tokens=2500):
        seen["user"] = user_content
        verdict = "real" if "occur 0 times" in user_content else "false_positive"
        return {
            "content": json.dumps(
                {
                    "verdict": verdict,
                    "severity": "medium",
                    "confidence": 0.9,
                    "reason": "MockLLM: host-key verdict from evidence.",
                    "fix": "Verify the host key.",
                }
            ),
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 200, "completion_tokens": 20},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.repo_scan_impl(
        repo_path=str(repo),
        stage1_model=CHEAP,
        stage2_model=QWEN,
        pricing=PRICING,
        semgrep_runner=_runner,
        semgrep_custom_runner=_runner,
        chat_fn=_chat,
        rules_dir=str(Path(__file__).resolve().parents[1] / "rules"),
    )
    assert result["findings_total"] == 1
    finding = result["findings"][0]
    assert finding["source"] == "custom-rule"
    assert finding["verdict"] == "real", seen
    assert "hostVerifier 0" in seen["user"]
    assert "knownHosts 0" in seen["user"]
    assert "trustedHostKey 0" in seen["user"]
    assert "not a model claim" in seen["user"]
