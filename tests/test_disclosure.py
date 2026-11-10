"""Unit tests for draft_private_disclosure. No API calls, no sends.

The worked example is the ssh-mcp-server host-key finding from
2026-11-07: missing SSH host key verification, no hostVerifier,
known_hosts never consulted, MEDIUM, proven in ssh2 1.17.0.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gmi_security_mcp import disclosure as d

SSH_FINDING = {
    "verdict": "real",
    "severity": "medium",
    "confidence": 0.9,
    "check": "Authentication and session flaws",
    "reason": "ssh-mcp-server never verifies the SSH server host key. "
    "Every SSH connection accepts any host key, with no option to pin "
    "one, no known_hosts check, and no warning to the operator.",
    "fix": "Add a hostVerifier that checks the presented host key "
    "against ~/.ssh/known_hosts, or against a configured trustedHostKey "
    "fingerprint, and fail closed on mismatch.",
    "file": "src/services/ssh-connection-manager.ts",
    "line": 1706,
    "title": "Missing SSH host key verification allows man-in-the-middle "
    "impersonation of the SSH server",
    "summary": "ssh-mcp-server never verifies the SSH server host key. "
    "Every SSH connection accepts any host key.",
    "affected_version": "1.11.0",
    "proof": "ssh2 1.17.0 auto-accepts host keys when hostVerifier is "
    "not set. In node_modules/ssh2/lib/protocol/kex.js, if "
    "_hostVerifier is undefined, ret is true.",
    "impact": "An active attacker who can redirect the connection can "
    "impersonate the configured SSH server, and the MCP server will "
    "send the configured password to the fake server.",
    "reporter": "Jayanng",
}

REPO = "classfang/ssh-mcp-server"


def test_ssh_host_key_draft_matches_template():
    result = d.draft_private_disclosure_impl(SSH_FINDING, REPO)
    assert result["sent"] is False
    assert result["error"] is None
    assert result["written_to"] is None
    draft = result["draft_markdown"]
    assert "DRAFT, NOT SUBMITTED" in draft
    assert "Missing SSH host key verification" in draft
    assert "1.11.0" in draft
    assert "src/services/ssh-connection-manager.ts" in draft
    assert "hostVerifier" in draft
    assert "known_hosts" in draft
    for section in (
        "## Summary",
        "## Product",
        "## Tested Version",
        "## Details",
        "## PoC",
        "## Impact",
        "## Remediation",
        "## GitHub Security Advisories",
        "## Credit",
        "## Contact",
        "## Disclosure Policy",
    ):
        assert section in draft, section
    assert "90 days" in draft
    assert "Jayanng" in draft


def test_next_steps_cover_pvr_public_issue_and_pr():
    result = d.draft_private_disclosure_impl(SSH_FINDING, REPO)
    steps = " ".join(result["next_steps"])
    assert "Private Vulnerability Reporting" in steps
    assert "GitHub sign-in" in steps
    assert "public issue" in steps
    assert "public PR discloses the flaw" in steps
    assert "No maintainer contact" in steps


def test_next_steps_no_contact_note_absent_when_contact_given():
    result = d.draft_private_disclosure_impl(
        SSH_FINDING, REPO, maintainer_contact="security@example.com"
    )
    steps = " ".join(result["next_steps"])
    assert "No maintainer contact" not in steps
    assert "security@example.com" in result["draft_markdown"]


def test_write_path_writes_draft_only_when_given(tmp_path):
    target = tmp_path / "disclosure.md"
    result = d.draft_private_disclosure_impl(
        SSH_FINDING, REPO, write_path=str(target)
    )
    assert result["written_to"] == str(target)
    assert target.read_text() == result["draft_markdown"]
    assert result["sent"] is False


def test_false_positive_refused():
    finding = dict(SSH_FINDING, verdict="false_positive")
    result = d.draft_private_disclosure_impl(finding, REPO)
    assert result["draft_markdown"] is None
    assert result["sent"] is False
    assert "not real" in result["error"]


def test_no_verdict_refused():
    finding = dict(SSH_FINDING, verdict=None)
    result = d.draft_private_disclosure_impl(finding, REPO)
    assert result["draft_markdown"] is None
    assert "not real" in result["error"]


def test_low_confidence_refused_without_confirmation():
    finding = dict(SSH_FINDING, confidence=0.5)
    result = d.draft_private_disclosure_impl(finding, REPO)
    assert result["draft_markdown"] is None
    assert "below 0.80" in result["error"]


def test_low_confidence_allowed_with_confirmation():
    finding = dict(SSH_FINDING, confidence=0.5)
    result = d.draft_private_disclosure_impl(
        finding, REPO, confirm_low_confidence=True
    )
    assert result["draft_markdown"] is not None
    assert result["sent"] is False


def test_missing_confidence_refused_without_confirmation():
    finding = dict(SSH_FINDING)
    del finding["confidence"]
    result = d.draft_private_disclosure_impl(finding, REPO)
    assert result["draft_markdown"] is None
    assert "not stated" in result["error"]


def test_missing_repo_refused():
    result = d.draft_private_disclosure_impl(SSH_FINDING, "")
    assert result["draft_markdown"] is None
    assert "repo is required" in result["error"]


def test_missing_finding_refused():
    result = d.draft_private_disclosure_impl(None, REPO)
    assert result["draft_markdown"] is None
    assert result["sent"] is False


def test_crafted_severity_is_allowlisted_in_draft():
    finding = dict(
        SSH_FINDING,
        severity="critical' onmouseover='alert(1)",
    )
    result = d.draft_private_disclosure_impl(finding, REPO)
    assert result["draft_markdown"] is not None
    assert "onmouseover" not in result["draft_markdown"]
    assert "Severity: low" in result["draft_markdown"]


def test_secret_in_finding_is_redacted():
    finding = dict(
        SSH_FINDING,
        reason="The key is AKIAIOSFODNN7EXAMPLE and the server accepts it.",
    )
    result = d.draft_private_disclosure_impl(finding, REPO)
    assert "AKIAIOSFODNN7EXAMPLE" not in result["draft_markdown"]
    assert "[REDACTED]" in result["draft_markdown"]
    assert result["redacted"] is True
    assert result["redaction_count"] >= 1


def test_include_fix_false_omits_fix():
    result = d.draft_private_disclosure_impl(
        SSH_FINDING, REPO, include_fix=False
    )
    assert "omitted at the caller's request" in result["draft_markdown"]
    assert "hostVerifier" not in result["draft_markdown"].split(
        "## Remediation"
    )[1].split("## GitHub")[0]


def test_unfilled_fields_are_marked_not_supplied():
    finding = {
        "verdict": "real",
        "severity": "high",
        "confidence": 0.95,
        "reason": "Input reaches the sink.",
        "fix": "Use parameters.",
    }
    result = d.draft_private_disclosure_impl(finding, "owner/repo")
    draft = result["draft_markdown"]
    assert "Version not supplied" in draft
    assert "No reproduction steps were supplied" in draft
    assert result["sent"] is False


def test_draft_is_json_serialisable():
    result = d.draft_private_disclosure_impl(SSH_FINDING, REPO)
    json.dumps(result)
