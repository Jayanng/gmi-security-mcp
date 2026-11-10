"""draft_private_disclosure: a private disclosure draft, never sent.

Structure: the GitHub Security Lab report template
(https://github.com/github/securitylab/blob/main/docs/report-template.md):
title and summary, product, tested version, details, proof, impact,
remediation, a request for a private GitHub Security Advisory, credit,
contact, and disclosure policy. The worked example for the format is
the ssh-mcp-server host-key draft
(~/workspace/bug-bounty/vuln/pending-disclosures/2026-11-07-ssh-mcp-server-host-key.md).

Rules, from the build plan:
- Refuse when the finding verdict is not real, or when confidence is
  below 0.8 and the caller did not confirm it. Never draft a
  disclosure for a false positive or an unparsed finding.
- The draft is returned as Markdown and, only when the caller gives
  an explicit write_path, written to that path. It is never sent,
  never opened as a PR, never forked, never pushed, never emailed.
  sent is always False.
- Nothing is invented: version, location, proof, and impact come
  from the finding object when supplied, and are marked as not
  supplied when they are not. A public PR would disclose the flaw,
  so private disclosure first is recommended in the next steps.
"""

from pathlib import Path

from . import redact as redact_mod
from . import validate as validate_mod

MIN_CONFIDENCE = 0.8
DISCLOSURE_DEADLINE_DAYS = 90

NEXT_STEPS_BASE = [
    "Report privately first. GitHub Private Vulnerability Reporting "
    "needs a GitHub sign-in; use it where it is enabled for this repo.",
    "A public issue needs your approval for that exact destination. "
    "Do not open one for a security flaw without it.",
    "Do not open a PR with the fix yet: a public PR discloses the "
    "flaw, so disclose privately first and let the maintainer fix it.",
    "Coordinated disclosure deadline: %d days after the first report, "
    "unless the maintainer agrees a different timeline."
    % DISCLOSURE_DEADLINE_DAYS,
]

NEXT_STEPS_NO_CONTACT = (
    "No maintainer contact was supplied. Check the repo for a "
    "SECURITY.md or a listed security contact before sending anything."
)


def _single_line(value):
    """Collapse a header-style field to one line, no newlines."""
    return " ".join(str(value or "").split()).strip()


def _section(value, not_supplied_note):
    text = str(value or "").strip()
    if text:
        return text
    return not_supplied_note


def build_draft(finding, repo, maintainer_contact=None, include_fix=True):
    """Build the draft Markdown from a validated real finding.

    Assumes the caller already checked verdict and confidence.
    The core fields (verdict, severity, confidence, reason, fix,
    check, line) come from validate.norm_finding, so the severity
    allowlist and the exact-verdict rule apply here too. Extra
    fields (title, version, proof, impact) come from the finding
    object when supplied, capped in length, and are marked as not
    supplied when they are not. Returns (draft_text, redaction_count).
    """
    validated = validate_mod.norm_finding(finding) or {}
    severity = validated.get("severity") or "low"
    confidence = validated.get("confidence")
    check = validated.get("check") or "other"
    reason = validated.get("reason") or ""
    fix = validated.get("fix") or ""
    title = _single_line(finding.get("title"))
    if not title:
        title = "%s: %s" % (check, reason) if reason else check
    version = _single_line(
        finding.get("affected_version") or finding.get("version") or ""
    )
    file_path = finding.get("file")
    line = validated.get("line")
    location = _single_line(finding.get("location"))
    if not location and file_path:
        location = "%s%s" % (
            file_path,
            (", line %s" % line) if line is not None else "",
        )
    proof = str(finding.get("proof") or finding.get("reproduction") or "")[:4000]
    impact = str(finding.get("impact") or "")[:4000]
    reporter = _single_line(finding.get("reporter") or "")
    contact = _single_line(maintainer_contact or "")

    lines = []
    lines.append("# DRAFT, NOT SUBMITTED, DO NOT SEND WITHOUT USER APPROVAL")
    lines.append("")
    lines.append("Target: %s" % _single_line(repo))
    lines.append("Title: %s" % title)
    lines.append("Severity: %s" % severity)
    lines.append(
        "Confidence: %s"
        % ("%.2f" % confidence if confidence is not None else "not stated")
    )
    if reporter:
        lines.append("Reporter: %s" % reporter)
    lines.append("")
    lines.append("## Vulnerability Report")
    lines.append("")
    lines.append(
        "I identified a potential security vulnerability in %s."
        % _single_line(repo)
    )
    lines.append("")
    lines.append(
        "I am committed to working with you to help resolve this issue. "
        "In this report you will find everything needed to coordinate "
        "a resolution."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        _section(
            finding.get("summary") or reason,
            "No summary was supplied with the finding.",
        )
    )
    lines.append("")
    lines.append("## Product")
    lines.append("")
    lines.append(_single_line(repo))
    lines.append("")
    lines.append("## Tested Version")
    lines.append("")
    lines.append(
        _section(version, "Version not supplied with the finding.")
    )
    lines.append("")
    lines.append("## Details")
    lines.append("")
    lines.append(
        "Check: %s. Location: %s."
        % (
            check,
            _section(
                location,
                "Location not supplied with the finding.",
            ),
        )
    )
    lines.append("")
    lines.append(
        _section(
            reason,
            "No detail was supplied with the finding.",
        )
    )
    lines.append("")
    lines.append("## PoC")
    lines.append("")
    lines.append(
        _section(
            proof,
            "No reproduction steps were supplied with the finding. "
            "Add them before sending.",
        )
    )
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append(
        _section(
            impact,
            "Impact was not stated separately from the summary. "
            "The summary above describes the effect.",
        )
    )
    lines.append("")
    lines.append("## Remediation")
    lines.append("")
    if include_fix and fix:
        lines.append(
            "Suggested fix: %s This is a suggestion only; the "
            "maintainer may have a better fix." % fix
        )
    elif include_fix:
        lines.append(
            "No fix suggestion was supplied with the finding."
        )
    else:
        lines.append("Fix suggestion omitted at the caller's request.")
    lines.append("")
    lines.append("## GitHub Security Advisories")
    lines.append("")
    lines.append(
        "If possible, please create a private GitHub Security Advisory "
        "for this finding. That keeps the report private until a fix "
        "ships, and lets us discuss it in private before it is "
        "published. A Security Advisory can also be used to request a "
        "CVE identification number from GitHub."
    )
    lines.append("")
    lines.append("## Credit")
    lines.append("")
    lines.append(reporter if reporter else "Reporter not named.")
    lines.append("")
    lines.append("## Contact")
    lines.append("")
    if contact:
        lines.append(contact)
    else:
        lines.append(
            "No maintainer contact was supplied. See the next steps: "
            "check the repo for a SECURITY.md or a listed security "
            "contact."
        )
    lines.append("")
    lines.append("## Disclosure Policy")
    lines.append("")
    lines.append(
        "This report is a draft, not sent. The disclosure deadline "
        "for publicly disclosing this vulnerability is %d days after "
        "the first report to the project team, unless the maintainer "
        "agrees a different timeline. Responsibility for developing "
        "and releasing a patch lies with the project team."
        % DISCLOSURE_DEADLINE_DAYS
    )
    lines.append("")
    lines.append(
        "Triage verdict: real, severity %s, confidence %s, check %s. "
        "This draft was generated from a triaged finding; it was not "
        "sent anywhere."
        % (
            severity,
            ("%.2f" % confidence if confidence is not None else "not stated"),
            check,
        )
    )
    lines.append("")
    draft, redaction_count, _hits = redact_mod.redact("\n".join(lines))
    return draft, redaction_count


def draft_private_disclosure_impl(
    finding,
    repo,
    maintainer_contact=None,
    include_fix=True,
    confirm_low_confidence=False,
    write_path=None,
):
    """Draft a private disclosure from a confirmed real finding.

    Returns a dict with draft_markdown (or None on refusal),
    written_to (or None), sent always False, and next_steps.
    No network call is made, nothing is sent, forked, pushed,
    emailed, or opened as a PR.
    """
    if not isinstance(finding, dict) or not finding:
        return {
            "draft_markdown": None,
            "written_to": None,
            "sent": False,
            "next_steps": [],
            "error": "finding is required and must be a validated "
            "finding object from triage_semgrep_finding or repo_scan",
        }
    verdict = finding.get("verdict")
    if verdict != "real":
        return {
            "draft_markdown": None,
            "written_to": None,
            "sent": False,
            "next_steps": [],
            "error": "Refusing to draft a disclosure: the finding "
            "verdict is %r, not real. Disclosures are drafted only "
            "for confirmed real findings." % (verdict,),
        }
    confidence = validate_mod.norm_confidence(finding.get("confidence"))
    if confidence is None or confidence < MIN_CONFIDENCE:
        if not confirm_low_confidence:
            return {
                "draft_markdown": None,
                "written_to": None,
                "sent": False,
                "next_steps": [],
                "error": "Refusing to draft a disclosure: confidence "
                "is %s, below %.2f. Confirm this finding explicitly "
                "with confirm_low_confidence=true to draft anyway."
                % (
                    ("%.2f" % confidence if confidence is not None else "not stated"),
                    MIN_CONFIDENCE,
                ),
            }
    if not repo or not str(repo).strip():
        return {
            "draft_markdown": None,
            "written_to": None,
            "sent": False,
            "next_steps": [],
            "error": "repo is required: owner/repo or a local path",
        }

    draft, redaction_count = build_draft(
        finding,
        repo,
        maintainer_contact=maintainer_contact,
        include_fix=include_fix,
    )
    next_steps = list(NEXT_STEPS_BASE)
    if not maintainer_contact or not str(maintainer_contact).strip():
        next_steps.append(NEXT_STEPS_NO_CONTACT)

    result = {
        "draft_markdown": draft,
        "written_to": None,
        "sent": False,
        "next_steps": next_steps,
        "repo": _single_line(repo),
        "title": _single_line(finding.get("title") or ""),
        "severity": validate_mod.norm_severity(finding.get("severity")),
        "confidence": confidence,
        "redacted": redaction_count > 0,
        "redaction_count": redaction_count,
        "error": None,
    }
    if write_path:
        try:
            Path(write_path).write_text(draft)
            result["written_to"] = str(write_path)
        except OSError as err:
            result["written_to"] = None
            result["error"] = "could not write draft to %s: %s" % (
                write_path,
                err,
            )
    return result
