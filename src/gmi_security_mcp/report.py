"""JSON and Markdown report output for repo_scan.

The JSON report is the tool result. The Markdown report is the
same data rendered for a human, written only to a path the caller
asked for. Neither ever contains a key or a full file: findings
carry the snippet verdict fields only, not the code sent to GMI.
"""

from . import validate as validate_mod


def build_report(**fields):
    """Assemble the repo_scan report dict from named fields."""
    report = {
        "repo_path": fields.get("repo_path"),
        "stage1_model": fields.get("stage1_model"),
        "stage2_model": fields.get("stage2_model"),
        "threshold": fields.get("threshold"),
        "semgrep_config": fields.get("semgrep_config"),
        "files_scanned": fields.get("files_scanned", 0),
        "findings_total": fields.get("findings_total", 0),
        "findings_triaged": fields.get("findings_triaged", 0),
        "findings_real": fields.get("findings_real", 0),
        "findings_false_positive": fields.get("findings_false_positive", 0),
        "findings_no_verdict": fields.get("findings_no_verdict", 0),
        "findings": fields.get("findings", []),
        "skipped": fields.get("skipped", []),
        "osv": fields.get("osv"),
        "total_cost_usd": fields.get("total_cost_usd", 0.0),
        "estimate_usd": fields.get("estimate_usd"),
        "max_estimate_usd": fields.get("max_estimate_usd"),
        "stopped_early": fields.get("stopped_early", False),
        "stopped_reason": fields.get("stopped_reason"),
        "dry_run": fields.get("dry_run", False),
        "errors": fields.get("errors", []),
        "warnings": fields.get("warnings", []),
    }
    return report


def _md_finding(finding):
    esc = validate_mod.esc
    verdict = finding.get("verdict") or "no verdict"
    return (
        "- **%s:%s** (%s) - %s, %s, confidence %s\n"
        "  Rule: `%s`. %s\n"
        "  Fix: %s\n"
        "  Stage: %s, cost $%.6f\n"
        % (
            esc(str(finding.get("file"))),
            esc(str(finding.get("line"))),
            esc(str(finding.get("check") or "other")),
            verdict,
            esc(str(finding.get("severity") or "low")),
            esc(str(finding.get("confidence"))),
            esc(str(finding.get("rule_id"))),
            esc(str(finding.get("reason") or finding.get("error") or "")),
            esc(str(finding.get("fix") or "")),
            esc(str(finding.get("stage_used") or finding.get("stage") or "")),
            finding.get("cost_usd") or 0,
        )
    )


def report_to_markdown(report):
    """Render a repo_scan report dict as Markdown."""
    esc = validate_mod.esc
    lines = []
    lines.append("# Security scan report: %s" % esc(str(report.get("repo_path"))))
    lines.append("")
    lines.append(
        "Stage 1: %s. Stage 2: %s. Threshold: %s. Semgrep: %s."
        % (
            esc(str(report.get("stage1_model"))),
            esc(str(report.get("stage2_model"))),
            esc(str(report.get("threshold"))),
            esc(str(report.get("semgrep_config"))),
        )
    )
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append("- Findings (semgrep, after exclusions and dedup): %d" % report.get("findings_total", 0))
    lines.append("- Triaged: %d" % report.get("findings_triaged", 0))
    lines.append("- Real: %d" % report.get("findings_real", 0))
    lines.append("- False positive: %d" % report.get("findings_false_positive", 0))
    lines.append("- No verdict: %d" % report.get("findings_no_verdict", 0))
    lines.append("- Total cost: $%.6f (estimate was $%s, max $%s)" % (
        report.get("total_cost_usd") or 0,
        report.get("estimate_usd"),
        report.get("max_estimate_usd"),
    ))
    if report.get("stopped_early"):
        lines.append("- Stopped early: %s" % esc(str(report.get("stopped_reason"))))
    if report.get("dry_run"):
        lines.append("- Dry run: no GMI calls were made, no verdicts.")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if report.get("findings"):
        for finding in report["findings"]:
            lines.append(_md_finding(finding))
    else:
        lines.append("No findings triaged.")
    lines.append("")
    skipped = report.get("skipped") or []
    if skipped:
        lines.append("## Skipped")
        lines.append("")
        for item in skipped:
            lines.append(
                "- %s:%s - %s"
                % (
                    esc(str(item.get("file"))),
                    esc(str(item.get("line"))),
                    esc(str(item.get("reason"))),
                )
            )
        lines.append("")
    osv = report.get("osv")
    if osv:
        lines.append("## Dependencies (osv-scanner)")
        lines.append("")
        for section in osv.get("lockfiles") or []:
            lines.append(
                "- %s: %d packages scanned, %d vulnerable"
                % (
                    esc(str(section.get("lockfile_path"))),
                    section.get("packages_scanned", 0),
                    section.get("vulnerable_packages", 0),
                )
            )
            for advisory in section.get("advisories") or []:
                lines.append(
                    "  - %s %s %s, fixed in %s, CVSS %s: %s"
                    % (
                        esc(str(advisory.get("package"))),
                        esc(str(advisory.get("installed_version"))),
                        esc(str(advisory.get("id"))),
                        esc(str(advisory.get("fixed_version"))),
                        esc(str(advisory.get("cvss_score"))),
                        esc(str(advisory.get("summary") or "")),
                    )
                )
            if section.get("error"):
                lines.append("  - Error: %s" % esc(str(section["error"])))
            if section.get("note"):
                lines.append("  - Note: %s" % esc(str(section["note"])))
        if not osv.get("lockfiles"):
            lines.append("- No lockfile found in the repo, so no dependency check ran.")
        lines.append("")
    errors = report.get("errors") or []
    if errors:
        lines.append("## Errors")
        lines.append("")
        for error in errors:
            lines.append("- %s" % esc(str(error)))
        lines.append("")
    warnings = report.get("warnings") or []
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in warnings:
            lines.append("- %s" % esc(str(warning)))
        lines.append("")
    lines.append(
        "Unparsed and errored findings are no verdict, not clean. "
        "A verdict is a triage opinion on the code shown, not proof."
    )
    lines.append("")
    return "\n".join(lines)
