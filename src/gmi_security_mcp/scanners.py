"""Local scanner runs: semgrep and osv-scanner.

Both scanners run locally as subprocesses, read-only on the repo.
No scanner output is trusted as a verdict: it is input to GMI
triage (semgrep) or a fact lookup against OSV (osv-scanner).

Semgrep config: the default is the set decided in Phase 1
research, DECISIONS.md section 5:
  p/default,p/security-audit,p/python,p/javascript,p/secrets
Note the form: semgrep takes one --config flag per config. A
single --config with a comma-separated list is NOT valid: semgrep
treats the whole string as one config name, fails to download it
(HTTP 404), and returns zero findings with the error buried in
its JSON output. This module always splits the list and passes
one --config flag per entry. Measured 2026-11-10: on
gmi-benchmark, ssh-mcp-server, and axios the full set returned
exactly the same findings as p/default alone.

Rule ids are mapped to the 7 known checks by an explicit table
plus keyword fallback. Unmapped rules report check "other", never
a known check they are not.
"""

import json
import re
import subprocess
from pathlib import Path

from . import lockfiles as lockfiles_mod
from . import osv as osv_mod
from . import rules as rules_mod

DEFAULT_SEMGREP_CONFIG = "p/default,p/security-audit,p/python,p/javascript,p/secrets"
DEFAULT_SEMGREP_CONFIGS = [
    "p/default",
    "p/security-audit",
    "p/python",
    "p/javascript",
    "p/secrets",
]

SEMGREP_TIMEOUT_SECONDS = 300
OSV_TIMEOUT_SECONDS = 300

EXCLUDED_DIR_NAMES = {
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".eggs",
}

# Explicit rule id to known-check mapping, from rules observed on
# the real test repos plus the dataset categories in the plan.
RULE_CHECK_MAP = {
    "html.security.audit.missing-integrity.missing-integrity": "other",
    "javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal": "Path traversal",
    "javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp": "other",
    "package_managers.npm.npm-missing-minimum-release-age.npm-missing-minimum-release-age": "other",
    "javascript.browser.security.wildcard-postmessage-configuration.wildcard-postmessage-configuration": "other",
    "javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring": "other",
    # Custom rules pack, Phase A3 (v0.5.0), rules/*.yaml. The
    # host-key rule maps to the check string the host-key oracle
    # matches on, not to one of the 7 known checks, because the
    # oracle keys off the wording "host key".
    "custom.ssh-missing-host-key-verification": (
        "Missing SSH host key verification"
    ),
    "custom.missing-auth": "Authentication and session flaws",
    "custom.missing-crypto-verification": "Weak cryptography",
    "custom.hardcoded-secret": "Hardcoded secrets",
    "custom.ssrf-user-input-to-fetch": (
        "Server-side request forgery (SSRF)"
    ),
    "custom.path-traversal-user-input-to-file": "Path traversal",
    "custom.sqli-user-input-to-query": "SQL injection",
    "custom.xss-user-input-to-html-sink": (
        "Cross-site scripting (XSS)"
    ),
}

_CHECK_KEYWORDS = [
    ("sql", "SQL injection"),
    ("xss", "Cross-site scripting (XSS)"),
    ("cross-site-scripting", "Cross-site scripting (XSS)"),
    ("ssrf", "Server-side request forgery (SSRF)"),
    ("server-side-request-forgery", "Server-side request forgery (SSRF)"),
    ("secret", "Hardcoded secrets"),
    ("hardcoded", "Hardcoded secrets"),
    ("password", "Hardcoded secrets"),
    ("api-key", "Hardcoded secrets"),
    ("crypto", "Weak cryptography"),
    ("md5", "Weak cryptography"),
    ("sha1", "Weak cryptography"),
    ("deserialization", "other"),
    ("path-traversal", "Path traversal"),
    ("traversal", "Path traversal"),
    ("jwt", "Authentication and session flaws"),
    ("auth", "Authentication and session flaws"),
    ("session", "Authentication and session flaws"),
]


def map_rule_to_check(rule_id):
    """Map a semgrep rule id to one of the 7 known checks, or other.

    Custom-rule ids arrive with the config directory prefix
    (rules.custom....), so the prefix is stripped first.
    """
    if not rule_id:
        return "other"
    stripped = rules_mod.strip_rule_prefix(rule_id)
    if stripped in RULE_CHECK_MAP:
        return RULE_CHECK_MAP[stripped]
    if rule_id in RULE_CHECK_MAP:
        return RULE_CHECK_MAP[rule_id]
    lowered = str(rule_id).lower()
    for keyword, check in _CHECK_KEYWORDS:
        if keyword in lowered:
            return check
    return "other"


_CONFIG_RE = re.compile(r"^[A-Za-z0-9_./\-]+$")


def parse_semgrep_config(value):
    """Split a semgrep config string into a list of config names.

    Accepts a comma-separated string ("p/default,p/python") or a
    list. Rejects empty entries and names with characters outside
    letters, digits, underscore, dot, slash, and hyphen.
    """
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value]
    else:
        items = [item.strip() for item in str(value or "").split(",")]
    configs = [item for item in items if item]
    if not configs:
        raise ValueError("semgrep_config is empty, name at least one config")
    for item in configs:
        if not _CONFIG_RE.match(item):
            raise ValueError("invalid semgrep config name: %r" % item)
    return configs


def _default_runner(cmd, timeout):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise RuntimeError("scanner binary not found: %s" % cmd[0])
    return proc.returncode, proc.stdout, proc.stderr


def _parse_semgrep_json(text):
    try:
        data = json.loads(text)
    except ValueError:
        raise RuntimeError("semgrep returned output that is not JSON")
    if not isinstance(data, dict) or "results" not in data:
        raise RuntimeError("semgrep returned JSON with no results array")
    findings = []
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        findings.append(
            {
                "rule_id": item.get("check_id"),
                "message": extra.get("message"),
                "file": item.get("path"),
                "line": start.get("line"),
                "semgrep_severity": extra.get("severity"),
                "check": map_rule_to_check(item.get("check_id")),
            }
        )
    errors = []
    for err in data.get("errors") or []:
        if isinstance(err, dict) and err.get("message"):
            errors.append(str(err["message"]))
    return findings, errors


def run_semgrep(repo_path, configs=None, timeout=SEMGREP_TIMEOUT_SECONDS,
                runner=None, binary="semgrep"):
    """Run semgrep on a repo path. Returns (findings, errors).

    configs is a list of config names, defaulting to
    DEFAULT_SEMGREP_CONFIGS. A scanner failure that produces no
    parseable JSON raises RuntimeError. Findings are raw semgrep
    output: not verdicts, not deduplicated, paths as semgrep
    reports them.
    """
    configs = list(configs) if configs else list(DEFAULT_SEMGREP_CONFIGS)
    cmd = [binary, "scan"]
    for config in configs:
        cmd += ["--config", config]
    cmd += ["--json", "--quiet", str(repo_path)]
    run = runner or _default_runner
    returncode, stdout, stderr = run(cmd, timeout)
    if returncode not in (0, 1):
        raise RuntimeError(
            "semgrep exited %d: %s" % (returncode, (stderr or stdout)[:500])
        )
    try:
        return _parse_semgrep_json(stdout)
    except RuntimeError:
        if returncode != 0:
            raise RuntimeError(
                "semgrep exited %d with unparseable output: %s"
                % (returncode, (stderr or stdout)[:500])
            )
        raise


def run_semgrep_custom_rules(repo_path, rules_dir, timeout=SEMGREP_TIMEOUT_SECONDS,
                             runner=None, binary="semgrep"):
    """Run the custom rules pack on a repo path. Returns (findings, errors).

    The rules directory is passed as its own --config value, never
    as part of a comma list. Each finding carries source
    custom-rule and the bare rule id (the config directory prefix
    semgrep adds is stripped). A config error is returned in
    errors, never as an empty finding list: a custom-rules run
    that errors is an error, not a clean scan.
    """
    if rules_dir is None:
        return [], ["custom rules pack not found, see list_rules"]
    cmd = [
        binary, "scan", "--config", str(rules_dir),
        "--json", "--quiet", str(repo_path),
    ]
    run = runner or _default_runner
    try:
        returncode, stdout, stderr = run(cmd, timeout)
    except RuntimeError as err:
        return [], [str(err)]
    if returncode not in (0, 1):
        return [], [
            "custom rules semgrep exited %d: %s"
            % (returncode, (stderr or stdout)[:500])
        ]
    try:
        findings, errors = _parse_semgrep_json(stdout)
    except RuntimeError as err:
        return [], [str(err)]
    for finding in findings:
        finding["rule_id"] = rules_mod.strip_rule_prefix(
            finding.get("rule_id")
        )
        finding["source"] = "custom-rule"
    return findings, errors


def deduplicate_findings(findings):
    """Drop duplicate findings by rule id, file, and line."""
    seen = set()
    out = []
    for finding in findings:
        key = (
            finding.get("rule_id"),
            finding.get("file"),
            finding.get("line"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def is_excluded_path(rel_path, include_tests=False):
    """True for paths repo_scan skips: VCS, vendors, build output,
    and test files and fixtures unless include_tests is true."""
    parts = Path(rel_path).parts
    if any(part in EXCLUDED_DIR_NAMES for part in parts):
        return True
    if not include_tests:
        lowered = rel_path.lower()
        if "/test/" in lowered or "/tests/" in lowered or "/test_" in lowered:
            return True
        name = Path(rel_path).name.lower()
        if name.startswith("test_") or name.endswith("_test.py"):
            return True
        if name.endswith((".test.js", ".test.ts", ".spec.js", ".spec.ts")):
            return True
    return False


def find_lockfiles(repo_path):
    """Lockfile paths under a repo, skipping excluded directories."""
    root = Path(repo_path)
    found = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIR_NAMES for part in rel.parts):
            continue
        if path.name in lockfiles_mod.LOCKFILE_NAMES:
            found.append(path)
    return found


def read_snippet(repo_path, rel_file, line, context_lines=25, max_chars=8000):
    """Code around a finding line, bounded by lines and characters.

    Returns None when the file cannot be read. Only the lines from
    (line - context) to (line + context) are read, so a large file
    is never loaded whole or sent whole to GMI. repo_scan also
    skips files over the per-file cap before this is called.
    """
    try:
        number = int(line)
    except (TypeError, ValueError):
        number = 1
    start = max(0, number - 1 - context_lines)
    end = number + context_lines
    wanted = []
    try:
        with open(Path(repo_path) / rel_file, errors="replace") as handle:
            for index, text_line in enumerate(handle):
                if index < start:
                    continue
                if index >= end:
                    break
                wanted.append(text_line.rstrip("\n"))
    except (OSError, ValueError):
        return None
    return "\n".join(wanted)[:max_chars]


def run_osv_scanner(lockfile_path, timeout=OSV_TIMEOUT_SECONDS,
                    runner=None, binary="osv-scanner"):
    """Run osv-scanner on one lockfile. Returns (advisories, scanned, vulnerable, error).

    Exit 0 means clean, exit 1 means vulnerabilities were found;
    both are normal results. Any other exit, or output that is not
    JSON, is returned as an error string with empty advisories.
    """
    cmd = [binary, "--format", "json", "--lockfile", str(lockfile_path)]
    run = runner or _default_runner
    try:
        returncode, stdout, stderr = run(cmd, timeout)
    except RuntimeError as err:
        return [], 0, 0, str(err)
    if returncode not in (0, 1):
        return [], 0, 0, "osv-scanner exited %d: %s" % (
            returncode,
            (stderr or stdout)[:500],
        )
    try:
        data = json.loads(stdout)
    except ValueError:
        return [], 0, 0, "osv-scanner returned output that is not JSON"
    advisories, scanned, vulnerable = osv_mod.parse_osv_scanner_output(data)
    return advisories, scanned, vulnerable, None
