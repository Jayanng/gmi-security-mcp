"""Custom semgrep rules pack registry, Phase A3 (v0.5.0).

The rules themselves live as YAML in rules/ at the repo root, one
file per rule. This module is the registry for list_rules and the
loader the server uses to find the pack and to normalise the rule
ids semgrep reports.

Semgrep prefixes a rule id with the config directory name when
the config is a directory or a file in a directory, for example
rules.custom.ssh-missing-host-key-verification for the rule id
custom.ssh-missing-host-key-verification. The prefix is the
directory basename, so it changes with the checkout path. The
registry knows the bare ids, and strip_rule_prefix matches a
reported id by suffix, so the server never depends on the prefix.

The registry is the source of truth for list_rules metadata
(name, category, severity, description, enabled). The YAML files
are the source of truth for what semgrep matches. A test asserts
the two agree on every rule id.
"""

import os
from pathlib import Path

import yaml

# One entry per rule, in the order list_rules returns them. Category
# is one of the 7 known checks. The host-key rule maps to
# Authentication and session flaws; the finding it returns carries
# the check string "Missing SSH host key verification", which is
# the wording the host-key oracle matches on. Severity is the
# semgrep severity from the YAML file, not a triage severity.
RULES = [
    {
        "id": "custom.ssh-missing-host-key-verification",
        "name": "Missing SSH host key verification",
        "category": "Authentication and session flaws",
        "severity": "WARNING",
        "file": "ssh-host-key.yaml",
        "description": (
            "SSH client configuration with no host key "
            "verification: no hostVerifier, knownHosts, or "
            "trustedHostKey. The client accepts any host key, so "
            "any server can impersonate the configured host."
        ),
        "enabled": True,
    },
    {
        "id": "custom.missing-auth",
        "name": "Missing authentication on a route",
        "category": "Authentication and session flaws",
        "severity": "WARNING",
        "file": "auth.yaml",
        "description": (
            "Route registered with no authentication middleware "
            "visible in the call. Triage must decide whether the "
            "route needs auth; public routes are false positives."
        ),
        "enabled": True,
    },
    {
        "id": "custom.missing-crypto-verification",
        "name": "Missing crypto verification",
        "category": "Weak cryptography",
        "severity": "ERROR",
        "file": "crypto-verify.yaml",
        "description": (
            "Token or signature used without verification: "
            "jwt.decode does not verify, a verify call with "
            "ignoreExpiration true skips expiry, a decode with "
            "verify_signature false skips verification."
        ),
        "enabled": True,
    },
    {
        "id": "custom.hardcoded-secret",
        "name": "Hardcoded secret",
        "category": "Hardcoded secrets",
        "severity": "WARNING",
        "file": "secret.yaml",
        "description": (
            "Secret-shaped value assigned directly in code. A "
            "hint, not a verdict: triage must still run, because "
            "example keys and placeholders match the same shapes."
        ),
        "enabled": True,
    },
    {
        "id": "custom.ssrf-user-input-to-fetch",
        "name": "SSRF, user input to fetch",
        "category": "Server-side request forgery (SSRF)",
        "severity": "ERROR",
        "file": "ssrf.yaml",
        "description": (
            "User input reaches a fetch or request call with no "
            "allowlist check in the code shown."
        ),
        "enabled": True,
    },
    {
        "id": "custom.path-traversal-user-input-to-file",
        "name": "Path traversal, user input to file path",
        "category": "Path traversal",
        "severity": "ERROR",
        "file": "path-traversal.yaml",
        "description": (
            "User input reaches a file open or path join with no "
            "base-directory check in the code shown."
        ),
        "enabled": True,
    },
    {
        "id": "custom.sqli-user-input-to-query",
        "name": "SQL injection, user input to query",
        "category": "SQL injection",
        "severity": "ERROR",
        "file": "sqli.yaml",
        "description": (
            "User input reaches a database query string with no "
            "parameterisation in the code shown."
        ),
        "enabled": True,
    },
    {
        "id": "custom.xss-user-input-to-html-sink",
        "name": "XSS, user input to HTML sink",
        "category": "Cross-site scripting (XSS)",
        "severity": "ERROR",
        "file": "xss.yaml",
        "description": (
            "User input reaches an HTML sink with no escaping in "
            "the code shown."
        ),
        "enabled": True,
    },
]

RULE_IDS = tuple(rule["id"] for rule in RULES)


def strip_rule_prefix(check_id):
    """Return the bare custom rule id for a semgrep check_id.

    Semgrep reports rules.<id> when the config is the rules/
    directory, and <dirname>.<id> for other directories. A bare
    id is returned unchanged. An id that matches no known custom
    rule is returned unchanged, never guessed.
    """
    if not check_id:
        return check_id
    text = str(check_id)
    for rule_id in RULE_IDS:
        if text == rule_id or text.endswith("." + rule_id):
            return rule_id
    return text


def find_rules_dir(explicit=None):
    """Locate the rules/ directory, or None when it is not found.

    Order: an explicit path, the GMI_SECURITY_MCP_RULES_DIR
    environment variable, then a rules/ directory found by walking
    up from this file (a repo checkout), then a rules/ directory
    next to the installed package. An explicit path or an env
    value that does not contain the pack is authoritative: it
    returns None instead of silently falling back to another
    checkout. A missing pack is not an error here: the caller
    reports it and runs the default rules only.
    """
    if explicit:
        candidate = Path(explicit).expanduser()
        if (candidate / "ssh-host-key.yaml").is_file():
            return candidate
        return None
    env_dir = os.environ.get("GMI_SECURITY_MCP_RULES_DIR", "").strip()
    if env_dir:
        candidate = Path(env_dir).expanduser()
        if (candidate / "ssh-host-key.yaml").is_file():
            return candidate
        return None
    here = Path(__file__).resolve()
    candidates = []
    for parent in [here.parent] + list(here.parents):
        candidates.append(parent / "rules")
    candidates.append(here.parent / "rules")
    for candidate in candidates:
        try:
            marker = candidate / "ssh-host-key.yaml"
        except (OSError, ValueError):
            continue
        if marker.is_file():
            return candidate
    return None


def load_rules(rules_dir=None):
    """Load the registry, checked against the YAML files.

    Returns (rules, error): rules is the list of registry dicts
    with the YAML severity filled in, error is None on success or
    a message string. A missing directory, an unparseable YAML
    file, or a YAML rule id that disagrees with the registry is an
    error, never a silent empty list.
    """
    directory = find_rules_dir(rules_dir)
    if directory is None:
        return [], (
            "custom rules pack not found: no rules/ directory with "
            "ssh-host-key.yaml was found. Set "
            "GMI_SECURITY_MCP_RULES_DIR to the rules/ directory, or "
            "run from a repo checkout."
        )
    loaded = []
    for entry in RULES:
        path = directory / entry["file"]
        if not path.is_file():
            return [], "custom rule file is missing: %s" % path
        try:
            with open(path, encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        except (OSError, ValueError, yaml.YAMLError) as err:
            return [], "custom rule file %s does not parse: %s" % (
                entry["file"],
                err,
            )
        if not isinstance(data, dict) or not isinstance(
            data.get("rules"), list
        ):
            return [], "custom rule file %s has no rules list" % (
                entry["file"],
            )
        yaml_ids = [
            item.get("id")
            for item in data["rules"]
            if isinstance(item, dict)
        ]
        if entry["id"] not in yaml_ids:
            return [], (
                "custom rule file %s does not contain rule %s"
                % (entry["file"], entry["id"])
            )
        item = dict(entry)
        for rule in data["rules"]:
            if isinstance(rule, dict) and rule.get("id") == entry["id"]:
                severity = str(rule.get("severity") or "").strip()
                if severity:
                    item["severity"] = severity
        loaded.append(item)
    return loaded, None


def list_rules(category=None, rules_dir=None):
    """Rules for the list_rules tool, optionally filtered by category.

    Returns a dict with rules, rules_dir, and error. An unknown
    category is an error, never an empty list.
    """
    if category is not None and category not in {
        rule["category"] for rule in RULES
    }:
        return {
            "rules": [],
            "rules_dir": None,
            "error": "unknown rule category %r" % (category,),
        }
    rules, error = load_rules(rules_dir)
    if error is not None:
        return {"rules": [], "rules_dir": None, "error": error}
    directory = find_rules_dir(rules_dir)
    out = []
    for rule in rules:
        if category is not None and rule["category"] != category:
            continue
        out.append(
            {
                "id": rule["id"],
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "description": rule["description"],
                "enabled": bool(rule["enabled"]),
            }
        )
    return {
        "rules": out,
        "rules_dir": str(directory) if directory is not None else None,
        "error": None,
    }
