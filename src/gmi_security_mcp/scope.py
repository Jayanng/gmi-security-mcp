"""Scope plugin, Phase A3 (v0.5.0), fail-closed, disabled by default.

Adapted in spirit from 0sec-labs/0 scope plugin
(https://github.com/0sec-labs/0, commit a891ba1, docs scope):
a scope file alone never activates checks, only an explicit
enable does; exclusions always win; an empty allowlist denies
all. Written in Python from those rules, not copied.

A scope file is JSON: {"in_scope": [...], "out_of_scope": [...]}.
Entries are hostnames (case-insensitive, a leading *. wildcard
only), or IPv4 CIDR ranges. IPv6 CIDR is NOT supported and is
refused with a clear message. An exact-host rule allows any path
and any port on that host: matching is on the host only.

Scope is a destination policy, NOT authorisation to test, and
NOT an OS sandbox. In v0.5.0 there is no live-web tool, so the
policy engine is used two ways: the hostname and CIDR matching
is implemented and tested for the live-target tools of a later
phase, and the enable/disable gate applies to the repo-path
tools now: repo_scan, verify_finding, and draft_private_disclosure
when it writes a file. With --require-scope (or env
GMI_REQUIRE_SCOPE=1) those tools refuse a repo with no enabled
scope policy, including localhost. Without it, scope is an
opt-in gate and tools run as before.

The --allow-apply double gate lives here too: any tool call that
writes a file needs the --allow-apply flag on the server command
line (or env GMI_ALLOW_APPLY=1) plus the exact candidate in the
call itself. A flag inside portable workflow JSON cannot grant
it, because the tools take no such parameter and this module
only reads the process-level flag and the environment.

Engagement profiles: standard (5 requests per second) and
conservative (1 request per second), full jitter, no WAF
evasion. In v0.5.0 the rate limit applies to GMI calls, because
there are no live web calls yet.

Scope state lives in this module for the server process
lifetime. A restarted server starts with scope disabled.
"""

import ipaddress
import json
import os
import random
import re
import time
from pathlib import Path
from urllib.parse import urlparse

SCOPE_WARNING = (
    "Scope is a destination policy, not authorisation to test, "
    "and not an OS sandbox. An in-scope entry does not permit "
    "testing that target; authorisation must come from the "
    "program or the target owner separately."
)

# Engagement profiles: requests per second for GMI calls.
PROFILES = {
    "standard": 5.0,
    "conservative": 1.0,
}
DEFAULT_PROFILE = "standard"

_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_WILDCARD_RE = re.compile(r"^\*\.[A-Za-z0-9.-]+$")

_require_scope = False
_allow_apply = False
_profile = DEFAULT_PROFILE
_enabled = {}


def set_require_scope(value):
    """Set the process-level --require-scope flag."""
    global _require_scope
    _require_scope = bool(value)


def require_scope_enabled():
    """True when --require-scope was passed or GMI_REQUIRE_SCOPE=1."""
    if _require_scope:
        return True
    return os.environ.get("GMI_REQUIRE_SCOPE", "").strip() == "1"


def set_allow_apply(value):
    """Set the process-level --allow-apply flag."""
    global _allow_apply
    _allow_apply = bool(value)


def allow_apply_enabled():
    """True when --allow-apply was passed or GMI_ALLOW_APPLY=1.

    Only the process flag and the environment grant it. No tool
    parameter and no workflow JSON can grant it.
    """
    if _allow_apply:
        return True
    return os.environ.get("GMI_ALLOW_APPLY", "").strip() == "1"


def set_profile(name):
    """Set the engagement profile. Returns an error string, or None."""
    global _profile
    if name is None:
        _profile = DEFAULT_PROFILE
        return None
    if str(name) not in PROFILES:
        return "unknown engagement profile %r, use standard or conservative" % (
            name,
        )
    _profile = str(name)
    return None


def get_profile():
    """Current engagement profile name."""
    return _profile


def rate_limit_interval(profile=None):
    """Seconds between GMI calls for a profile. None when unknown."""
    name = profile or _profile
    rps = PROFILES.get(str(name))
    if rps is None:
        return None
    return 1.0 / rps


class RateLimiter:
    """Jittered throttle between GMI calls.

    After each call the next call waits interval + uniform(0,
    interval): full jitter, average 1.5 intervals, always under
    the profile rate. time_fn and sleep_fn are injectable so
    tests can run without sleeping.
    """

    def __init__(self, interval, time_fn=None, sleep_fn=None,
                 random_fn=None):
        self.interval = float(interval)
        self._time = time_fn or time.monotonic
        self._sleep = sleep_fn or time.sleep
        self._random = random_fn or random.uniform
        self._last = None

    def wait_before_call(self):
        """Sleep when the last call was too recent. Returns seconds slept."""
        now = self._time()
        if self._last is None:
            self._last = now
            return 0.0
        delay = self.interval + self._random(0, self.interval)
        elapsed = now - self._last
        to_sleep = delay - elapsed
        if to_sleep > 0:
            self._sleep(to_sleep)
            self._last = self._time()
            return to_sleep
        self._last = now
        return 0.0


_limiter = None


def get_limiter():
    """Module-level limiter for the current profile, created lazily."""
    global _limiter
    interval = rate_limit_interval()
    if _limiter is None or _limiter.interval != interval:
        _limiter = RateLimiter(interval)
    return _limiter


def throttle_gmi_call():
    """Wait per the engagement profile before a GMI call. No-op
    when the limiter cannot be built."""
    try:
        get_limiter().wait_before_call()
    except (ValueError, TypeError, OSError):
        return


def _parse_entry(entry):
    """Parse one scope entry into ("host", value) or ("cidr", network).

    Returns (kind, value, error). IPv6, including IPv6 CIDR, is
    refused with a clear message. A bare "*" is refused: only a
    leading "*." wildcard is allowed.
    """
    if not isinstance(entry, str) or not entry.strip():
        return None, None, "scope entry must be a non-empty string"
    text = entry.strip()
    if ":" in text:
        return None, None, (
            "IPv6 is not supported in scope entries, refusing %r: "
            "use an IPv4 CIDR or a hostname instead" % text
        )
    if "/" in text:
        try:
            network = ipaddress.IPv4Network(text, strict=False)
        except ValueError:
            return None, None, "invalid IPv4 CIDR in scope: %r" % text
        return "cidr", network, None
    if text == "*":
        return None, None, (
            "a bare * is not a scope entry: use a leading *. "
            "wildcard such as *.example.com, or an exact hostname"
        )
    lowered = text.lower()
    if lowered.startswith("*."):
        if not _WILDCARD_RE.match(lowered):
            return None, None, "invalid wildcard scope entry: %r" % text
        return "host", lowered, None
    labels = lowered.split(".")
    if not all(_HOSTNAME_LABEL_RE.match(label) for label in labels):
        return None, None, "invalid hostname in scope: %r" % text
    return "host", lowered, None


def parse_scope_file(scope_file):
    """Parse and validate a scope file.

    Returns (policy, error): policy is {"in_scope": [...],
    "out_of_scope": [...]} with parsed entries, error is None on
    success or a message string. The file must be JSON with both
    lists present; unknown top-level keys are refused.
    """
    if not scope_file or not str(scope_file).strip():
        return None, "scope_file is required"
    path = Path(str(scope_file)).expanduser()
    if not path.is_file():
        return None, "scope file does not exist: %s" % scope_file
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return None, "scope file %s does not parse: %s" % (scope_file, err)
    if not isinstance(data, dict):
        return None, "scope file must be a JSON object with in_scope and out_of_scope"
    unknown = sorted(set(data) - {"in_scope", "out_of_scope"})
    if unknown:
        return None, "scope file has unknown keys: %s" % ", ".join(unknown)
    if not isinstance(data.get("in_scope"), list) or not isinstance(
        data.get("out_of_scope"), list
    ):
        return None, "scope file in_scope and out_of_scope must be arrays"
    policy = {"in_scope": [], "out_of_scope": []}
    for key in ("in_scope", "out_of_scope"):
        for entry in data[key]:
            kind, value, error = _parse_entry(entry)
            if error is not None:
                return None, error
            policy[key].append((kind, value))
    return policy, None


def _extract_host(target):
    """Host part of a hostname, host:port, or URL, lowercased, or None."""
    if not target or not str(target).strip():
        return None
    text = str(target).strip()
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname
        return host.lower() if host else None
    if text.startswith("["):
        return None
    host = text.split("/")[0].split(":")[0].strip()
    return host.lower() if host else None


def _host_matches(host, entry):
    """True when a lowercased host matches one parsed entry."""
    kind, value = entry
    if kind == "cidr":
        try:
            address = ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return address in value
    if value.startswith("*."):
        suffix = value[1:]
        return host.endswith(suffix) and host != value[2:]
    return host == value


def is_allowed(policy, target):
    """True when a target host is allowed by a parsed policy.

    Exclusions always win, and an empty allowlist denies all.
    Exact-host rules allow any path and any port on that host.
    """
    if not isinstance(policy, dict):
        return False
    host = _extract_host(target)
    if host is None:
        return False
    for entry in policy.get("out_of_scope") or []:
        if _host_matches(host, entry):
            return False
    in_scope = policy.get("in_scope") or []
    if not in_scope:
        return False
    return any(_host_matches(host, entry) for entry in in_scope)


def _resolve_repo_path(repo_path):
    if not repo_path or not str(repo_path).strip():
        return None
    try:
        root = Path(str(repo_path)).expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    if not root.is_dir():
        return None
    return root


def enable_scope(scope_file, repo_path):
    """Enable scope for one repo from a scope file.

    A scope file alone never activates checks: only this call
    does. Returns (result, error): result carries enabled true,
    the in-scope and out-of-scope lists as written, and the
    warning. error is a message string, or None.
    """
    root = _resolve_repo_path(repo_path)
    if root is None:
        return None, "repo_path is not an existing directory: %s" % repo_path
    policy, error = parse_scope_file(scope_file)
    if error is not None:
        return None, error
    with open(Path(str(scope_file)).expanduser(), encoding="utf-8") as handle:
        raw = json.load(handle)
    _enabled[str(root)] = {
        "policy": policy,
        "scope_file": str(scope_file),
        "profile": _profile,
    }
    return {
        "enabled": True,
        "repo_path": str(root),
        "scope_file": str(scope_file),
        "in_scope": list(raw.get("in_scope") or []),
        "out_of_scope": list(raw.get("out_of_scope") or []),
        "profile": _profile,
        "rate_limit_rps": PROFILES[_profile],
        "warning": SCOPE_WARNING,
        "error": None,
    }, None


def disable_scope(repo_path):
    """Disable scope for one repo. Returns (result, error)."""
    root = _resolve_repo_path(repo_path)
    if root is None:
        return None, "repo_path is not an existing directory: %s" % repo_path
    _enabled.pop(str(root), None)
    return {
        "enabled": False,
        "repo_path": str(root),
        "warning": (
            "Scope is disabled for this repo. Tools will now refuse "
            "if --require-scope is set, because there is no scope "
            "policy for the repo."
        ),
        "error": None,
    }, None


def is_scope_enabled(repo_path):
    """True when scope is enabled for a repo path."""
    root = _resolve_repo_path(repo_path)
    if root is None:
        return False
    return str(root) in _enabled


def is_path_in_scoped_repo(path):
    """True when a file path sits inside a repo with scope enabled.

    Used for file writes such as disclosure drafts: the write
    target must be inside a scoped repo, not just any directory.
    """
    if not path or not str(path).strip():
        return False
    try:
        target = Path(str(path)).expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    for root_text in _enabled:
        root = Path(root_text)
        if target == root or root in target.parents:
            return True
    return False


def get_scope_policy(repo_path):
    """Parsed policy enabled for a repo path, or None."""
    root = _resolve_repo_path(repo_path)
    if root is None:
        return None
    entry = _enabled.get(str(root))
    return entry["policy"] if entry is not None else None


def clear_scope_state():
    """Drop all enabled scope state. Tests only."""
    _enabled.clear()


def check_repo_scope(repo_path):
    """Refusal message when --require-scope is set and no scope
    policy is enabled for the repo, or None when the call may
    proceed. Without --require-scope this always returns None:
    scope is an opt-in gate, disabled by default."""
    if not require_scope_enabled():
        return None
    if not repo_path or not str(repo_path).strip():
        return (
            "refusing: --require-scope is set and no repo_path was "
            "given, so no scope policy applies"
        )
    if is_scope_enabled(repo_path):
        return None
    return (
        "refusing: --require-scope is set and no scope policy is "
        "enabled for %s. Run scope_enable with a scope file for "
        "this repo first." % repo_path
    )


def check_allow_apply(action):
    """Refusal message when a file-writing call lacks --allow-apply,
    or None when the write may proceed. The exact candidate is
    approved by being in the call itself; this check only gates
    on the process-level flag."""
    if allow_apply_enabled():
        return None
    return (
        "refusing to %s: --allow-apply was not passed on the server "
        "command line, so this file-writing call is refused. "
        "Re-run the server with --allow-apply and approve the exact "
        "candidate in the call. A flag in workflow JSON cannot "
        "grant it." % action
    )
