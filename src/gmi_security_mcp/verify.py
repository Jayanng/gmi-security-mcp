"""Deterministic verification oracles and PoC runner, Phase A1 (v0.5.0).

PoV-is-truth, adapted from 0sec-labs/0:
- Source: https://github.com/0sec-labs/0, commit
  a891ba1cbf95a74e29f1e9789ebf1000ebad91a3, dual MIT OR Apache-2.0,
  docs triage.md section 3 (per-class oracles) and
  verification-result.md (VerificationResult shape). The oracle
  rules below are adapted from that doc into Python; no 0
  TypeScript code is copied. Our code is MIT, see NOTICE.
- A finding is confirmed only when a deterministic oracle
  reproduces it. A model verdict alone never sets confirmation.
- SQLi needs at least 2 of boolean response-length difference,
  timing delta, SQL error signatures. Reflected XSS needs a unique
  token captured in a dialog or DOM sink; HTML reflection alone is
  not confirmation. SSRF needs a nonce-matched request to a
  temporary local collector. Path traversal needs a Linux
  /etc/passwd signature in the returned content; no Windows
  equivalent is claimed. The missing SSH host key verification
  oracle is the proof for the ssh-mcp-server host-key finding:
  a connection to a test SSH server with a wrong host key must
  succeed with no hostVerifier and no known_hosts check, and
  fail after the fix.
- Other categories have no oracle in v0.5.0: verify_finding
  returns skipped with "no oracle for this category". No oracle
  is invented, and no model verdict is called an oracle.

PoC runner safety, Python standard practice:
- subprocess list-form commands only, no shell (subprocess docs:
  never use shell=True with untrusted input; pass the command as
  a sequence). A timeout is always set. The working directory is
  inside the repo. tempfile is used for the PoC file, inside the
  repo, and removed after the run. The child environment is
  scrubbed of credential-shaped variables, so a PoC can never
  read the GMI key from its environment.
- No network except to a local collector the PoC itself starts
  (127.0.0.1). The runner cannot enforce that from outside the
  process; the PoC is reviewed before it runs, and the host
  warning in the result says so plainly.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Timeout for one PoC run, seconds. A PoC that runs longer is an
# error, never a pass and never a not_reproduced.
POC_TIMEOUT_SECONDS = 60

# Shell metacharacters: any of these in a PoC command refuses the
# run. List-form commands only, no shell.
_SHELL_META_RE = re.compile(r"[;&|`$><\n\r]")

# SQL error signatures, as the oracle looks for them in PoC output.
SQL_ERROR_SIGNATURES = (
    "syntax error",
    "sqlite3.operationalerror",
    "sqlite error",
    "sql syntax",
    "unclosed quotation",
    "unterminated string",
    "unrecognized token",
    "ora-",
    "psqlexception",
    "mysql",
    "you have an error in your sql syntax",
)

# Linux /etc/passwd signature: root entry, uid 0, gid 0.
PASSWD_SIGNATURE_RE = re.compile(r"^root:[^:\n]*:0:0:", re.M)

# Categories with an oracle in v0.5.0.
ORACLE_CATEGORIES = ("sqli", "xss", "ssrf", "path_traversal", "host_key")

# Finding check strings, as triage returns them, mapped to oracle
# categories. Anything else has no oracle.
_CHECK_TO_CATEGORY = {
    "SQL injection": "sqli",
    "Cross-site scripting (XSS)": "xss",
    "Server-side request forgery (SSRF)": "ssrf",
    "Path traversal": "path_traversal",
}


def category_for_check(check):
    """Oracle category for a finding check string, or None.

    The missing SSH host key verification finding has no triage
    check string of its own, so it is matched on its wording.
    """
    if not check:
        return None
    text = str(check)
    if text in _CHECK_TO_CATEGORY:
        return _CHECK_TO_CATEGORY[text]
    lowered = text.lower()
    if "host key" in lowered or "hostkey" in lowered:
        return "host_key"
    return None


def sha256_hex(data):
    """SHA-256 hex digest of bytes or text."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _evidence_from_output(output):
    """Parse the last JSON object in PoC output, or None.

    PoCs print one JSON evidence object as their last line, but
    the output may carry other text before or after it, so every
    brace position is tried and the last object that parses as a
    dict wins. Falls back to None when there is no JSON at all.
    """
    if not output:
        return None
    decoder = json.JSONDecoder()
    last = None
    index = 0
    while True:
        start = output.find("{", index)
        if start == -1:
            break
        try:
            value, end = decoder.raw_decode(output[start:])
        except (ValueError, TypeError):
            index = start + 1
            continue
        if isinstance(value, dict):
            last = value
        index = start + max(end, 1)
    return last


def _assertion(name, passed, detail):
    return {"name": name, "passed": bool(passed), "detail": str(detail)[:500]}


def oracle_sqli(finding, output, exit_code):
    """SQLi oracle: at least 2 of 3 signals.

    Signals: boolean response-length difference, timing delta,
    SQL error signatures. One signal alone is not confirmation.
    Evidence object: boolean_length_diff (bool), timing_delta_ms
    (number), sql_error (bool or string).
    """
    evidence = _evidence_from_output(output) or {}
    boolean_diff = bool(evidence.get("boolean_length_diff"))
    timing_ms = evidence.get("timing_delta_ms")
    try:
        timing_ms = float(timing_ms) if timing_ms is not None else 0.0
    except (TypeError, ValueError):
        timing_ms = 0.0
    timing_signal = timing_ms >= 500.0
    sql_error = evidence.get("sql_error")
    if isinstance(sql_error, str):
        sql_error_signal = bool(sql_error.strip())
    else:
        sql_error_signal = bool(sql_error)
    if not sql_error_signal and output:
        lowered = output.lower()
        sql_error_signal = any(sig in lowered for sig in SQL_ERROR_SIGNATURES)
    signals = sum((boolean_diff, timing_signal, sql_error_signal))
    assertions = [
        _assertion(
            "boolean_length_diff",
            boolean_diff,
            "boolean probe changed the response length"
            if boolean_diff
            else "no boolean response-length difference observed",
        ),
        _assertion(
            "timing_delta",
            timing_signal,
            "timing delta %.0f ms" % timing_ms,
        ),
        _assertion(
            "sql_error_signature",
            sql_error_signal,
            "SQL error signature observed"
            if sql_error_signal
            else "no SQL error signature observed",
        ),
    ]
    if signals >= 2:
        return "reproduced", assertions
    return "not_reproduced", assertions


def oracle_xss(finding, output, exit_code):
    """XSS oracle: unique token captured in a dialog or DOM sink.

    HTML reflection alone is not confirmation. Evidence object:
    token (str), captured_in ("dialog" or "dom_sink"), token_seen
    (bool). Text fallback: the token appears in the output together
    with a sink word (dialog, innerHTML, document.write, sink).
    """
    evidence = _evidence_from_output(output) or {}
    token = str(evidence.get("token") or "").strip()
    captured_in = str(evidence.get("captured_in") or "").strip().lower()
    token_seen = bool(evidence.get("token_seen"))
    if token and captured_in in ("dialog", "dom_sink") and token_seen:
        return "reproduced", [
            _assertion(
                "token_captured_in_sink",
                True,
                "unique token captured in %s" % captured_in,
            )
        ]
    if token and output and token in output:
        lowered = output.lower()
        sink_words = ("dialog", "dom sink", "innerhtml", "document.write")
        if any(word in lowered for word in sink_words):
            return "reproduced", [
                _assertion(
                    "token_captured_in_sink",
                    True,
                    "unique token found in a DOM sink in the PoC output",
                )
            ]
        return "not_reproduced", [
            _assertion(
                "token_captured_in_sink",
                False,
                "token was reflected but not captured in a dialog or DOM sink",
            )
        ]
    return "not_reproduced", [
        _assertion(
            "token_captured_in_sink",
            False,
            "no unique token captured in a dialog or DOM sink",
        )
    ]


def oracle_ssrf(finding, output, exit_code):
    """SSRF oracle: nonce-matched request to a local collector.

    Evidence object: nonce (str), collector_received_nonce (str).
    The two must match and be non-empty. A request without the
    nonce is not confirmation.
    """
    evidence = _evidence_from_output(output) or {}
    nonce = str(evidence.get("nonce") or "").strip()
    received = str(evidence.get("collector_received_nonce") or "").strip()
    if nonce and received and nonce == received:
        return "reproduced", [
            _assertion(
                "nonce_matched_collector_request",
                True,
                "collector received the nonce",
            )
        ]
    if nonce and not received:
        detail = "nonce was sent but the collector saw no request"
    elif nonce and received:
        detail = "collector saw a nonce that does not match the sent nonce"
    else:
        detail = "no nonce in the PoC evidence"
    return "not_reproduced", [
        _assertion("nonce_matched_collector_request", False, detail)
    ]


def oracle_path_traversal(finding, output, exit_code):
    """Path traversal oracle: /etc/passwd signature in content.

    Evidence object: content (str) or target_file (str). The Linux
    root entry signature must appear. No Windows equivalent is
    claimed.
    """
    evidence = _evidence_from_output(output) or {}
    content = evidence.get("content")
    haystack = str(content) if content is not None else (output or "")
    if PASSWD_SIGNATURE_RE.search(haystack):
        return "reproduced", [
            _assertion(
                "passwd_signature_in_content",
                True,
                "Linux /etc/passwd signature found in returned content",
            )
        ]
    return "not_reproduced", [
        _assertion(
            "passwd_signature_in_content",
            False,
            "no /etc/passwd signature in returned content",
        )
    ]


def oracle_host_key(finding, output, exit_code):
    """Missing SSH host key verification oracle.

    Evidence object: connected (bool), host_key_verified (bool),
    host_key_mismatch (bool). Confirmation needs a connection that
    succeeded while the host key was wrong and unverified: no
    hostVerifier and no known_hosts check. A connection that
    failed, or one that verified the key, is not confirmation.
    """
    evidence = _evidence_from_output(output) or {}
    connected = bool(evidence.get("connected"))
    verified = bool(evidence.get("host_key_verified"))
    mismatch = bool(evidence.get("host_key_mismatch"))
    if connected and mismatch and not verified:
        return "reproduced", [
            _assertion(
                "wrong_host_key_connection_succeeded",
                True,
                "connected to a test SSH server with a wrong host key "
                "and no verification",
            )
        ]
    if connected and verified:
        detail = "connection succeeded but the host key was verified"
    elif not connected:
        detail = "connection to the test SSH server did not succeed"
    else:
        detail = "connection succeeded without a host key mismatch to prove it"
    return "not_reproduced", [
        _assertion("wrong_host_key_connection_succeeded", False, detail)
    ]


ORACLES = {
    "sqli": oracle_sqli,
    "xss": oracle_xss,
    "ssrf": oracle_ssrf,
    "path_traversal": oracle_path_traversal,
    "host_key": oracle_host_key,
}


def run_oracle(category, finding, output, exit_code):
    """Run the oracle for a category. Returns (status, assertions).

    Unknown categories return skipped: no oracle is invented.
    """
    oracle = ORACLES.get(category)
    if oracle is None:
        return "skipped", [
            _assertion(
                "oracle_available",
                False,
                "no oracle for this category",
            )
        ]
    return oracle(finding, output, exit_code)


def evidence_contract(category):
    """Evidence contract text for a category, for PoC generation.

    Tells the model exactly what JSON evidence object the oracle
    reads, so a generated PoC can satisfy it.
    """
    contracts = {
        "sqli": (
            'Print as the last line a JSON object like '
            '{"boolean_length_diff": true, "timing_delta_ms": 1200, '
            '"sql_error": true}. At least two of the three signals '
            'must be true for confirmation.'
        ),
        "xss": (
            'Generate a unique token, try to get it executed or '
            'captured, and print as the last line a JSON object like '
            '{"token": "xss-<unique>", "captured_in": "dom_sink", '
            '"token_seen": true}. captured_in must be "dialog" or '
            '"dom_sink". Reflection of the token in HTML alone is '
            'not confirmation.'
        ),
        "ssrf": (
            'Generate a unique nonce, start a temporary local HTTP '
            'collector on 127.0.0.1, make the vulnerable code fetch '
            'a URL pointing at the collector with the nonce, and '
            'print as the last line a JSON object like {"nonce": '
            '"<nonce>", "collector_received_nonce": "<nonce seen by '
            'the collector>"}. The two nonces must match.'
        ),
        "path_traversal": (
            'Request the target file through the vulnerable path '
            'handling and print as the last line a JSON object like '
            '{"content": "<the returned file content>", '
            '"target_file": "/etc/passwd"}. The content must contain '
            'the Linux /etc/passwd root entry signature.'
        ),
        "host_key": (
            'Connect to the local test SSH server with a wrong host '
            'key, using a client with no host key verification, and '
            'print as the last line a JSON object like {"connected": '
            'true, "host_key_verified": false, "host_key_mismatch": '
            'true}. The connection must actually succeed while the '
            'key is wrong and unverified.'
        ),
    }
    return contracts.get(category, "")


# --- PoC command validation and runner ------------------------------


def validate_repo_path(repo_path):
    """Resolve repo_path. Returns the resolved Path, or None.

    The path must exist and be a directory. Symlinks are resolved,
    so a repo_path that is itself a symlink is followed to its
    real directory; paths inside it are checked against the
    resolved root.
    """
    if not repo_path or not str(repo_path).strip():
        return None
    try:
        root = Path(repo_path).expanduser().resolve()
    except (OSError, RuntimeError):
        return None
    if not root.is_dir():
        return None
    return root


def validate_poc_command(command, repo_path):
    """Validate a list-form PoC command. Returns an error string, or None.

    Refuses: an empty command, a non-list command, shell
    metacharacters in any token, and any token that is a path
    escaping the repo (absolute paths outside it, or .. segments
    and symlinks that resolve outside it). The first token, the
    program to run, may be an absolute path to an executable, for
    example the Python interpreter. Bare words that name no file
    in the repo, such as pytest flags, are not paths.
    """
    if not isinstance(command, (list, tuple)) or not command:
        return "PoC command must be a non-empty list of tokens"
    if not all(isinstance(tok, str) and tok for tok in command):
        return "PoC command tokens must be non-empty strings"
    root = validate_repo_path(repo_path)
    if root is None:
        return "repo_path is not an existing directory"
    for index, token in enumerate(command):
        if _SHELL_META_RE.search(token):
            return (
                "PoC command contains a shell metacharacter, refused: %r"
                % token
            )
        if token.startswith("~"):
            return "PoC command must not use ~ paths: %r" % token
        if token == "{poc}":
            continue
        path = Path(token)
        if path.is_absolute():
            if (
                index == 0
                and path.is_file()
                and os.access(path, os.X_OK)
            ):
                continue
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError):
                return "PoC command path cannot be resolved: %r" % token
            if resolved != root and root not in resolved.parents:
                return (
                    "PoC command path escapes the repo, refused: %r" % token
                )
            continue
        candidate = root / path
        if (
            "/" in token
            or ".." in path.parts
            or candidate.is_symlink()
            or candidate.exists()
        ):
            try:
                resolved = candidate.resolve()
            except (OSError, RuntimeError):
                return "PoC command path cannot be resolved: %r" % token
            if resolved != root and root not in resolved.parents:
                return (
                    "PoC command path escapes the repo, refused: %r" % token
                )
    return None


def _scrubbed_env():
    """Environment for a PoC child process, without credentials.

    Drops every variable whose name looks like a key, token,
    secret, password, or credential, including GMI_API_KEY, so a
    PoC can never read a credential from its environment.
    """
    scrub_re = re.compile(
        r"key|token|secret|password|passwd|credential|bearer|session|cookie",
        re.I,
    )
    return {
        key: value
        for key, value in os.environ.items()
        if not scrub_re.search(key)
    }


def run_poc(command, repo_path, timeout=POC_TIMEOUT_SECONDS,
            executor="host", docker_available=None):
    """Run a PoC command and return a PocRun dict.

    List-form subprocess only, no shell, timeout enforced, working
    directory inside the repo. Returns {"ran": bool, "exit_code":
    int or None, "output": str, "output_hash": str or None,
    "error": str or None, "timed_out": bool}. A timeout or an
    execution error is ran False with an error, never a pass.
    The executor is "host" by default, with a warning in the tool
    result. "docker" runs in a disposable container when Docker is
    available, and refuses clearly when it is not, never silently
    choosing host.
    """
    if executor not in ("host", "docker"):
        return {
            "ran": False,
            "exit_code": None,
            "output": "",
            "output_hash": None,
            "error": "executor must be host or docker, got %r" % executor,
            "timed_out": False,
        }
    if executor == "docker":
        available = (
            shutil.which("docker") is not None
            if docker_available is None
            else docker_available
        )
        if not available:
            return {
                "ran": False,
                "exit_code": None,
                "output": "",
                "output_hash": None,
                "error": (
                    "executor docker was requested but Docker is not "
                    "available on this machine. Refusing to run the PoC "
                    "on the host instead."
                ),
                "timed_out": False,
            }
        root = validate_repo_path(repo_path)
        if root is None:
            return {
                "ran": False,
                "exit_code": None,
                "output": "",
                "output_hash": None,
                "error": "repo_path is not an existing directory",
                "timed_out": False,
            }
        docker_cmd = [
            "docker", "run", "--rm", "--network", "none",
            "-v", "%s:/work:ro" % root, "-w", "/work",
            "python:3.13-slim",
        ] + [str(tok) for tok in command]
        return _run_list(docker_cmd, root, timeout)
    root = validate_repo_path(repo_path)
    if root is None:
        return {
            "ran": False,
            "exit_code": None,
            "output": "",
            "output_hash": None,
            "error": "repo_path is not an existing directory",
            "timed_out": False,
        }
    return _run_list([str(tok) for tok in command], root, timeout)


def _run_list(command, cwd, timeout):
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            shell=False,
            timeout=timeout,
            capture_output=True,
            text=True,
            env=_scrubbed_env(),
        )
    except subprocess.TimeoutExpired:
        return {
            "ran": False,
            "exit_code": None,
            "output": "",
            "output_hash": None,
            "error": "PoC timed out after %d seconds" % timeout,
            "timed_out": True,
        }
    except OSError as err:
        return {
            "ran": False,
            "exit_code": None,
            "output": "",
            "output_hash": None,
            "error": "PoC could not run: %s" % err,
            "timed_out": False,
        }
    output = (proc.stdout or "") + (proc.stderr or "")
    return {
        "ran": True,
        "exit_code": proc.returncode,
        "output": output,
        "output_hash": sha256_hex(output),
        "error": None,
        "timed_out": False,
    }


def write_poc_file(poc_text, repo_path):
    """Write PoC text to a temp file inside the repo. Returns the Path.

    Uses tempfile inside the repo directory so the PoC runs with
    the repo as its working directory and cannot be confused with
    a file elsewhere. The caller removes the file after the run.
    """
    root = validate_repo_path(repo_path)
    if root is None:
        raise ValueError("repo_path is not an existing directory")
    handle, name = tempfile.mkstemp(
        prefix="poc-", suffix=".py", dir=str(root)
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as handle_file:
            handle_file.write(poc_text)
    except OSError:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    return Path(name)


def parse_poc_generation(content):
    """Parse a PoC generation reply into {"poc", "language", "notes"}.

    Uses the same balanced-JSON extraction as triage. Returns None
    when no JSON can be extracted or the poc field is empty: an
    unparsed PoC generation is an error, never a pass.
    """
    if not content:
        return None
    from . import validate as validate_mod

    raw = validate_mod.extract_balanced_json(content)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    poc = data.get("poc")
    if not isinstance(poc, str) or not poc.strip():
        return None
    return {
        "poc": poc,
        "language": str(data.get("language") or "python")[:50],
        "notes": str(data.get("notes") or "")[:500],
    }
