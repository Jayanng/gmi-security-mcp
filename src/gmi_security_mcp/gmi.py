"""GMI Inference client: one POST, temperature 0, no POST retry.

Endpoint: https://api.gmi-serving.com/v1/chat/completions, the same
endpoint the Security Audit Tool uses. The key comes from the
environment variable GMI_API_KEY only. It is never read from a file,
never logged, never printed, and never returned in a tool result.

Retry rule, copied from the audit tool: a POST that reached the API
is billed even if the response is lost, so a POST is never retried
for a lost response. The only retry is one retry on timeout, with a
longer timeout, and the billed cost of a timed-out attempt is
reported as unknown, not as zero.
"""

import json
import os
import re
import socket
import time
import urllib.error
import urllib.request

API_URL = "https://api.gmi-serving.com/v1/chat/completions"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/120.0 Safari/537.36"
)
REASONING_MODEL_RE = re.compile(r"deepseek|thinking|\br1\b|reasoning", re.I)

# Models whose id carries no reasoning marker but which were
# observed returning reasoning tokens in live use. Evidence,
# 2026-11-10, repo_scan on classfang/ssh-mcp-server: Stage 2
# Qwen/Qwen3.8-Flash returned 3,566 reasoning tokens and took 53 s
# on one small finding, costing $0.002231 for that finding alone.
# The regex above does not match its id, so it is listed here by
# exact id. Add a model here only with observed reasoning-token
# evidence, never on a guess: Qwen3.5-27B and other Qwen3 instruct
# models show 0 reasoning tokens in the benchmark runs.
KNOWN_REASONING_BEHAVIOUR = frozenset({"qwen/qwen3.8-flash"})


def is_reasoning_model(model_id):
    """True for reasoning-heavy models, which can spend their whole
    completion budget thinking and return no JSON."""
    text = str(model_id or "")
    return bool(REASONING_MODEL_RE.search(text)) or (
        text.lower() in KNOWN_REASONING_BEHAVIOUR
    )


def is_known_reasoning_model(model_id):
    """True only for models observed returning reasoning tokens
    despite an id with no reasoning marker."""
    return str(model_id or "").lower() in KNOWN_REASONING_BEHAVIOUR


def get_api_key():
    """GMI key from the environment only. None when it is missing."""
    key = os.environ.get("GMI_API_KEY", "").strip()
    return key or None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError("redirect refused")


def _post(url, body, timeout):
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Accept", "application/json")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", BROWSER_USER_AGENT)
    key = get_api_key()
    request.add_header("Authorization", "Bearer " + key)
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _is_timeout(exc):
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        return isinstance(reason, (TimeoutError, socket.timeout)) or (
            "timed out" in str(reason).lower()
        )
    return False


def chat(model, system_content, user_content, max_tokens=2500, timeout=120):
    """One chat completion call.

    Returns a dict: content (str or None), latency_seconds, usage
    (dict, may be empty), error (str or None), retried (bool),
    timeout (bool). A timeout retries once with a 300s timeout.
    Any other failure returns an error, never raises, and never
    retries the POST.
    """
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": max_tokens,
            "temperature": 0,
        }
    ).encode()
    # Engagement profile throttle, Phase A3 (v0.5.0): standard
    # 5 requests per second, conservative 1 per second, full
    # jitter. The wait happens before the POST, never after a
    # billed call. A throttle failure never blocks the call.
    try:
        from . import scope as scope_mod

        scope_mod.throttle_gmi_call()
    except (ImportError, ValueError, TypeError, OSError):
        pass
    started = time.time()
    attempt = 1
    for attempt, attempt_timeout in ((1, timeout), (2, 300)):
        try:
            result = _post(API_URL, body, attempt_timeout)
            break
        except urllib.error.HTTPError as err:
            try:
                detail = err.read().decode(errors="replace")[:300]
            except Exception:
                detail = ""
            return {
                "content": None,
                "latency_seconds": time.time() - started,
                "usage": {},
                "error": "HTTP %s: %s" % (err.code, detail),
                "retried": False,
                "timeout": False,
            }
        except Exception as exc:
            if not _is_timeout(exc):
                return {
                    "content": None,
                    "latency_seconds": time.time() - started,
                    "usage": {},
                    "error": "request failed: %s" % (exc,),
                    "retried": False,
                    "timeout": False,
                }
            if attempt == 1:
                continue
            return {
                "content": None,
                "latency_seconds": time.time() - started,
                "usage": {},
                "error": "timeout after retry (120s + 300s): %s" % (exc,),
                "retried": True,
                "timeout": True,
            }
    latency = time.time() - started
    choices = result.get("choices", [{}])
    message = choices[0].get("message", {}) if choices else {}
    content = message.get("content") or ""
    usage = dict(result.get("usage", {}) or {})
    usage["retried"] = attempt == 2
    return {
        "content": content,
        "latency_seconds": latency,
        "usage": usage,
        "error": None,
        "retried": attempt == 2,
        "timeout": False,
    }
