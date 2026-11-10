# Example 10: False positive, SSRF allowlisted host

Expected verdict: false_positive

Expected: FALSE POSITIVE - low. Dataset finding F05. A fixed URL is not user-controlled, so there is no SSRF.

Check: Server-side request forgery (SSRF)

```
Semgrep flagged: possible SSRF, server-side request.
Code in status.py:

resp = requests.get("https://api.gmicloud.ai/v1/models", timeout=5)

The URL is a fixed constant, not user-controlled, and it is GMI Cloud's own API host. There is no attacker-controlled URL reaching an internal service or cloud metadata endpoint. Fix: none needed, this is a false positive. Mark it as such and do not change the code.
```
