# Example 5: Apache path traversal, CVE-2021-41773

Expected verdict: real

Expected: REAL - high, critical with CGI. CVE-2021-41773, Apache HTTP Server 2.4.49, CISA KEV, fix 2.4.51 (2.4.50 fix was incomplete, CVE-2021-42013).

Check: Path traversal

```
CVE-2021-41773, Apache HTTP Server 2.4.49, CISA Known Exploited Vulnerabilities, published 4 Oct 2021.
A change to ap_normalize_path() in 2.4.49 let URL-encoded dot segments slip past the traversal check. A request such as GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd maps to files outside the configured Alias directory. If CGI is enabled, POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh runs commands as remote code execution.
Fix: upgrade Apache HTTP Server to 2.4.51 or later. The 2.4.50 fix was incomplete, see CVE-2021-42013.
```
