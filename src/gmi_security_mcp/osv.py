"""OSV advisory lookup and osv-scanner output parsing.

Two sources, kept separate:
- The OSV API (https://api.osv.dev/v1/vulns/<id>) for explain_cve:
  fetch by exact id, refuse when not found, never invent one.
  Alias records (for example the GHSA record behind a CVE) are
  fetched too and merged, because the CVE record itself often
  carries only GIT ranges while the GHSA record carries the
  ecosystem ranges with fixed versions.
- osv-scanner JSON output for check_osv_advisory: parse the
  vulnerabilities osv-scanner already matched, with advisory id,
  package, installed and fixed versions, severity, and summary.

Fixed versions come only from advisory range events. When an
advisory lists only a last_affected version and no fixed event,
fixed_version is None and that is reported, not guessed.
"""

import base64
import gzip
import http.client
import io
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import cvss as cvss_mod

OSV_API_BASE = "https://api.osv.dev/v1/vulns/"
OSV_WEB_BASE = "https://osv.dev/vulnerability/"
_OSV_HOST = "api.osv.dev"

# OSV fetch transport. The v0.5.10 retry change was not the root
# fix. Root cause, measured 2026-11-12 against CVE-2021-44228
# (61,567 bytes): urllib.request forces a "Connection: close"
# request header, it cannot be overridden, and responses to
# close requests truncated near the end in most trials, losing
# the last 0.2-5.5 KB. The same request made with http.client,
# which sends no Connection header, returned the full body in
# 20 of 20 raw trials, and curl and urllib3 were likewise
# reliable. The OSV server ignores Accept-Encoding, it returned
# the plain body with no Content-Encoding, and ignores Range,
# it returned 200 with the full body and no Content-Range, so
# neither gzip nor range resume is available on this endpoint.
# _default_fetch therefore uses http.client directly and reads
# the Content-Length delimited body on a connection the server
# does not close mid-response. The retry loop in fetch_advisory
# stays as a backstop for transient network failures only.
_OSV_FETCH_ATTEMPTS = 3
_OSV_FETCH_BACKOFF_SECONDS = 0.5

# Response body cap. OSV documents a 32 MiB response size limit
# for HTTP/1.1, so a larger body is not a real OSV response. The
# cap bounds memory use on a bad or compromised response, and
# the gzip decode is capped at the same size.
_OSV_MAX_BODY_BYTES = 32 * 1024 * 1024

_ADVISORY_ID_RE = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|OSV-\d{4}-\d+)$",
    re.I,
)

_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


def normalise_advisory_id(advisory_id):
    """Normalise an advisory id, or return None when malformed.

    CVE and OSV ids are upper case. GHSA ids are stored as "GHSA-"
    plus lower-case segments, the canonical GitHub form, as the
    OSV API returns them.
    """
    text = (advisory_id or "").strip()
    if not _ADVISORY_ID_RE.match(text):
        return None
    if text.upper().startswith("GHSA-"):
        return "GHSA-" + text[5:].lower()
    return text.upper()


def _proxy_url_for(host):
    """Proxy URL for host from the process environment, or None.

    Uses the standard library proxy discovery, the same source
    urllib.request used, so an environment that needs a proxy for
    egress keeps working after the move to http.client. The proxy
    credential, when the proxy URL carries one, is used only to
    build the CONNECT Proxy-Authorization header in
    _osv_connection and is never logged or returned.
    """
    try:
        if urllib.request.proxy_bypass_environment(host):
            return None
        proxies = urllib.request.getproxies()
    except Exception:
        return None
    value = proxies.get("https") or proxies.get("all")
    if not value:
        return None
    if "://" not in value:
        value = "http://" + value
    return urllib.parse.urlparse(value)


def _osv_connection(url, timeout):
    """HTTPS connection to the OSV API, through a proxy if set.

    http.client is used directly because urllib.request forces a
    Connection: close request header, which is the truncation
    trigger measured above. No Connection header is sent here, so
    the server keeps the connection open until the full
    Content-Length body has been delivered.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != _OSV_HOST:
        raise RuntimeError(
            "OSV API request refused for %s: not the OSV API host" % (url,)
        )
    port = parsed.port or 443
    context = ssl.create_default_context()
    proxy = _proxy_url_for(parsed.hostname)
    if proxy is None:
        return http.client.HTTPSConnection(
            parsed.hostname, port, timeout=timeout, context=context
        )
    if proxy.scheme == "https":
        # A TLS proxy needs a TLS connection to the proxy before
        # the tunnel, which http.client does not layer. Fall back
        # to a marker the caller turns into the urllib path, so
        # behaviour in that rare setup is unchanged from v0.5.10.
        return None
    if proxy.scheme != "http" or not proxy.hostname:
        raise RuntimeError(
            "OSV API request failed for %s: unsupported proxy" % (url,)
        )
    connection = http.client.HTTPSConnection(
        proxy.hostname, proxy.port or 3128, timeout=timeout, context=context
    )
    tunnel_headers = {}
    if proxy.username:
        user = urllib.parse.unquote(proxy.username)
        password = urllib.parse.unquote(proxy.password or "")
        token = base64.b64encode(
            ("%s:%s" % (user, password)).encode("utf-8")
        ).decode("ascii")
        tunnel_headers["Proxy-Authorization"] = "Basic " + token
    connection.set_tunnel(parsed.hostname, port, headers=tunnel_headers)
    return connection


def _decode_body(raw, content_encoding):
    """Decode a response body, honouring a gzip Content-Encoding.

    The decoded size is capped at _OSV_MAX_BODY_BYTES, so a
    compressed body cannot expand without bound in memory.
    """
    if (content_encoding or "").lower() == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as handle:
            data = handle.read(_OSV_MAX_BODY_BYTES + 1)
        if len(data) > _OSV_MAX_BODY_BYTES:
            raise RuntimeError("OSV API response too large after gzip decode")
        return data
    return raw


def _default_fetch(url, timeout=30):
    # The URL host is validated against the constant OSV host in
    # _osv_connection; the only variable part is the advisory id,
    # validated by normalise_advisory_id against a strict
    # CVE/GHSA/OSV regex in fetch_advisory before this is called.
    # No user-controlled host or path can reach this request.
    connection = _osv_connection(url, timeout)
    if connection is None:
        return _default_fetch_via_urllib(url, timeout=timeout)
    parsed = urllib.parse.urlparse(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "gmi-security-mcp",
            },
        )
        resp = connection.getresponse()
        status = resp.status
        encoding = resp.getheader("Content-Encoding")
        try:
            raw = resp.read(_OSV_MAX_BODY_BYTES + 1)
        except http.client.IncompleteRead as err:
            # A truncated read is accepted only if the bytes
            # actually received decode to a complete JSON
            # document. Otherwise it is a failed read, and the
            # caller retries on a fresh connection.
            partial = err.partial or b""
            try:
                return status, json.loads(
                    _decode_body(partial, encoding).decode()
                )
            except (ValueError, UnicodeDecodeError, OSError):
                raise RuntimeError(
                    "OSV API request failed for %s: %s" % (url, err)
                )
        if status == 404:
            return 404, None
        if status < 200 or status >= 300:
            raise RuntimeError("OSV API HTTP %s for %s" % (status, url))
        if len(raw) > _OSV_MAX_BODY_BYTES:
            raise RuntimeError(
                "OSV API response too large for %s: over %d bytes"
                % (url, _OSV_MAX_BODY_BYTES)
            )
        return status, json.loads(_decode_body(raw, encoding).decode())
    except RuntimeError:
        raise
    except (http.client.HTTPException, OSError, ValueError) as err:
        # IncompleteRead, RemoteDisconnected, a dropped connection,
        # and a non-JSON body are all request failures, not tool
        # crashes: the caller turns a RuntimeError into a found
        # false result with an error string.
        raise RuntimeError("OSV API request failed for %s: %s" % (url, err))
    finally:
        connection.close()


def _default_fetch_via_urllib(url, timeout=30):
    """Previous urllib fetch, kept only for TLS proxy setups.

    urllib.request forces Connection: close, the truncation
    trigger, so this path is used solely when the configured
    proxy itself is reached over TLS, which http.client cannot
    layer. The retry loop in fetch_advisory still applies.
    """
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            try:
                raw = resp.read()
            except http.client.IncompleteRead as err:
                partial = err.partial or b""
                try:
                    return resp.status, json.loads(partial.decode())
                except (ValueError, UnicodeDecodeError):
                    raise RuntimeError(
                        "OSV API request failed for %s: %s" % (url, err)
                    )
            return resp.status, json.loads(raw.decode())
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return 404, None
        raise RuntimeError("OSV API HTTP %s for %s" % (err.code, url))
    except urllib.error.URLError as err:
        raise RuntimeError("OSV API request failed for %s: %s" % (url, err))
    except (http.client.HTTPException, OSError, ValueError) as err:
        raise RuntimeError("OSV API request failed for %s: %s" % (url, err))


def fetch_advisory(advisory_id, fetcher=None):
    """Fetch one advisory record from the OSV API by exact id.

    Returns the record dict, or None when no advisory with that
    exact id exists. Raises ValueError for a malformed id and
    RuntimeError for a failed request.
    """
    normalised = normalise_advisory_id(advisory_id)
    if normalised is None:
        raise ValueError(
            "not a recognised advisory id: %r (expected CVE-YYYY-NNNNN, "
            "GHSA-xxxx-xxxx-xxxx, or OSV-YYYY-NNN)" % (advisory_id,)
        )
    fetch = fetcher or _default_fetch
    last_error = None
    for attempt in range(1, _OSV_FETCH_ATTEMPTS + 1):
        try:
            status, data = fetch(OSV_API_BASE + normalised)
            break
        except (
            RuntimeError,
            http.client.IncompleteRead,
            urllib.error.URLError,
            OSError,
            ValueError,
        ) as err:
            # A truncated or dropped OSV response is transient:
            # retry with a short backoff. A 404 is not an error
            # here, it returns (404, None) from the fetcher and
            # never reaches this branch, so it is never retried.
            last_error = err
            if attempt == _OSV_FETCH_ATTEMPTS:
                raise RuntimeError(
                    "OSV API request failed for %s after %d attempts: %s"
                    % (OSV_API_BASE + normalised, _OSV_FETCH_ATTEMPTS, err)
                )
            time.sleep(_OSV_FETCH_BACKOFF_SECONDS * attempt)
    else:  # pragma: no cover - the loop always breaks or raises
        raise RuntimeError(
            "OSV API request failed for %s: %s"
            % (OSV_API_BASE + normalised, last_error)
        )
    if status == 404 or data is None:
        return None
    if not isinstance(data, dict) or data.get("id") is None:
        return None
    return data


def _severity_entries(record):
    """Severity list with numeric CVSS 3.1 scores where computable."""
    entries = []
    for item in record.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score_type = item.get("type")
        vector = item.get("score")
        score = None
        if score_type in ("CVSS_V3", "CVSS_V2"):
            score = cvss_mod.cvss31_base_score(vector)
        entries.append(
            {"type": score_type, "vector": vector, "score": score}
        )
    return entries


def _fixed_versions_for_package(record, package_name):
    """Fixed versions for one package name across a record's ranges."""
    fixed = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        if package_name and package.get("name") != package_name:
            continue
        for range_entry in affected.get("ranges") or []:
            for event in range_entry.get("events") or []:
                version = event.get("fixed")
                if version and not _HEX40_RE.match(str(version)):
                    if version not in fixed:
                        fixed.append(version)
    return fixed


def _affected_packages(record):
    """Per-package affected info: fixed and last-affected versions."""
    out = []
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        name = package.get("name")
        if not name:
            continue
        fixed = []
        last_affected = []
        for range_entry in affected.get("ranges") or []:
            for event in range_entry.get("events") or []:
                version = event.get("fixed")
                if version and not _HEX40_RE.match(str(version)):
                    if version not in fixed:
                        fixed.append(version)
                version = event.get("last_affected")
                if version and not _HEX40_RE.match(str(version)):
                    if version not in last_affected:
                        last_affected.append(version)
        entry = {
            "ecosystem": package.get("ecosystem"),
            "package": name,
            "fixed_versions": fixed,
            "last_affected_versions": last_affected,
        }
        if entry not in out:
            out.append(entry)
    return out


def summarize_advisory(primary, alias_records=None, package=None):
    """Summarise an OSV record (plus alias records) as plain data.

    Returns id, aliases, summary, details, CVSS score, severity
    label, fixed versions, per-package affected info, references,
    and publication date, all from the advisory records. The
    top-level fixed_versions are for the requested package when
    one is given, otherwise for the first named package in the
    records. When no record states a fixed version, the list is
    empty, never guessed.
    """
    records = [primary] + list(alias_records or [])
    aliases = list(primary.get("aliases") or [])
    for record in records[1:]:
        for alias in record.get("aliases") or []:
            if alias not in aliases and alias != primary.get("id"):
                aliases.append(alias)
    severities = []
    for record in records:
        severities.extend(_severity_entries(record))
    cvss_score = None
    for entry in severities:
        if entry.get("score") is not None:
            cvss_score = entry["score"]
            break
    severity_label = None
    for record in records:
        label = (record.get("database_specific") or {}).get("severity")
        if label:
            severity_label = label
            break
    affected = []
    for record in records:
        for entry in _affected_packages(record):
            if entry not in affected:
                affected.append(entry)
    fixed_versions = []
    if package:
        for record in records:
            fixed_versions.extend(_fixed_versions_for_package(record, package))
    elif affected:
        first_package = affected[0]["package"]
        for record in records:
            fixed_versions.extend(
                _fixed_versions_for_package(record, first_package)
            )
    fixed_versions = list(dict.fromkeys(fixed_versions))
    references = []
    for record in records:
        for ref in record.get("references") or []:
            if isinstance(ref, dict) and ref.get("url"):
                item = {"type": ref.get("type"), "url": ref["url"]}
                if item not in references:
                    references.append(item)
    cwe_ids = []
    for record in records:
        for cwe in (record.get("database_specific") or {}).get("cwe_ids") or []:
            if cwe not in cwe_ids:
                cwe_ids.append(cwe)
    summary = primary.get("summary")
    if not summary:
        for record in records[1:]:
            if record.get("summary"):
                summary = record["summary"]
                break
    return {
        "id": primary.get("id"),
        "aliases": aliases,
        "summary": summary,
        "details": primary.get("details"),
        "cvss_score": cvss_score,
        "severity": severities,
        "severity_label": severity_label,
        "cwe_ids": cwe_ids,
        "fixed_versions": fixed_versions,
        "affected": affected,
        "references": references[:20],
        "published": primary.get("published"),
        "modified": primary.get("modified"),
        "source_url": OSV_WEB_BASE + str(primary.get("id")),
    }


def _cve_alias(vulnerability):
    """First CVE alias of a vulnerability record, or None."""
    for alias in vulnerability.get("aliases") or []:
        if str(alias).upper().startswith("CVE-"):
            return alias
    return None


def _severity_for_vuln(package_entry, vulnerability):
    """Best severity for one osv-scanner vulnerability entry.

    Prefers the package group's max_severity, then a computed
    CVSS 3.1 score from the record, then the database severity
    label. Returns (score, label) with either possibly None.
    """
    vuln_id = vulnerability.get("id")
    aliases = vulnerability.get("aliases") or []
    for group in package_entry.get("groups") or []:
        ids = list(group.get("ids") or []) + list(group.get("aliases") or [])
        if vuln_id in ids or any(a in ids for a in aliases):
            raw = group.get("max_severity")
            try:
                return float(raw), None
            except (TypeError, ValueError):
                pass
    for entry in _severity_entries(vulnerability):
        if entry.get("score") is not None:
            return entry["score"], None
    label = (vulnerability.get("database_specific") or {}).get("severity")
    return None, label


def parse_osv_scanner_output(data):
    """Parse osv-scanner --format json output into advisories.

    Returns (advisories, packages_scanned, vulnerable_packages).
    packages_scanned counts the packages listed in the scanner
    results, which are the vulnerable ones, not the whole lockfile:
    callers that parsed the lockfile should report the parsed count
    as the scanned population instead.
    Each advisory has the record id, the CVE alias when one exists,
    package, installed version, fixed version (None when the
    advisory states none), severity, summary, and link.
    """
    advisories = []
    packages_scanned = 0
    vulnerable_packages = 0
    for result in data.get("results") or []:
        for package_entry in result.get("packages") or []:
            packages_scanned += 1
            package = package_entry.get("package") or {}
            vulnerabilities = package_entry.get("vulnerabilities") or []
            if vulnerabilities:
                vulnerable_packages += 1
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                fixed = None
                last_affected = None
                for affected in vuln.get("affected") or []:
                    affected_package = affected.get("package") or {}
                    if affected_package.get("name") not in (
                        None,
                        package.get("name"),
                    ):
                        continue
                    for range_entry in affected.get("ranges") or []:
                        for event in range_entry.get("events") or []:
                            if event.get("fixed") and not _HEX40_RE.match(
                                str(event["fixed"])
                            ):
                                fixed = fixed or str(event["fixed"])
                            if event.get("last_affected"):
                                last_affected = str(event["last_affected"])
                score, label = _severity_for_vuln(package_entry, vuln)
                cve_id = _cve_alias(vuln)
                advisories.append(
                    {
                        "id": cve_id or vuln.get("id"),
                        "osv_id": vuln.get("id"),
                        "aliases": list(vuln.get("aliases") or []),
                        "package": package.get("name"),
                        "installed_version": package.get("version"),
                        "ecosystem": package.get("ecosystem"),
                        "fixed_version": fixed,
                        "last_affected_version": last_affected,
                        "cvss_score": score,
                        "severity_label": label,
                        "summary": vuln.get("summary"),
                        "link": OSV_WEB_BASE + str(vuln.get("id")),
                    }
                )
    return advisories, packages_scanned, vulnerable_packages
