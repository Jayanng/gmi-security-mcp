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

import http.client
import json
import re
import time
import urllib.error
import urllib.request

from . import cvss as cvss_mod

OSV_API_BASE = "https://api.osv.dev/v1/vulns/"
OSV_WEB_BASE = "https://osv.dev/vulnerability/"

# OSV fetch retries. The OSV API response truncates over this
# environment's egress proxy (measured 2026-11-11: IncompleteRead
# on Log4Shell, 46-60 KB read of about 61.5 KB, and on a 2.5 KB
# record through Hermes), so one attempt is not enough. Three
# attempts with a short backoff, never inventing data.
_OSV_FETCH_ATTEMPTS = 3
_OSV_FETCH_BACKOFF_SECONDS = 0.5

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


def _default_fetch(url, timeout=30):
    # The URL host here is the constant OSV_API_BASE; the only
    # variable part is the advisory id, validated by
    # normalise_advisory_id against a strict CVE/GHSA/OSV regex in
    # fetch_advisory before this is called. No user-controlled host
    # or path can reach this request. (Semgrep flags urlopen with a
    # variable URL here; that is a false positive for this reason,
    # recorded in the Phase 2-3 audit note.)
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            try:
                raw = resp.read()
            except http.client.IncompleteRead as err:
                # A truncated read is accepted only if the bytes
                # actually received parse as JSON. Otherwise it is
                # a failed read, and the caller retries.
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
        # IncompleteRead, RemoteDisconnected, a dropped connection,
        # and a non-JSON body are all request failures, not tool
        # crashes: the caller turns a RuntimeError into a found
        # false result with an error string. IncompleteRead is not
        # a URLError subclass, so without this branch it escaped
        # _default_fetch and crashed explain_cve in the MCP server
        # (measured 2026-11-10: IncompleteRead 54656 bytes read,
        # 6911 more expected, on CVE-2021-44228).
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
