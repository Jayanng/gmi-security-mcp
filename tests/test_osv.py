"""Unit tests for OSV lookup and osv-scanner parsing.

No network. The OSV API is replaced with a stub fetcher serving
canned records copied from the real OSV responses fetched
2026-11-10. The osv-scanner fixture mirrors the real output seen
on the bug-bounty machine for axios/package-lock.json.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from gmi_security_mcp import osv as osv_mod
from gmi_security_mcp import server as srv

PRICING = {
    "google/gemini-3.5-flash-lite": (0.000000300, 0.000002500),
    "Qwen/Qwen3.8-Flash": (0.000000160, 0.000000470),
}
CHEAP = "google/gemini-3.5-flash-lite"

os.environ["GMI_API_KEY"] = "test-key-never-sent"

LOG4J_CVE = {
    "id": "CVE-2021-44228",
    "details": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not "
    "protect against attacker controlled LDAP endpoints.",
    "aliases": ["GHSA-jfh8-c2jp-5v3q"],
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        }
    ],
    "affected": [
        {
            "ranges": [
                {
                    "type": "GIT",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "38513a7d57343881f7bf58f37e67d6a87e0a47c5"},
                    ],
                }
            ]
        }
    ],
    "published": "2021-12-10T10:15:09.143Z",
    "references": [
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
    ],
}

LOG4J_GHSA = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
        }
    ],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.13.0"},
                        {"fixed": "2.15.0"},
                    ],
                }
            ],
        },
        {
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.0-beta9"},
                        {"fixed": "2.3.1"},
                    ],
                }
            ],
        },
        {
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.4"},
                        {"fixed": "2.12.2"},
                    ],
                }
            ],
        },
    ],
    "published": "2021-12-10T10:15:09.143Z",
}

DEEPMERGE_GHSA = {
    "id": "GHSA-gcqx-w48m-w2h4",
    "summary": "deepmerge mergeObject() allows prototype poisoning of returned objects",
    "aliases": ["CVE-2026-93753"],
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        }
    ],
    "database_specific": {"severity": "LOW"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "deepmerge"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "4.2.0"},
                        {"last_affected": "4.3.1"},
                    ],
                }
            ],
        }
    ],
}


def _fetcher_factory(records):
    def _fetch(url, timeout=30):
        advisory_id = url.rsplit("/", 1)[-1]
        if advisory_id in records:
            return 200, records[advisory_id]
        return 404, None

    return _fetch


FETCHER = _fetcher_factory(
    {
        "CVE-2021-44228": LOG4J_CVE,
        "GHSA-jfh8-c2jp-5v3q": LOG4J_GHSA,
        "GHSA-gcqx-w48m-w2h4": DEEPMERGE_GHSA,
    }
)

OSV_SCANNER_FIXTURE = {
    "results": [
        {
            "source": {"path": "package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "deepmerge",
                        "version": "4.3.1",
                        "ecosystem": "npm",
                    },
                    "groups": [
                        {
                            "ids": ["GHSA-gcqx-w48m-w2h4"],
                            "aliases": ["CVE-2026-93753", "GHSA-gcqx-w48m-w2h4"],
                            "max_severity": "5.3",
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-gcqx-w48m-w2h4",
                            "aliases": ["CVE-2026-93753"],
                            "summary": "deepmerge mergeObject() allows prototype poisoning",
                            "affected": [
                                {
                                    "package": {
                                        "ecosystem": "npm",
                                        "name": "deepmerge",
                                    },
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "4.2.0"},
                                                {"last_affected": "4.3.1"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
                {
                    "package": {
                        "name": "minimatch",
                        "version": "10.2.6",
                        "ecosystem": "npm",
                    },
                    "groups": [
                        {
                            "ids": ["GHSA-g3hv-75wg-m249"],
                            "aliases": ["CVE-2026-118764", "GHSA-g3hv-75wg-m249"],
                            "max_severity": "6.9",
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "id": "GHSA-g3hv-75wg-m249",
                            "aliases": ["CVE-2026-118764"],
                            "summary": "minimatch has potential denial of service",
                            "affected": [
                                {
                                    "package": {
                                        "ecosystem": "npm",
                                        "name": "minimatch",
                                    },
                                    "ranges": [
                                        {
                                            "type": "SEMVER",
                                            "events": [
                                                {"introduced": "7.0.0"},
                                                {"fixed": "11.0.1"},
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
                {
                    "package": {
                        "name": "clean-pkg",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                    },
                    "vulnerabilities": [],
                },
            ],
        }
    ]
}


def test_normalise_advisory_id():
    assert osv_mod.normalise_advisory_id("CVE-2021-44228") == "CVE-2021-44228"
    assert osv_mod.normalise_advisory_id("ghsa-jfh8-c2jp-5v3q") == "GHSA-jfh8-c2jp-5v3q"
    assert osv_mod.normalise_advisory_id("cve-2026-93753") == "CVE-2026-93753"
    assert osv_mod.normalise_advisory_id("made-up-123") is None
    assert osv_mod.normalise_advisory_id("CVE-2021-442") is None
    assert osv_mod.normalise_advisory_id("") is None


def test_fetch_advisory_found_and_missing():
    record = osv_mod.fetch_advisory("CVE-2021-44228", fetcher=FETCHER)
    assert record["id"] == "CVE-2021-44228"
    assert osv_mod.fetch_advisory("CVE-2021-99999", fetcher=FETCHER) is None
    with pytest.raises(ValueError, match="not a recognised advisory id"):
        osv_mod.fetch_advisory("not-an-id", fetcher=FETCHER)


class _FakeResponse:
    def __init__(self, payload, status=200, headers=None, read_error=None):
        self.status = status
        self._payload = payload
        self._headers = headers or {}
        self._read_error = read_error

    def getheader(self, name):
        return self._headers.get(name)

    def read(self, amt=-1):
        if self._read_error is not None:
            raise self._read_error
        if amt is not None and amt >= 0:
            return self._payload[:amt]
        return self._payload


class _FakeConnection:
    def __init__(self, response):
        self._response = response
        self.request_args = None
        self.closed = False

    def request(self, method, target, headers=None):
        self.request_args = (method, target, headers or {})

    def getresponse(self):
        return self._response

    def close(self):
        self.closed = True


def _patch_connection(monkeypatch, connection):
    monkeypatch.setattr(
        osv_mod, "_osv_connection", lambda url, timeout: connection
    )


def test_default_fetch_uses_http_client_without_connection_close(monkeypatch):
    # Root-cause regression test, measured live 2026-11-12:
    # urllib.request forces Connection: close and the OSV
    # response truncates near the end. The default fetch must go
    # through http.client and must not send a Connection header.
    import json as _json

    payload = _json.dumps({"id": "CVE-2021-44228"}).encode()
    connection = _FakeConnection(_FakeResponse(payload))
    _patch_connection(monkeypatch, connection)
    status, data = osv_mod._default_fetch(
        "https://api.osv.dev/v1/vulns/CVE-2021-44228"
    )
    assert status == 200
    assert data["id"] == "CVE-2021-44228"
    method, target, headers = connection.request_args
    assert method == "GET"
    assert target == "/v1/vulns/CVE-2021-44228"
    assert "Connection" not in headers
    assert headers["Accept-Encoding"] == "identity"
    assert connection.closed is True


def test_default_fetch_rejects_non_osv_host():
    with pytest.raises(RuntimeError, match="not the OSV API host"):
        osv_mod._default_fetch("https://example.com/v1/vulns/CVE-2021-44228")


def test_fetch_incomplete_read_returns_runtime_error(monkeypatch):
    import http.client

    connection = _FakeConnection(
        _FakeResponse(
            b"", read_error=http.client.IncompleteRead(b"x" * 10, 5)
        )
    )
    _patch_connection(monkeypatch, connection)
    with pytest.raises(RuntimeError, match="OSV API request failed"):
        osv_mod._default_fetch("https://api.osv.dev/v1/vulns/CVE-2021-44228")


def test_fetch_retries_truncated_response_then_succeeds(monkeypatch):
    import http.client

    calls = []

    def _flaky(url, timeout=30):
        calls.append(url)
        if len(calls) < 3:
            raise http.client.IncompleteRead(b"x" * 10, 5)
        return 200, LOG4J_CVE

    record = osv_mod.fetch_advisory("CVE-2021-44228", fetcher=_flaky)
    assert record["id"] == "CVE-2021-44228"
    assert len(calls) == 3


def test_fetch_retries_runtime_error_then_succeeds():
    calls = []

    def _flaky(url, timeout=30):
        calls.append(url)
        if len(calls) < 2:
            raise RuntimeError("OSV API request failed: boom")
        return 200, LOG4J_CVE

    record = osv_mod.fetch_advisory("CVE-2021-44228", fetcher=_flaky)
    assert record["id"] == "CVE-2021-44228"
    assert len(calls) == 2


def test_fetch_still_fails_honestly_after_all_retries():
    calls = []

    def _failing(url, timeout=30):
        calls.append(url)
        raise RuntimeError("OSV API request failed: boom")

    with pytest.raises(RuntimeError, match="after 3 attempts"):
        osv_mod.fetch_advisory("CVE-2021-44228", fetcher=_failing)
    assert len(calls) == 3
    result = srv.explain_cve_impl("CVE-2021-44228", fetcher=_failing)
    assert result["found"] is False
    assert "boom" in result["error"]


def test_default_fetch_accepts_partial_read_only_if_json_parses(monkeypatch):
    import http.client

    payload = b'{"id": "CVE-2021-44228"}'
    connection = _FakeConnection(
        _FakeResponse(
            b"", read_error=http.client.IncompleteRead(payload, 5)
        )
    )
    _patch_connection(monkeypatch, connection)
    status, data = osv_mod._default_fetch(
        "https://api.osv.dev/v1/vulns/CVE-2021-44228"
    )
    assert status == 200
    assert data["id"] == "CVE-2021-44228"


def test_default_fetch_decompresses_gzip_response(monkeypatch):
    import gzip as _gzip
    import json as _json

    payload = _gzip.compress(
        _json.dumps({"id": "CVE-2021-44228"}).encode()
    )
    connection = _FakeConnection(
        _FakeResponse(payload, headers={"Content-Encoding": "gzip"})
    )
    _patch_connection(monkeypatch, connection)
    status, data = osv_mod._default_fetch(
        "https://api.osv.dev/v1/vulns/CVE-2021-44228"
    )
    assert status == 200
    assert data["id"] == "CVE-2021-44228"


def test_default_fetch_rejects_oversize_body(monkeypatch):
    import json as _json

    monkeypatch.setattr(osv_mod, "_OSV_MAX_BODY_BYTES", 8)
    payload = _json.dumps({"id": "CVE-2021-44228"}).encode()
    connection = _FakeConnection(_FakeResponse(payload))
    _patch_connection(monkeypatch, connection)
    with pytest.raises(RuntimeError, match="too large"):
        osv_mod._default_fetch("https://api.osv.dev/v1/vulns/CVE-2021-44228")


def test_default_fetch_rejects_gzip_body_over_cap(monkeypatch):
    import gzip as _gzip
    import json as _json

    raw_json = _json.dumps(
        {"id": "CVE-2021-44228", "padding": "x" * 500}
    ).encode()
    payload = _gzip.compress(raw_json)
    # Cap sits above the compressed size and below the decoded
    # size, so only the decode cap can refuse this response.
    monkeypatch.setattr(osv_mod, "_OSV_MAX_BODY_BYTES", len(payload) + 10)
    assert len(raw_json) > len(payload) + 10
    connection = _FakeConnection(
        _FakeResponse(payload, headers={"Content-Encoding": "gzip"})
    )
    _patch_connection(monkeypatch, connection)
    with pytest.raises(RuntimeError, match="too large"):
        osv_mod._default_fetch("https://api.osv.dev/v1/vulns/CVE-2021-44228")


def test_osv_connection_honours_http_proxy_and_tunnel(monkeypatch):
    import urllib.request

    monkeypatch.setattr(
        urllib.request, "proxy_bypass_environment", lambda host: False
    )
    monkeypatch.setattr(
        urllib.request,
        "getproxies",
        lambda: {"https": "http://proxy.example:3128"},
    )
    connection = osv_mod._osv_connection(
        "https://api.osv.dev/v1/vulns/CVE-2021-44228", 30
    )
    try:
        assert connection.host == "proxy.example"
        assert connection.port == 3128
        assert connection._tunnel_host == "api.osv.dev"
        assert connection._tunnel_port == 443
    finally:
        connection.close()


def test_explain_cve_fetch_failure_returns_found_false():
    def _failing(url, timeout=30):
        raise RuntimeError("OSV API request failed for %s: boom" % url)

    result = srv.explain_cve_impl("CVE-2021-44228", fetcher=_failing)
    assert result["found"] is False
    assert "boom" in result["error"]


def test_summarize_log4shell_cvss_10_and_fixed():
    summary = osv_mod.summarize_advisory(LOG4J_CVE, [LOG4J_GHSA])
    assert summary["cvss_score"] == 10.0
    assert summary["severity_label"] == "CRITICAL"
    assert "2.15.0" in summary["fixed_versions"]
    assert "2.3.1" in summary["fixed_versions"]
    assert "2.12.2" in summary["fixed_versions"]
    assert "GHSA-jfh8-c2jp-5v3q" in summary["aliases"]
    # Commit hashes from GIT ranges are not versions.
    assert not any(
        len(v) == 40 for v in summary["fixed_versions"]
    )


def test_summarize_deepmerge_no_fixed_version():
    summary = osv_mod.summarize_advisory(DEEPMERGE_GHSA)
    assert summary["cvss_score"] == 5.3
    assert summary["fixed_versions"] == []
    affected = summary["affected"][0]
    assert affected["last_affected_versions"] == ["4.3.1"]


def test_parse_osv_scanner_output_axios_pair():
    advisories, scanned, vulnerable = osv_mod.parse_osv_scanner_output(
        OSV_SCANNER_FIXTURE
    )
    assert scanned == 3
    assert vulnerable == 2
    assert len(advisories) == 2
    by_id = {a["id"]: a for a in advisories}
    deepmerge = by_id["CVE-2026-93753"]
    assert deepmerge["package"] == "deepmerge"
    assert deepmerge["installed_version"] == "4.3.1"
    assert deepmerge["osv_id"] == "GHSA-gcqx-w48m-w2h4"
    assert deepmerge["fixed_version"] is None
    assert deepmerge["last_affected_version"] == "4.3.1"
    assert deepmerge["cvss_score"] == 5.3
    minimatch = by_id["CVE-2026-118764"]
    assert minimatch["package"] == "minimatch"
    assert minimatch["installed_version"] == "10.2.6"
    assert minimatch["fixed_version"] == "11.0.1"
    assert minimatch["cvss_score"] == 6.9


def test_explain_cve_made_up_id_returns_found_false():
    result = srv.explain_cve_impl("CVE-2021-99999", fetcher=FETCHER)
    assert result["found"] is False
    assert "advisory" not in result


def test_explain_cve_bad_format_returns_found_false():
    result = srv.explain_cve_impl("not-a-cve", fetcher=FETCHER)
    assert result["found"] is False


def test_explain_cve_log4shell_no_model_uses_advisory_summary():
    result = srv.explain_cve_impl("CVE-2021-44228", fetcher=FETCHER)
    assert result["found"] is True
    advisory = result["advisory"]
    assert advisory["id"] == "CVE-2021-44228"
    assert advisory["cvss_score"] == 10.0
    assert "2.15.0" in advisory["fixed_versions"]
    assert "CVE-2021-44228" in result["citations"]
    assert "2.15.0" in " ".join(result["citations"])
    assert result["explanation_source"] == "advisory"
    assert "Log4j" in (result["explanation"] or "")


def test_explain_cve_with_model_calls_gmi_once():
    calls = []

    def _chat(model, system_content, user_content, max_tokens=2500):
        calls.append(model)
        assert "CVE-2021-44228" in user_content
        return {
            "content": "Log4Shell lets an attacker run code via JNDI lookups. "
            "Upgrade Log4j to 2.15.0 or later. (CVE-2021-44228)",
            "latency_seconds": 0.5,
            "usage": {"prompt_tokens": 300, "completion_tokens": 30},
            "error": None,
            "retried": False,
            "timeout": False,
        }

    result = srv.explain_cve_impl(
        "CVE-2021-44228",
        stage1_model=CHEAP,
        fetcher=FETCHER,
        chat_fn=_chat,
        pricing=PRICING,
    )
    assert result["found"] is True
    assert result["explanation_source"] == "gmi"
    assert "CVE-2021-44228" in result["explanation"]
    assert result["cost_usd"] is not None and result["cost_usd"] > 0
    assert calls == [CHEAP]


def test_check_osv_advisory_with_stub_scanner(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{'
        '"node_modules/deepmerge":{"version":"4.3.1"},'
        '"node_modules/minimatch":{"version":"10.2.6"}}}'
    )

    def _runner(cmd, timeout):
        import json as _json

        assert cmd[0] == "osv-scanner"
        return 1, _json.dumps(OSV_SCANNER_FIXTURE), ""

    result = srv.check_osv_impl(str(lockfile), osv_runner=_runner)
    assert result["error"] is None
    assert result["ecosystem"] == "npm"
    assert result["packages_parsed"] == 2
    assert result["packages_scanned"] == 2
    assert result["vulnerable_packages"] == 2
    ids = [a["id"] for a in result["advisories"]]
    assert "CVE-2026-93753" in ids
    assert "CVE-2026-118764" in ids


def test_check_osv_advisory_missing_scanner_reports_error(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        '{"lockfileVersion":3,"packages":{'
        '"node_modules/deepmerge":{"version":"4.3.1"}}}'
    )

    def _runner(cmd, timeout):
        raise RuntimeError("scanner binary not found: osv-scanner")

    result = srv.check_osv_impl(str(lockfile), osv_runner=_runner)
    assert result["advisories"] == []
    assert "not found" in (result["error"] or "")
    assert result["packages_parsed"] == 1


def test_check_osv_advisory_missing_file():
    result = srv.check_osv_impl("/tmp/does-not-exist-package-lock.json")
    assert result["advisories"] == []
    assert result["error"]
