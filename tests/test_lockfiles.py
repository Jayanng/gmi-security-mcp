"""Unit tests for lockfile parsing. No API calls, no scanners."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from gmi_security_mcp import lockfiles

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _by_name(parsed, name):
    for package in parsed["packages"]:
        if package["name"] == name:
            return package
    return None


def test_detect_ecosystem():
    assert lockfiles.detect_ecosystem("package-lock.json") == "npm"
    assert lockfiles.detect_ecosystem("requirements.txt") == "PyPI"
    assert lockfiles.detect_ecosystem("go.mod") == "Go"
    assert lockfiles.detect_ecosystem("Cargo.lock") == "Cargo"
    assert lockfiles.detect_ecosystem("Gemfile.lock") == "RubyGems"
    assert lockfiles.detect_ecosystem("composer.lock") == "Packagist"
    assert lockfiles.detect_ecosystem("unknown.txt") is None


def test_package_lock_v3():
    parsed = lockfiles.parse_lockfile(FIXTURES / "package-lock.json")
    assert parsed["ecosystem"] == "npm"
    assert _by_name(parsed, "deepmerge")["version"] == "4.3.1"
    assert _by_name(parsed, "minimatch")["version"] == "10.2.6"
    assert _by_name(parsed, "@scope/pkg")["version"] == "2.0.0"
    assert _by_name(parsed, "brace-expansion")["version"] == "1.1.11"
    assert _by_name(parsed, "fixture") is None
    assert parsed["unresolved"] == []


def test_package_json_ranges_unresolved():
    parsed = lockfiles.parse_lockfile(FIXTURES / "package.json")
    assert _by_name(parsed, "exact-pkg")["version"] == "1.2.3"
    assert _by_name(parsed, "dev-exact")["version"] == "0.1.0"
    assert _by_name(parsed, "range-pkg") is None
    assert _by_name(parsed, "tilde-pkg") is None
    names = [u["name"] for u in parsed["unresolved"]]
    assert "range-pkg" in names and "tilde-pkg" in names


def test_requirements_txt():
    parsed = lockfiles.parse_lockfile(FIXTURES / "requirements.txt")
    assert _by_name(parsed, "requests")["version"] == "2.32.3"
    assert _by_name(parsed, "django")["version"] == "5.1.1"
    assert _by_name(parsed, "flask") is None
    assert _by_name(parsed, "numpy") is None
    names = [u["name"] for u in parsed["unresolved"]]
    assert "flask" in names and "numpy" in names


def test_pipfile_lock():
    parsed = lockfiles.parse_lockfile(FIXTURES / "Pipfile.lock")
    assert _by_name(parsed, "requests")["version"] == "2.32.3"
    assert _by_name(parsed, "pytest")["version"] == "8.3.2"
    assert _by_name(parsed, "flask") is None


def test_poetry_lock():
    parsed = lockfiles.parse_lockfile(FIXTURES / "poetry.lock")
    assert _by_name(parsed, "requests")["version"] == "2.32.3"
    assert _by_name(parsed, "urllib3")["version"] == "2.2.2"


def test_go_mod():
    parsed = lockfiles.parse_lockfile(FIXTURES / "go.mod")
    assert parsed["ecosystem"] == "Go"
    assert _by_name(parsed, "github.com/spf13/cobra")["version"] == "v1.8.1"
    assert (
        _by_name(parsed, "github.com/inconshreveable/mousetrap")["version"]
        == "v1.1.0"
    )


def test_cargo_lock():
    parsed = lockfiles.parse_lockfile(FIXTURES / "Cargo.lock")
    assert _by_name(parsed, "serde")["version"] == "1.0.210"
    assert _by_name(parsed, "tokio")["version"] == "1.42.0"


def test_gemfile_lock():
    parsed = lockfiles.parse_lockfile(FIXTURES / "Gemfile.lock")
    assert _by_name(parsed, "rack")["version"] == "3.1.0"
    assert _by_name(parsed, "rails")["version"] == "7.1.3"


def test_composer_lock():
    parsed = lockfiles.parse_lockfile(FIXTURES / "composer.lock")
    assert _by_name(parsed, "guzzlehttp/guzzle")["version"] == "7.8.1"
    assert _by_name(parsed, "phpunit/phpunit")["version"] == "10.5.20"


def test_go_sum_has_no_versions():
    path = FIXTURES / "go.sum"
    path.write_text("example.com/mod v1.0.0 h1:abc=\n")
    try:
        parsed = lockfiles.parse_lockfile(path)
        assert parsed["packages"] == []
        assert parsed["unresolved"]
    finally:
        path.unlink()


def test_unknown_lockfile_name_refused():
    with pytest.raises(ValueError, match="unsupported lockfile"):
        lockfiles.parse_lockfile(FIXTURES / "requirements.txt.bak")


def test_missing_lockfile_refused(tmp_path):
    with pytest.raises(FileNotFoundError):
        lockfiles.parse_lockfile(tmp_path / "package-lock.json")
