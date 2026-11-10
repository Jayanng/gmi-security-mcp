"""Lockfile parsing for check_osv_advisory.

Each parser reads one lockfile locally and extracts exact package
name and version pairs. A file that holds only version ranges and
no exact versions returns those packages as unresolved, with a
reason, never as a verdict. That is the sqlalchemy case from the
2026-11-07 scans: a requirements file with no pinned versions
yields no dependency verdict.

Supported files (ecosystem in brackets):
  package-lock.json [npm], package.json [npm],
  requirements.txt, requirements.lock [PyPI],
  Pipfile.lock [PyPI], poetry.lock [PyPI],
  go.mod, go.sum [Go], Cargo.lock [Cargo],
  Gemfile.lock [RubyGems], composer.lock [Packagist]

No network is used here. Version lookup against OSV is done by
osv-scanner (see scanners.py), not by this module.
"""

import json
import re
import tomllib
from pathlib import Path

MAX_LOCKFILE_BYTES = 5 * 1024 * 1024

FILENAME_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "package.json": "npm",
    "requirements.txt": "PyPI",
    "requirements.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "Cargo.lock": "Cargo",
    "Gemfile.lock": "RubyGems",
    "composer.lock": "Packagist",
}

LOCKFILE_NAMES = tuple(FILENAME_ECOSYSTEMS)


def detect_ecosystem(filename):
    """Ecosystem for a lockfile name, or None when unknown."""
    return FILENAME_ECOSYSTEMS.get(Path(filename).name)


def _is_exact_version(version):
    """True when a version string is a single exact version.

    Rejects ranges (>, <, ~, ^, >=, ||, spaces, commas, wildcards)
    and empty strings.
    """
    text = (version or "").strip()
    if not text:
        return False
    if any(ch in text for ch in " <>~^|,"):
        return False
    if text.endswith(".*") or "*" in text:
        return False
    return True


def _parse_package_lock(data):
    packages = []
    unresolved = []
    seen = set()
    entries = data.get("packages")
    if isinstance(entries, dict):
        for key, value in entries.items():
            if not key:
                continue
            if not isinstance(value, dict):
                continue
            name = key.split("node_modules/")[-1]
            if not name or "/" in name and not name.startswith("@"):
                continue
            version = value.get("version")
            if not version:
                continue
            if (name, version) in seen:
                continue
            seen.add((name, version))
            packages.append({"name": name, "version": str(version)})
    else:
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            _flatten_npm_dependencies(dependencies, packages, unresolved, seen)
    return packages, unresolved


def _flatten_npm_dependencies(dependencies, packages, unresolved, seen):
    for name, value in dependencies.items():
        if not isinstance(value, dict):
            continue
        version = value.get("version")
        if version and (name, str(version)) not in seen:
            seen.add((name, str(version)))
            packages.append({"name": name, "version": str(version)})
        nested = value.get("dependencies")
        if isinstance(nested, dict):
            _flatten_npm_dependencies(nested, packages, unresolved, seen)


def _parse_package_json(data):
    packages = []
    unresolved = []
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            spec_text = str(spec or "").strip()
            if _is_exact_version(spec_text):
                packages.append({"name": name, "version": spec_text})
            else:
                unresolved.append(
                    {
                        "name": name,
                        "reason": "version range %r, not an exact version"
                        % spec_text,
                    }
                )
    return packages, unresolved


_REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*"
    r"(===|==|~=|!=|>=|<=|>|<)?\s*([^;\s]+)?"
)


def _parse_requirements(text):
    packages = []
    unresolved = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-", "--")):
            continue
        line = line.split(";")[0].strip()
        match = _REQ_LINE_RE.match(line)
        if not match:
            unresolved.append(
                {"name": line, "reason": "could not parse requirement line"}
            )
            continue
        name = match.group(1)
        operator = match.group(3)
        version = (match.group(4) or "").strip()
        if operator in ("==", "===") and _is_exact_version(version):
            packages.append({"name": name, "version": version})
        else:
            unresolved.append(
                {
                    "name": name,
                    "reason": "no exact pinned version in %r" % line,
                }
            )
    return packages, unresolved


def _parse_pipfile_lock(data):
    packages = []
    unresolved = []
    for section in ("default", "develop"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, value in entries.items():
            if not isinstance(value, dict):
                continue
            spec = str(value.get("version") or "").strip()
            if spec.startswith("==") and _is_exact_version(spec[2:]):
                packages.append({"name": name, "version": spec[2:]})
            else:
                unresolved.append(
                    {
                        "name": name,
                        "reason": "no exact pinned version in %r" % spec,
                    }
                )
    return packages, unresolved


def _parse_poetry_lock(data):
    packages = []
    unresolved = []
    entries = data.get("package")
    if not isinstance(entries, list):
        return packages, unresolved
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if name and version:
            packages.append({"name": str(name), "version": str(version)})
    return packages, unresolved


def _parse_go_mod(text):
    packages = []
    unresolved = []
    in_require = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require ") and not line.endswith("("):
            rest = line[len("require "):].strip()
            parts = rest.split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1]})
            continue
        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1]})
    return packages, unresolved


def _parse_cargo_lock(data):
    packages = []
    unresolved = []
    entries = data.get("package")
    if not isinstance(entries, list):
        return packages, unresolved
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if name and version:
            packages.append({"name": str(name), "version": str(version)})
    return packages, unresolved


def _parse_gemfile_lock(text):
    packages = []
    unresolved = []
    in_gem = False
    in_specs = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line == "GEM":
            in_gem = True
            continue
        if in_gem and line.strip() == "specs:":
            in_specs = True
            continue
        if in_gem and line and not line.startswith(" ") and line.strip() != "specs:":
            in_gem = False
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", line)
        if match:
            packages.append({"name": match.group(1), "version": match.group(2)})
    return packages, unresolved


def _parse_composer_lock(data):
    packages = []
    unresolved = []
    for section in ("packages", "packages-dev"):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if name and version:
                packages.append({"name": str(name), "version": str(version)})
    return packages, unresolved


def parse_lockfile(path, ecosystem=None):
    """Parse a lockfile into exact packages and unresolved entries.

    Returns a dict: ecosystem, packages, unresolved. Raises
    FileNotFoundError when the file is missing, ValueError for an
    unknown lockfile name or an unreadable file, and ValueError when
    the file is over the size cap.
    """
    path = Path(path)
    filename = path.name
    detected = detect_ecosystem(filename)
    if detected is None:
        raise ValueError("unsupported lockfile name: %s" % filename)
    ecosystem = ecosystem or detected
    if not path.is_file():
        raise FileNotFoundError("lockfile not found: %s" % path)
    if path.stat().st_size > MAX_LOCKFILE_BYTES:
        raise ValueError(
            "lockfile is over the %d byte cap" % MAX_LOCKFILE_BYTES
        )
    text = path.read_text(errors="replace")
    if filename == "package-lock.json":
        packages, unresolved = _parse_package_lock(json.loads(text))
    elif filename == "package.json":
        packages, unresolved = _parse_package_json(json.loads(text))
    elif filename in ("requirements.txt", "requirements.lock"):
        packages, unresolved = _parse_requirements(text)
    elif filename == "Pipfile.lock":
        packages, unresolved = _parse_pipfile_lock(json.loads(text))
    elif filename == "poetry.lock":
        packages, unresolved = _parse_poetry_lock(tomllib.loads(text))
    elif filename == "go.mod":
        packages, unresolved = _parse_go_mod(text)
    elif filename == "go.sum":
        packages, unresolved = [], [
            {
                "name": "*",
                "reason": "go.sum holds hashes only, use go.mod for versions",
            }
        ]
    elif filename == "Cargo.lock":
        packages, unresolved = _parse_cargo_lock(tomllib.loads(text))
    elif filename == "Gemfile.lock":
        packages, unresolved = _parse_gemfile_lock(text)
    elif filename == "composer.lock":
        packages, unresolved = _parse_composer_lock(json.loads(text))
    else:  # pragma: no cover - detect_ecosystem already guards this
        raise ValueError("unsupported lockfile name: %s" % filename)
    for package in packages:
        package["ecosystem"] = ecosystem
    return {
        "ecosystem": ecosystem,
        "packages": packages,
        "unresolved": unresolved,
    }
