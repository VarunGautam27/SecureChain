"""Parses dependency manifests into (name, version, ecosystem) triples.

Two ecosystems are supported: npm (package.json) and Python (requirements.txt).
Which parser runs is decided purely by the manifest file's own name, there is
no content sniffing, a file named package.json is always read as npm and a
file named requirements.txt is always read as Python.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

NPM = "npm"
PYPI = "pypi"

_RANGE_PREFIX_RE = re.compile(r"^[\^~>=<\s]+")
_PIP_OPERATOR_RE = re.compile(r"(==|>=|<=|~=|!=|>|<)")
_PIP_OPTION_PREFIXES = ("-e ", "-r ", "-c ", "--", "git+", "http://", "https://")


class ManifestError(Exception):
    """Raised when a manifest file cannot be read or parsed."""


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    raw_version: str
    ecosystem: str = NPM
    is_direct: bool = True


def detect_ecosystem(manifest_path: str | Path) -> str:
    name = Path(manifest_path).name.lower()
    if name == "requirements.txt":
        return PYPI
    return NPM


def _clean_npm_version(raw_version: str) -> str:
    """Strips semver range prefixes (^, ~, >=, etc.) down to a concrete version string.

    This is a best-effort resolution: real installs use a lockfile to pin exact
    versions, but for scanning purposes we take the lowest explicit version token
    named in the range as the version to look up.
    """
    cleaned = _RANGE_PREFIX_RE.sub("", raw_version.strip())
    # Ranges like "1.2.3 - 2.0.0" or "1.x || 2.x": take the first token.
    cleaned = re.split(r"[\s|]+", cleaned)[0]
    return cleaned or raw_version.strip()


def _parse_npm_manifest(path: Path) -> list[Dependency]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"Could not read manifest file {path}: {exc}") from exc

    if not raw_text.strip():
        raise ManifestError(f"Manifest file is empty: {path}")

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ManifestError(
            f"Manifest file {path} is not valid JSON: {exc.msg} (line {exc.lineno}, col {exc.colno})"
        ) from exc

    if not isinstance(data, dict):
        raise ManifestError(f"Manifest file {path} must contain a JSON object at the top level")

    dependencies = data.get("dependencies", {})
    if dependencies is None:
        dependencies = {}
    if not isinstance(dependencies, dict):
        raise ManifestError(f"Manifest file {path} has an invalid 'dependencies' field (expected an object)")

    result: list[Dependency] = []
    for name, raw_version in dependencies.items():
        if not isinstance(raw_version, str):
            raise ManifestError(
                f"Manifest file {path} has an invalid version for dependency '{name}' (expected a string)"
            )
        result.append(Dependency(name=name, version=_clean_npm_version(raw_version), raw_version=raw_version, ecosystem=NPM))

    return result


def _clean_pip_version(raw_version: str) -> str:
    """Takes the first version token from a pip specifier, e.g. '>=2.0,<3.0' -> '2.0'."""
    first_clause = re.split(r",", raw_version.strip())[0]
    cleaned = _PIP_OPERATOR_RE.sub("", first_clause).strip()
    return cleaned or raw_version.strip()


def _parse_pypi_requirements(path: Path) -> list[Dependency]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"Could not read manifest file {path}: {exc}") from exc

    if not raw_text.strip():
        raise ManifestError(f"Manifest file is empty: {path}")

    result: list[Dependency] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(_PIP_OPTION_PREFIXES):
            continue
        # Drop an inline environment marker, e.g. "requests==2.31.0; python_version >= '3.8'".
        stripped = stripped.split(";", 1)[0].strip()
        if not stripped:
            continue

        match = _PIP_OPERATOR_RE.search(stripped)
        if not match:
            # A bare package name with no version pin, e.g. "requests". There is
            # nothing to look up a specific version against, so this is skipped
            # rather than guessed.
            continue

        name = stripped[: match.start()].strip()
        raw_version = stripped[match.start():].strip()
        if not name:
            continue
        result.append(Dependency(name=name, version=_clean_pip_version(raw_version), raw_version=raw_version, ecosystem=PYPI))

    return result


def parse_manifest(manifest_path: str | Path) -> list[Dependency]:
    """Reads a manifest file and extracts its dependencies.

    Dispatches to the npm or Python parser based on the manifest's file name
    (see detect_ecosystem). Raises ManifestError on a missing file, unreadable
    file, or invalid content. Returns an empty list (not an error) when there
    are zero dependencies.
    """
    path = Path(manifest_path)
    if not path.exists():
        raise ManifestError(f"Manifest file not found: {path}")
    if not path.is_file():
        raise ManifestError(f"Manifest path is not a file: {path}")

    ecosystem = detect_ecosystem(path)
    if ecosystem == PYPI:
        return _parse_pypi_requirements(path)
    return _parse_npm_manifest(path)


def find_lockfile(manifest_path: str | Path) -> Optional[Path]:
    """A package-lock.json sitting next to a package.json, if there is one.
    Only npm has a well-defined, universal lockfile format; plain pip
    requirements.txt has no equivalent, so this is npm-only.
    """
    if detect_ecosystem(manifest_path) != NPM:
        return None
    candidate = Path(manifest_path).parent / "package-lock.json"
    return candidate if candidate.is_file() else None


def parse_lockfile(lockfile_path: str | Path, direct_names: set[str]) -> list[Dependency]:
    """Reads an npm package-lock.json (lockfile version 2 or 3, both of which
    use a flat "packages" map) and returns every package it resolves,
    including ones pulled in only transitively, dependencies of your
    dependencies, that never appear in package.json at all.

    Each entry is marked is_direct=True only if its name is also in
    direct_names (the set of names package.json itself declares); everything
    else is a transitive dependency. devDependencies-only and optional
    entries are skipped, since scanning focuses on what actually ships, not
    the full development toolchain.

    Silently returns an empty list for anything that isn't a readable,
    valid lockfile in this shape, rather than raising, since transitive
    scanning is an addition to a scan, not something that should be able to
    break scanning the manifest itself.
    """
    path = Path(lockfile_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    result: list[Dependency] = []
    seen: set[tuple[str, str]] = set()
    for key, info in packages.items():
        if key == "" or not isinstance(info, dict):
            continue  # the root project entry itself, not a dependency
        if info.get("dev") or info.get("optional") or info.get("devOptional"):
            continue

        # A path like "node_modules/foo" or, for a scoped package,
        # "node_modules/@scope/foo", possibly nested again for a version
        # conflict ("node_modules/foo/node_modules/bar"). The name is
        # whatever comes after the last "node_modules/" segment.
        name = key.rsplit("node_modules/", 1)[-1].rstrip("/")
        version = info.get("version")
        if not name or not version:
            continue

        dedupe_key = (name, version)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        result.append(Dependency(
            name=name,
            version=version,
            raw_version=version,
            ecosystem=NPM,
            is_direct=name in direct_names,
        ))

    return result
