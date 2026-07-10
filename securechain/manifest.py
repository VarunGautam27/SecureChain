"""Parses npm package.json manifests into (name, version) dependency pairs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_RANGE_PREFIX_RE = re.compile(r"^[\^~>=<\s]+")


class ManifestError(Exception):
    """Raised when a manifest file cannot be read or parsed."""


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    raw_version: str


def _clean_version(raw_version: str) -> str:
    """Strips semver range prefixes (^, ~, >=, etc.) down to a concrete version string.

    This is a best-effort resolution: real installs use a lockfile to pin exact
    versions, but for scanning purposes we take the lowest explicit version token
    named in the range as the version to look up.
    """
    cleaned = _RANGE_PREFIX_RE.sub("", raw_version.strip())
    # Ranges like "1.2.3 - 2.0.0" or "1.x || 2.x": take the first token.
    cleaned = re.split(r"[\s|]+", cleaned)[0]
    return cleaned or raw_version.strip()


def parse_manifest(manifest_path: str | Path) -> list[Dependency]:
    """Reads a package.json file and extracts its production dependencies.

    Raises ManifestError on a missing file, unreadable file, or invalid JSON.
    Returns an empty list (not an error) when there are zero dependencies.
    """
    path = Path(manifest_path)
    if not path.exists():
        raise ManifestError(f"Manifest file not found: {path}")
    if not path.is_file():
        raise ManifestError(f"Manifest path is not a file: {path}")

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
        result.append(Dependency(name=name, version=_clean_version(raw_version), raw_version=raw_version))

    return result
