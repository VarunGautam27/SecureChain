"""Local, persistent cache of static-scan results.

Without this, a dependency verified once (resolved to Safe or flagged via a
real scan of its source) would revert to Unverified every time the same
project folder is scanned again, forcing a re-scan every single time -
real, unnecessary, repeated network/parsing cost for something already
checked. This cache sits next to the manifest, like .riskignore.json - a
real, persisted file, not a demo/fixtures-style curated offline API-response
cache (a completely different concept; that one holds curated CVE/registry
data for deterministic demos, this one holds this project's own past
static-scan verdicts).

Keyed by exact package@version, same as .riskignore.json - a cached result
for one version is never assumed to apply to a different version.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

DEFAULT_CACHE_FILENAME = ".static_scan_cache.json"


def _cache_path(folder: str | Path) -> Path:
    return Path(folder) / DEFAULT_CACHE_FILENAME


def load_static_scan_cache(folder: str | Path) -> dict:
    path = _cache_path(folder)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def get_cached_result(folder: str | Path, package: str, version: str) -> Optional[dict]:
    return load_static_scan_cache(folder).get(f"{package}@{version}")


def save_cached_result(
    folder: str | Path,
    package: str,
    version: str,
    severity: str,
    static_scan: dict,
    recommendation: str,
) -> None:
    cache = load_static_scan_cache(folder)
    cache[f"{package}@{version}"] = {
        "severity": severity,
        "static_scan": static_scan,
        "recommendation": recommendation,
    }
    _cache_path(folder).write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
