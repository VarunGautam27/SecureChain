"""Behavioral feature extraction from npm or PyPI registry metadata.

Four features are computed per dependency, used both as classifier inputs
(alongside CVSS) and as the sole inputs to the Isolation Forest anomaly
detector:

  release_frequency_deviation - coefficient of variation (stdev / mean) of the
      gaps between consecutive published versions. A relative measure, so a
      package with wildly uneven release cadence (long silence then a burst)
      scores higher regardless of whether its typical gap is days or years.
  maintainer_count - size of the current maintainers list; a proxy for
      ownership concentration (bus-factor / single-maintainer risk).
  version_jump_irregularity - coefficient of variation of the weighted semver
      delta between consecutive chronological releases; flags disproportionate
      version jumps relative to a package's own usual jump size.
  download_age_ratio - weekly downloads divided by package age in days; a
      very low ratio for an old package can indicate abandonment, a very
      high ratio for a young package can indicate a sudden viral pickup.

npm and PyPI are both supported. Whichever registry a dependency came from,
its raw metadata is normalized into the same {"time": {...}, "maintainers":
[...]} shape before any feature is computed, so the four functions below
never need to know which ecosystem they're looking at. The one honest
difference: npm publishes a real, structured maintainers list, while PyPI's
JSON API only exposes free-text author/maintainer email fields, so
maintainer_count for a PyPI package is an approximation from that text, not
an exact count the way it is for npm.
"""

from __future__ import annotations

import json
import os
import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from packaging.version import InvalidVersion, Version

NPM_REGISTRY_URL = "https://registry.npmjs.org"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week"
PYPI_REGISTRY_URL = "https://pypi.org/pypi"
PYPI_DOWNLOADS_URL = "https://pypistats.org/api/packages"
REQUEST_TIMEOUT_SECONDS = 10

_NON_VERSION_TIME_KEYS = {"created", "modified"}


@dataclass
class BehavioralFeatures:
    release_frequency_deviation: float
    maintainer_count: int
    version_jump_irregularity: float
    download_age_ratio: float
    status: str = "ok"  # "ok" | "lookup_failed"

    def to_dict(self) -> dict:
        return asdict(self)

    def as_vector(self) -> list[float]:
        return [
            self.release_frequency_deviation,
            float(self.maintainer_count),
            self.version_jump_irregularity,
            self.download_age_ratio,
        ]

    @staticmethod
    def failed() -> "BehavioralFeatures":
        return BehavioralFeatures(0.0, 0, 0.0, 0.0, status="lookup_failed")


class NpmRegistryClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def fetch(self, package: str) -> Optional[dict]:
        try:
            response = self.session.get(
                f"{NPM_REGISTRY_URL}/{package.replace('/', '%2F')}",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            return None


class NpmDownloadsClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def fetch(self, package: str) -> Optional[int]:
        try:
            response = self.session.get(
                f"{NPM_DOWNLOADS_URL}/{package.replace('/', '%2F')}",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            return int(data.get("downloads", 0))
        except (requests.RequestException, json.JSONDecodeError, ValueError, TypeError):
            return None


def _parse_pypi_emails(*fields: Optional[str]) -> list[str]:
    """PyPI has no structured maintainers list like npm does, only free-text
    author/maintainer email fields (often "Name <email>, Name2 <email2>" or
    empty). This is an approximation of maintainer count from that text, not
    an exact figure. author_email and maintainer_email commonly name the same
    person for a small package, so entries are de-duplicated, otherwise a
    single-maintainer package would be miscounted as two.
    """
    seen: dict[str, str] = {}
    for field_value in fields:
        if not field_value:
            continue
        for entry in field_value.split(","):
            entry = entry.strip()
            if entry:
                seen.setdefault(entry.lower(), entry)
    return list(seen.values())


class PypiRegistryClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def fetch(self, package: str) -> Optional[dict]:
        try:
            response = self.session.get(
                f"{PYPI_REGISTRY_URL}/{package}/json",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            raw = response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError):
            return None
        return normalize_pypi_metadata(raw)


class PypiDownloadsClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def fetch(self, package: str) -> Optional[int]:
        try:
            response = self.session.get(
                f"{PYPI_DOWNLOADS_URL}/{package}/recent",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            data = response.json()
            return int(data.get("data", {}).get("last_week", 0))
        except (requests.RequestException, json.JSONDecodeError, ValueError, TypeError):
            return None


def normalize_pypi_metadata(raw: dict) -> dict:
    """Converts PyPI's JSON API response into the same {"time": {...},
    "maintainers": [...]} shape npm's registry already produces, so the
    feature functions below can stay ecosystem-agnostic.
    """
    info = raw.get("info", {}) or {}
    releases = raw.get("releases", {}) or {}

    time_map: dict = {}
    earliest = None
    latest = None
    for version, files in releases.items():
        if not files:
            continue
        upload_time = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
        if not upload_time:
            continue
        time_map[version] = upload_time
        if earliest is None or upload_time < earliest:
            earliest = upload_time
        if latest is None or upload_time > latest:
            latest = upload_time

    if earliest is not None:
        time_map["created"] = earliest
    if latest is not None:
        time_map["modified"] = latest

    maintainer_names = _parse_pypi_emails(info.get("maintainer_email"), info.get("author_email"))
    if not maintainer_names:
        maintainer_names = ["unknown"]  # PyPI reported nothing parseable; treated as a single, unnamed owner

    project_urls = info.get("project_urls") or {}
    source_url = None
    for key in ("Source", "Repository", "Source Code", "Homepage", "Home"):
        if project_urls.get(key):
            source_url = project_urls[key]
            break
    if not source_url:
        source_url = info.get("home_page")

    return {
        "time": time_map,
        "maintainers": [{"name": name} for name in maintainer_names],
        # Matches npm's registry shape for this field, so extract_github_repo()
        # in scorecard.py can read either ecosystem's normalized metadata the
        # same way, without needing to know which one it came from.
        "repository": {"url": source_url} if source_url else None,
    }


class CachedBehavioralClient:
    """Cache-first wrapper mirroring CachedLookupClient's semantics for
    registry metadata, dispatching to npm or PyPI clients and cache files
    based on the ecosystem of the dependency being looked up.
    """

    _CACHE_FILES = {
        "npm": ("npm_metadata.json", "npm_downloads.json"),
        "pypi": ("pypi_metadata.json", "pypi_downloads.json"),
    }

    def __init__(
        self,
        cache_dir: Optional[str | Path] = None,
        offline: bool = False,
        registry_client: Optional[NpmRegistryClient] = None,
        downloads_client: Optional[NpmDownloadsClient] = None,
        pypi_registry_client: Optional[PypiRegistryClient] = None,
        pypi_downloads_client: Optional[PypiDownloadsClient] = None,
    ):
        self.offline = offline
        self._metadata_cache: dict[str, dict] = {}
        self._downloads_cache: dict[str, dict] = {}
        if cache_dir:
            for ecosystem, (metadata_name, downloads_name) in self._CACHE_FILES.items():
                metadata_file = Path(cache_dir) / metadata_name
                downloads_file = Path(cache_dir) / downloads_name
                if metadata_file.exists():
                    self._metadata_cache[ecosystem] = json.loads(metadata_file.read_text(encoding="utf-8"))
                if downloads_file.exists():
                    self._downloads_cache[ecosystem] = json.loads(downloads_file.read_text(encoding="utf-8"))
        self.registry_client = registry_client or NpmRegistryClient()
        self.downloads_client = downloads_client or NpmDownloadsClient()
        self.pypi_registry_client = pypi_registry_client or PypiRegistryClient()
        self.pypi_downloads_client = pypi_downloads_client or PypiDownloadsClient()

    def fetch_metadata(self, package: str, ecosystem: str = "npm") -> Optional[dict]:
        cache = self._metadata_cache.get(ecosystem, {})
        if package in cache:
            return cache[package]
        if self.offline:
            return None
        if ecosystem == "pypi":
            return self.pypi_registry_client.fetch(package)
        return self.registry_client.fetch(package)

    def fetch_downloads(self, package: str, ecosystem: str = "npm") -> Optional[int]:
        cache = self._downloads_cache.get(ecosystem, {})
        if package in cache:
            return cache[package]
        if self.offline:
            return None
        if ecosystem == "pypi":
            return self.pypi_downloads_client.fetch(package)
        return self.downloads_client.fetch(package)


def _parse_release_times(time_map: dict) -> list[datetime]:
    times = []
    for key, value in time_map.items():
        if key in _NON_VERSION_TIME_KEYS:
            continue
        try:
            times.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except (ValueError, AttributeError):
            continue
    return sorted(times)


def _release_frequency_deviation(times: list[datetime]) -> float:
    """Coefficient of variation (stdev / mean) of inter-release gaps.

    Using a relative (self-normalizing) measure rather than raw stdev keeps the
    feature's scale comparable across packages regardless of whether a package
    releases every few days or every few years - what matters is how uneven
    the cadence is relative to that package's own typical gap, not the
    absolute gap length.
    """
    if len(times) < 3:
        return 0.0
    gaps_days = [(b - a).total_seconds() / 86400 for a, b in zip(times, times[1:])]
    mean_gap = statistics.mean(gaps_days)
    if mean_gap <= 0:
        return 0.0
    return statistics.pstdev(gaps_days) / mean_gap


def _version_weight(version: Version) -> float:
    release = version.release + (0, 0, 0)
    major, minor, patch = release[0], release[1], release[2]
    return major * 10_000 + minor * 100 + patch


def _version_jump_irregularity(time_map: dict) -> float:
    """Coefficient of variation of weighted semver deltas between consecutive
    chronological releases.

    A relative measure, as with release_frequency_deviation above: a package
    that consistently jumps whole major versions is not itself "irregular" (its
    deltas are all similar in size), whereas a package that mostly makes small
    patch/minor jumps but has one disproportionate outlier jump is irregular
    relative to its own history.
    """
    entries = []
    for key, value in time_map.items():
        if key in _NON_VERSION_TIME_KEYS:
            continue
        try:
            version = Version(key)
            published = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (InvalidVersion, ValueError, AttributeError):
            continue
        entries.append((published, version))
    entries.sort(key=lambda e: e[0])

    if len(entries) < 3:
        return 0.0

    deltas = [
        abs(_version_weight(b) - _version_weight(a))
        for (_, a), (_, b) in zip(entries, entries[1:])
    ]
    mean_delta = statistics.mean(deltas)
    if mean_delta <= 0:
        return 0.0
    return statistics.pstdev(deltas) / mean_delta


def _download_age_ratio(weekly_downloads: int, created: Optional[datetime]) -> float:
    if created is None:
        return 0.0
    age_days = max((datetime.now(timezone.utc) - created).total_seconds() / 86400, 1.0)
    return weekly_downloads / age_days


def compute_behavioral_features(
    package: str,
    client: CachedBehavioralClient,
    ecosystem: str = "npm",
) -> BehavioralFeatures:
    metadata = client.fetch_metadata(package, ecosystem=ecosystem)
    downloads = client.fetch_downloads(package, ecosystem=ecosystem)

    if metadata is None or downloads is None:
        return BehavioralFeatures.failed()

    time_map = metadata.get("time", {})
    maintainers = metadata.get("maintainers", [])

    release_times = _parse_release_times(time_map)
    created_raw = time_map.get("created")
    created = None
    if created_raw:
        try:
            created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
        except ValueError:
            created = release_times[0] if release_times else None

    return BehavioralFeatures(
        release_frequency_deviation=_release_frequency_deviation(release_times),
        maintainer_count=len(maintainers) if isinstance(maintainers, list) else 0,
        version_jump_irregularity=_version_jump_irregularity(time_map),
        download_age_ratio=_download_age_ratio(downloads, created),
        status="ok",
    )
