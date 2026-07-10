"""Behavioral feature extraction from npm registry metadata.

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


class CachedBehavioralClient:
    """Cache-first wrapper mirroring CachedLookupClient's semantics for npm metadata."""

    def __init__(
        self,
        cache_dir: Optional[str | Path] = None,
        offline: bool = False,
        registry_client: Optional[NpmRegistryClient] = None,
        downloads_client: Optional[NpmDownloadsClient] = None,
    ):
        self.offline = offline
        self._metadata_cache: dict = {}
        self._downloads_cache: dict = {}
        if cache_dir:
            metadata_file = Path(cache_dir) / "npm_metadata.json"
            downloads_file = Path(cache_dir) / "npm_downloads.json"
            if metadata_file.exists():
                self._metadata_cache = json.loads(metadata_file.read_text(encoding="utf-8"))
            if downloads_file.exists():
                self._downloads_cache = json.loads(downloads_file.read_text(encoding="utf-8"))
        self.registry_client = registry_client or NpmRegistryClient()
        self.downloads_client = downloads_client or NpmDownloadsClient()

    def fetch_metadata(self, package: str) -> Optional[dict]:
        if package in self._metadata_cache:
            return self._metadata_cache[package]
        if self.offline:
            return None
        return self.registry_client.fetch(package)

    def fetch_downloads(self, package: str) -> Optional[int]:
        if package in self._downloads_cache:
            return self._downloads_cache[package]
        if self.offline:
            return None
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
) -> BehavioralFeatures:
    metadata = client.fetch_metadata(package)
    downloads = client.fetch_downloads(package)

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
