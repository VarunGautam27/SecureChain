"""CVSS / vulnerability lookup against GitHub Advisory Database and NVD.

Resolution order per dependency:
  1. Local cache file (curated fixtures for the demo, or a previously-populated
     cache) is consulted first if a cache directory is configured.
  2. If not cached and not running in --offline mode, GitHub Advisory Database
     (GraphQL) is queried first (npm-ecosystem-aware, version-range matching).
  3. If GitHub Advisory has no record, NVD is queried as a best-effort fallback
     (keyword search; NVD's CPE dictionary is not reliable for exact npm
     package/version matching, so this is informational only).

Network/parse failures never raise - they degrade to a "lookup_failed" status
so a single flaky dependency lookup cannot crash an entire scan.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import requests
from packaging.version import InvalidVersion, Version

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
REQUEST_TIMEOUT_SECONDS = 10

_GHSA_SEVERITY_TO_CVSS_FLOOR = {
    "LOW": 2.0,
    "MODERATE": 5.0,
    "HIGH": 7.5,
    "CRITICAL": 9.5,
}

_RANGE_CONSTRAINT_RE = re.compile(r"(>=|<=|>|<|=)\s*([0-9][0-9A-Za-z.\-+]*)")


@dataclass
class LookupResult:
    status: str  # "ok" | "no_cve" | "lookup_failed"
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity_label: Optional[str] = None  # qualitative fallback when no numeric CVSS
    fixed_version: Optional[str] = None
    source: Optional[str] = None  # "github_advisory" | "nvd" | "cache"
    summary: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def no_cve(source: str = "none") -> "LookupResult":
        return LookupResult(status="no_cve", source=source)

    @staticmethod
    def failed(reason: str) -> "LookupResult":
        return LookupResult(status="lookup_failed", summary=reason)


def _version_satisfies_range(version_str: str, range_str: str) -> bool:
    """Evaluates an AND-combined set of comparison constraints, e.g. '>= 1.0.0, < 2.0.0'."""
    try:
        version = Version(version_str)
    except InvalidVersion:
        return False

    constraints = _RANGE_CONSTRAINT_RE.findall(range_str)
    if not constraints:
        return False

    for op, bound_str in constraints:
        try:
            bound = Version(bound_str)
        except InvalidVersion:
            return False
        if op == ">=" and not (version >= bound):
            return False
        if op == "<=" and not (version <= bound):
            return False
        if op == ">" and not (version > bound):
            return False
        if op == "<" and not (version < bound):
            return False
        if op == "=" and not (version == bound):
            return False
    return True


class GitHubAdvisoryClient:
    """Queries the GitHub Advisory Database GraphQL API for npm advisories."""

    QUERY = """
    query($package: String!) {
      securityVulnerabilities(ecosystem: NPM, package: $package, first: 25) {
        nodes {
          advisory {
            summary
            severity
            cvss { score }
            identifiers { type value }
          }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
    """

    def __init__(self, token: Optional[str] = None, session: Optional[requests.Session] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.session = session or requests.Session()

    def lookup(self, package: str, version: str) -> LookupResult:
        if not self.token:
            return LookupResult.failed("no GITHUB_TOKEN configured, skipped GitHub Advisory lookup")

        try:
            response = self.session.post(
                GITHUB_GRAPHQL_URL,
                json={"query": self.QUERY, "variables": {"package": package}},
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
            return LookupResult.failed(f"GitHub Advisory API error: {exc}")

        if "errors" in payload:
            return LookupResult.failed(f"GitHub Advisory API returned errors: {payload['errors']}")

        try:
            nodes = payload["data"]["securityVulnerabilities"]["nodes"]
        except (KeyError, TypeError) as exc:
            return LookupResult.failed(f"GitHub Advisory API returned an unexpected shape: {exc}")

        matches = [n for n in nodes if _version_satisfies_range(version, n.get("vulnerableVersionRange", ""))]
        if not matches:
            return LookupResult.no_cve(source="github_advisory")

        best = max(
            matches,
            key=lambda n: (n["advisory"].get("cvss") or {}).get("score") or 0.0,
        )
        advisory = best["advisory"]
        cve_id = next(
            (i["value"] for i in advisory.get("identifiers", []) if i.get("type") == "CVE"),
            next((i["value"] for i in advisory.get("identifiers", [])), None),
        )
        cvss_score = (advisory.get("cvss") or {}).get("score") or None
        fixed = (best.get("firstPatchedVersion") or {}).get("identifier")

        return LookupResult(
            status="ok",
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity_label=advisory.get("severity"),
            fixed_version=fixed,
            source="github_advisory",
            summary=advisory.get("summary"),
        )


class NVDClient:
    """Best-effort keyword lookup against the NVD CVE API v2.0."""

    def __init__(self, api_key: Optional[str] = None, session: Optional[requests.Session] = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.session = session or requests.Session()

    def lookup(self, package: str, version: str) -> LookupResult:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            response = self.session.get(
                NVD_API_URL,
                params={"keywordSearch": package, "resultsPerPage": 20},
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
            return LookupResult.failed(f"NVD API error: {exc}")

        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return LookupResult.no_cve(source="nvd")

        best_score = 0.0
        best_cve_id = None
        for entry in vulnerabilities:
            cve = entry.get("cve", {})
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for metric in metrics.get(key, []):
                    score = metric.get("cvssData", {}).get("baseScore")
                    if score is not None and score > best_score:
                        best_score = score
                        best_cve_id = cve.get("id")

        if best_cve_id is None:
            return LookupResult.no_cve(source="nvd")

        return LookupResult(
            status="ok",
            cve_id=best_cve_id,
            cvss_score=best_score,
            source="nvd",
            summary="Best-effort NVD keyword match; not version-range verified.",
        )


class CachedLookupClient:
    """Cache-first wrapper: consults a curated fixture file before (optionally) live APIs."""

    def __init__(
        self,
        cache_dir: Optional[str | Path] = None,
        offline: bool = False,
        github_client: Optional[GitHubAdvisoryClient] = None,
        nvd_client: Optional[NVDClient] = None,
    ):
        self.offline = offline
        self._cache: dict = {}
        if cache_dir:
            cache_file = Path(cache_dir) / "advisories.json"
            if cache_file.exists():
                self._cache = json.loads(cache_file.read_text(encoding="utf-8"))
        self.github_client = github_client or GitHubAdvisoryClient()
        self.nvd_client = nvd_client or NVDClient()

    def lookup(self, package: str, version: str) -> LookupResult:
        key = f"{package}@{version}"
        if key in self._cache:
            data = dict(self._cache[key])
            data.setdefault("source", "cache")
            return LookupResult(**data)

        if self.offline:
            return LookupResult.failed(f"no cache entry for {key} and --offline set, lookup skipped")

        gh_result = self.github_client.lookup(package, version)
        if gh_result.status == "ok":
            return gh_result
        if gh_result.status == "no_cve":
            nvd_result = self.nvd_client.lookup(package, version)
            return nvd_result
        # GitHub lookup failed outright (no token / network error): try NVD before giving up.
        nvd_result = self.nvd_client.lookup(package, version)
        if nvd_result.status != "lookup_failed":
            return nvd_result
        return gh_result


def base_cvss_score(result: LookupResult) -> Optional[float]:
    """Resolves a numeric CVSS-equivalent score for severity bucketing.

    Falls back to a representative floor value derived from GHSA's qualitative
    severity label when no numeric CVSS score was published.
    """
    if result.status != "ok":
        return None
    if result.cvss_score is not None:
        return result.cvss_score
    if result.severity_label:
        return _GHSA_SEVERITY_TO_CVSS_FLOOR.get(result.severity_label.upper())
    return None
