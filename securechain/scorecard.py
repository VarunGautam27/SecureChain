"""OpenSSF Scorecard lookup: a dependency's own repository health.

CVSS and the behavioral features describe the release you have pinned;
Scorecard describes the health of the project that produces it, does it
require code review before merging, does it pin its own CI dependencies,
does it have a security policy, is it actively maintained. This is
informational context only, shown in the report, never fed into either ML
model, so it never changes a risk_score or an anomaly flag, and adding it
required no retraining.

The dependency's own GitHub repository is read from whichever registry
already provided its behavioral metadata (npm's "repository" field, PyPI's
"project_urls"), not looked up separately, so this costs no extra registry
call. If a dependency has no discoverable GitHub repository, or Scorecard
has never scanned it (its weekly run covers roughly the top 1,000,000
projects, not everything on npm or PyPI), this degrades to "not_available"
rather than an error.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import requests

SCORECARD_API_URL = "https://api.securityscorecards.dev/projects"
REQUEST_TIMEOUT_SECONDS = 10

_GITHUB_URL_RE = re.compile(r"github\.com[:/]([^/\s]+)/([^/\s.]+?)(?:\.git)?/?$")


def extract_github_repo(registry_metadata: dict) -> Optional[str]:
    """Finds an "owner/repo" style GitHub path from a dependency's registry
    metadata. Both npm's raw registry document and this project's normalized
    PyPI metadata (see behavioral.normalize_pypi_metadata) expose the same
    {"repository": {"url": ...}} shape, so this works identically for either
    ecosystem. Returns None if no GitHub URL is present.
    """
    candidates: list[str] = []

    repository = registry_metadata.get("repository")
    if isinstance(repository, dict) and repository.get("url"):
        candidates.append(repository["url"])
    elif isinstance(repository, str):
        candidates.append(repository)

    if registry_metadata.get("homepage"):
        candidates.append(registry_metadata["homepage"])

    for candidate in candidates:
        match = _GITHUB_URL_RE.search(candidate)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
    return None


@dataclass
class ScorecardResult:
    status: str  # "ok" | "not_available" | "lookup_failed"
    score: Optional[float] = None
    checks: Optional[list] = None  # [{"name": ..., "score": ...}, ...] top few checks
    repo: Optional[str] = None
    source: Optional[str] = None  # "scorecard_api" | "cache"
    summary: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def not_available() -> "ScorecardResult":
        return ScorecardResult(status="not_available")

    @staticmethod
    def failed(reason: str) -> "ScorecardResult":
        return ScorecardResult(status="lookup_failed", summary=reason)


class ScorecardClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def lookup(self, repo: str) -> ScorecardResult:
        try:
            response = self.session.get(
                f"{SCORECARD_API_URL}/github.com/{repo}",
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code == 404:
                return ScorecardResult.not_available()
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, json.JSONDecodeError, ValueError) as exc:
            return ScorecardResult.failed(f"OpenSSF Scorecard API error: {exc}")

        score = payload.get("score")
        checks = [
            {"name": c.get("name"), "score": c.get("score")}
            for c in (payload.get("checks") or [])[:5]
        ]
        return ScorecardResult(status="ok", score=score, checks=checks, repo=repo, source="scorecard_api")


class CachedScorecardClient:
    """Cache-first wrapper, mirroring the rest of this project's lookup clients."""

    def __init__(
        self,
        cache_dir: Optional[str | Path] = None,
        offline: bool = False,
        scorecard_client: Optional[ScorecardClient] = None,
    ):
        self.offline = offline
        self._cache: dict = {}
        if cache_dir:
            cache_file = Path(cache_dir) / "scorecard.json"
            if cache_file.exists():
                self._cache = json.loads(cache_file.read_text(encoding="utf-8"))
        self.scorecard_client = scorecard_client or ScorecardClient()

    def lookup(self, repo: Optional[str]) -> ScorecardResult:
        if not repo:
            return ScorecardResult.not_available()

        if repo in self._cache:
            data = dict(self._cache[repo])
            data.setdefault("status", "ok")
            data.setdefault("source", "cache")
            data.setdefault("repo", repo)
            return ScorecardResult(**data)

        if self.offline:
            return ScorecardResult.failed(f"no cache entry for {repo} and --offline set, lookup skipped")

        return self.scorecard_client.lookup(repo)
