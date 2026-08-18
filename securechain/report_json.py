"""Builds and writes the machine-readable JSON report.

Schema (documented in README.md "JSON Report Schema" section):

{
  "scan_date": "2026-07-09T00:00:00+00:00",
  "manifest_path": "demo/package.json",
  "scanned_by": "ayush",
  "summary": {"total": 5, "critical": 1, "high": 0, "medium": 2, "low": 1, "safe": 1, "unverified": 0},
  "dependencies": [
    {
      "package": "xml2js",
      "version": "0.4.19",
      "lookup_status": "ok",
      "cvss": {"score": 9.8, "cve_id": "CVE-...", "source": "cache", "fixed_version": "0.5.0",
                 "summary": "Prototype pollution allows an attacker to modify Object.prototype ..."},
      "exploit_intel": {"status": "ok", "epss_score": 0.049, "epss_percentile": 0.91,
                          "in_kev": false, "kev_date_added": null, "source": "cache"},
      "scorecard": {"status": "ok", "score": 3.6, "checks": [...], "repo": "..."},
      "static_scan": {"status": "not_run", "flagged": false, "indicators": [], "files_scanned": 0,
                        "ml_risk_score": null, "ml_explanation": null},
      "behavioral": {"release_frequency_deviation": .., "maintainer_count": ..,
                      "version_jump_irregularity": .., "download_age_ratio": ..},
      "anomaly_flagged": false,
      "anomaly_explanation": {"attributions": [...], "explanation_text": "..."},
      "severity": "Critical",
      "recommendation": "..."
    }
  ]
}

Severity itself never comes from behavioral/anomaly data - a catalogued CVE's
severity comes strictly from CVSS; an uncatalogued dependency's comes from
Unverified/Safe/High/Critical based on the static scan (see severity.py).
Behavioral/anomaly data is informational context only, computed for every
dependency (both tracks), shown so a reviewer can prioritize which Unverified
dependencies look most worth a manual static scan first - restoring the same
publish-pattern signal validated against real historical incidents
(event-stream, ua-parser-js) in this project's retrospective testing, without
letting it silently determine severity on its own the way it used to.
"""

from __future__ import annotations

import getpass
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from securechain.behavioral import BehavioralFeatures
from securechain.exploit_intel import ExploitIntelResult
from securechain.ml.explain import ExplanationResult
from securechain.scorecard import ScorecardResult
from securechain.static_scan import StaticScanResult
from securechain.vuln_lookup import LookupResult

SEVERITY_ORDER = ["critical", "high", "medium", "low", "safe", "unverified"]


def detect_scanner_identity() -> str:
    """Who ran this scan: the CI platform's actor if running in CI (GitHub Actions'
    GITHUB_ACTOR, GitLab's GITLAB_USER_LOGIN), else the local OS username - so the
    report always records who to ask if a dependency needs a follow-up.
    """
    for env_var in ("GITHUB_ACTOR", "GITLAB_USER_LOGIN", "CI_COMMIT_AUTHOR"):
        value = os.environ.get(env_var)
        if value:
            return value
    try:
        return getpass.getuser()
    except OSError:
        return "unknown"


@dataclass
class DependencyRecord:
    package: str
    version: str
    ecosystem: str
    is_direct: bool
    lookup_status: str
    cvss: dict
    severity: str
    recommendation: str
    exploit_intel: dict
    scorecard: dict
    static_scan: dict
    behavioral: dict
    anomaly_flagged: bool
    anomaly_explanation: dict

    def to_dict(self) -> dict:
        return asdict(self)


def build_dependency_record(
    package: str,
    version: str,
    lookup_result: LookupResult,
    severity: str,
    recommendation: str,
    exploit_intel: ExploitIntelResult,
    behavioral: BehavioralFeatures,
    anomaly_flagged: bool,
    anomaly_explanation: ExplanationResult,
    scorecard: Optional[ScorecardResult] = None,
    static_scan: Optional[StaticScanResult] = None,
    ecosystem: str = "npm",
    is_direct: bool = True,
) -> DependencyRecord:
    return DependencyRecord(
        package=package,
        version=version,
        ecosystem=ecosystem,
        is_direct=is_direct,
        lookup_status=lookup_result.status,
        cvss={
            "score": lookup_result.cvss_score,
            "cve_id": lookup_result.cve_id,
            "source": lookup_result.source,
            "fixed_version": lookup_result.fixed_version,
            "severity_label": lookup_result.severity_label,
            "summary": lookup_result.summary,
            "cwes": lookup_result.cwes,
        },
        exploit_intel=exploit_intel.to_dict(),
        scorecard=(scorecard or ScorecardResult.not_available()).to_dict(),
        static_scan=(static_scan or StaticScanResult.not_run()).to_dict(),
        behavioral=behavioral.to_dict(),
        anomaly_flagged=anomaly_flagged,
        anomaly_explanation=anomaly_explanation.to_dict(),
        severity=severity,
        recommendation=recommendation,
    )


def build_summary(records: list[DependencyRecord]) -> dict:
    counts = {tier: 0 for tier in SEVERITY_ORDER}
    for record in records:
        counts[record.severity.lower()] += 1
    return {"total": len(records), **counts}


def build_report(manifest_path: str, records: list[DependencyRecord]) -> dict:
    return {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "manifest_path": str(manifest_path),
        "scanned_by": detect_scanner_identity(),
        "summary": build_summary(records),
        "dependencies": [r.to_dict() for r in records],
    }


def write_report(report: dict, output_path: str | Path) -> None:
    Path(output_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def load_report(report_path: str | Path) -> dict:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))
