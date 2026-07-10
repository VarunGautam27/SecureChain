"""Builds and writes the machine-readable JSON report.

Schema (documented in README.md "JSON Report Schema" section):

{
  "scan_date": "2026-07-09T00:00:00+00:00",
  "manifest_path": "demo/package.json",
  "scanned_by": "ayush",
  "summary": {"total": 5, "critical": 1, "high": 0, "medium": 2, "low": 1, "safe": 1},
  "dependencies": [
    {
      "package": "xml2js",
      "version": "0.4.19",
      "lookup_status": "ok",
      "cvss": {"score": 9.8, "cve_id": "CVE-...", "source": "cache", "fixed_version": "0.5.0"},
      "behavioral": {"release_frequency_deviation": .., "maintainer_count": ..,
                      "version_jump_irregularity": .., "download_age_ratio": ..},
      "risk_score": 0.93,
      "anomaly_flagged": true,
      "base_severity": "Critical",
      "severity": "Critical",
      "escalated": false,
      "recommendation": "...",
      "shap": {
        "classifier": {"attributions": [...], "base_value": .., "model_output": ..,
                         "top_feature": "cvss_score", "explanation_text": "..."},
        "anomaly": {"attributions": [...], "base_value": .., "model_output": ..,
                      "top_feature": "maintainer_count", "explanation_text": "..."}
      }
    }
  ]
}
"""

from __future__ import annotations

import getpass
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from securechain.behavioral import BehavioralFeatures
from securechain.ml.explain import ExplanationResult
from securechain.vuln_lookup import LookupResult

SEVERITY_ORDER = ["critical", "high", "medium", "low", "safe"]


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
    lookup_status: str
    cvss: dict
    behavioral: dict
    risk_score: float
    anomaly_flagged: bool
    base_severity: str
    severity: str
    escalated: bool
    recommendation: str
    shap: dict

    def to_dict(self) -> dict:
        return asdict(self)


def build_dependency_record(
    package: str,
    version: str,
    lookup_result: LookupResult,
    behavioral: BehavioralFeatures,
    risk_score: float,
    anomaly_flagged: bool,
    base_severity: str,
    severity: str,
    escalated: bool,
    recommendation: str,
    classifier_explanation: ExplanationResult,
    anomaly_explanation: ExplanationResult,
) -> DependencyRecord:
    return DependencyRecord(
        package=package,
        version=version,
        lookup_status=lookup_result.status,
        cvss={
            "score": lookup_result.cvss_score,
            "cve_id": lookup_result.cve_id,
            "source": lookup_result.source,
            "fixed_version": lookup_result.fixed_version,
            "severity_label": lookup_result.severity_label,
        },
        behavioral=behavioral.to_dict(),
        risk_score=risk_score,
        anomaly_flagged=anomaly_flagged,
        base_severity=base_severity,
        severity=severity,
        escalated=escalated,
        recommendation=recommendation,
        shap={
            "classifier": classifier_explanation.to_dict(),
            "anomaly": anomaly_explanation.to_dict(),
        },
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
