"""Severity labeling engine: CVSS-based base label plus a capped anomaly escalation.

The base label comes strictly from the CVSS score (standard ranges below).
The anomaly detector may escalate the base label by exactly one tier, never
more, and never above what the tier ladder allows (Critical cannot escalate
further). A package with no CVE at all starts at Safe (tier 0), so the most
an anomaly flag alone can ever produce is Low (tier 1) - this floor is
deliberate and enforced regardless of how "severe" the anomaly looks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

TIER_NAMES = ["Safe", "Low", "Medium", "High", "Critical"]
SAFE, LOW, MEDIUM, HIGH, CRITICAL = range(5)


@dataclass
class SeverityResult:
    base_severity: str
    severity: str
    escalated: bool


def base_tier_from_cvss(cvss_score: Optional[float]) -> int:
    """Maps a CVSS (or CVSS-equivalent) score to a base tier using standard CVSS v3 ranges."""
    if cvss_score is None or cvss_score <= 0.0:
        return SAFE
    if cvss_score >= 9.0:
        return CRITICAL
    if cvss_score >= 7.0:
        return HIGH
    if cvss_score >= 4.0:
        return MEDIUM
    return LOW


def escalate(base_tier: int, anomaly_flagged: bool) -> int:
    """Escalates by exactly one tier when flagged, never more, never past Critical."""
    if not anomaly_flagged:
        return base_tier
    return min(base_tier + 1, CRITICAL)


def label_severity(cvss_score: Optional[float], anomaly_flagged: bool) -> SeverityResult:
    base_tier = base_tier_from_cvss(cvss_score)
    final_tier = escalate(base_tier, anomaly_flagged)
    return SeverityResult(
        base_severity=TIER_NAMES[base_tier],
        severity=TIER_NAMES[final_tier],
        escalated=final_tier != base_tier,
    )


def tier_index(severity_name: str) -> int:
    return TIER_NAMES.index(severity_name)
