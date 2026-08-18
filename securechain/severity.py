"""Severity labeling engine.

Two independent tracks, since they answer different questions:

  - A dependency with a catalogued CVE gets its severity strictly from the
    CVSS score (standard ranges below). No escalation, no behavioral input -
    the advisory data speaks for itself.
  - A dependency with NO catalogued CVE is never silently assumed Safe. It
    starts "Unverified" - a distinct, non-CVSS pending state - until a static
    source-code scan has actually run (see static_scan.py); only then does it
    become Safe (scanned clean) or Critical (scanned, flagged), never before.
    This replaces the previous behavioral/anomaly-based escalation entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

TIER_NAMES = ["Safe", "Low", "Medium", "High", "Critical"]
SAFE, LOW, MEDIUM, HIGH, CRITICAL = range(5)
UNVERIFIED = "Unverified"


@dataclass
class SeverityResult:
    base_severity: str
    severity: str


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


def label_severity(cvss_score: Optional[float]) -> SeverityResult:
    """For dependencies with a catalogued CVE only."""
    tier_name = TIER_NAMES[base_tier_from_cvss(cvss_score)]
    return SeverityResult(base_severity=tier_name, severity=tier_name)


def label_unscanned_status() -> str:
    """For a dependency with no catalogued CVE that has not yet had a static
    scan run against it - never defaults to Safe just because no CVE exists.
    """
    return UNVERIFIED


def label_static_scan_status(static_scan_status: str, flag_reason: Optional[str]) -> str:
    """For a dependency with no catalogued CVE, once a static scan has
    actually run. Still Unverified if the scan hasn't completed. Otherwise:
    Safe if clean; if flagged, tiered by WHICH structural evidence triggered
    it rather than by the model's raw score (which is bimodal - near 0 or
    near 1, not a gradient - so tiering by score magnitude would be fake
    nuance). A confirmed data-flow chain (an actual traced attack path) is
    the strongest, most concrete evidence, so it's Critical; a suspicious
    pattern sitting inside an install-time hook is real but weaker context,
    so it's High.
    """
    if static_scan_status != "ok":
        return UNVERIFIED
    if flag_reason == "confirmed_chain":
        return TIER_NAMES[CRITICAL]
    if flag_reason == "install_hook":
        return TIER_NAMES[HIGH]
    return TIER_NAMES[SAFE]


def tier_index(severity_name: str) -> int:
    """Unverified is treated at the same gate-sensitivity level as Low: a
    dependency nobody has actually checked yet should not silently pass a
    strict CI gate the way a confirmed-clean Safe dependency does.
    """
    if severity_name == UNVERIFIED:
        return LOW
    return TIER_NAMES.index(severity_name)
