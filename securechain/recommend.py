"""Generates a plain-text upgrade or mitigation recommendation for a scanned dependency.

Recommendation only - this module never modifies a manifest or installs anything.
"""

from __future__ import annotations

from securechain.severity import tier_index
from securechain.vuln_lookup import LookupResult


def generate_recommendation(
    package: str,
    severity: str,
    lookup_result: LookupResult,
    anomaly_flagged: bool,
) -> str:
    if tier_index(severity) < tier_index("Medium"):
        return "No action required."

    has_cve = lookup_result.status == "ok" and lookup_result.cve_id
    if has_cve:
        if lookup_result.fixed_version:
            return (
                f"Upgrade {package} to version {lookup_result.fixed_version} or later "
                f"to remediate {lookup_result.cve_id}."
            )
        return (
            f"No fix available for {lookup_result.cve_id}. "
            "Manual mitigation required, such as replacing the dependency or applying a vendor patch."
        )

    if anomaly_flagged:
        return (
            "No known CVE was found for this dependency, but its behavioral profile is unusual. "
            "Manually audit this dependency before deploying."
        )

    return "No action required."
