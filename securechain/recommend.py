"""Generates a plain-text upgrade or mitigation recommendation for a scanned dependency.

Recommendation only - this module never modifies a manifest or installs anything.
"""

from __future__ import annotations

from typing import Optional

from securechain.exploit_intel import ExploitIntelResult
from securechain.severity import tier_index
from securechain.vuln_lookup import LookupResult


def generate_recommendation(
    package: str,
    severity: str,
    lookup_result: LookupResult,
    anomaly_flagged: bool,
    exploit_intel: Optional[ExploitIntelResult] = None,
) -> str:
    # CISA KEV membership means this CVE is confirmed to be actively exploited
    # in the wild right now - that outranks the CVSS-derived severity tier
    # entirely, so it's checked and prefixed before anything else below,
    # including the Low/Safe "no action required" short-circuit.
    kev_prefix = ""
    if exploit_intel is not None and exploit_intel.status == "ok" and exploit_intel.in_kev:
        kev_prefix = (
            f"URGENT: {lookup_result.cve_id} is on CISA's Known Exploited Vulnerabilities "
            "catalog, confirming active real-world exploitation. Treat this as top priority "
            "regardless of its severity tier. "
        )

    if tier_index(severity) < tier_index("Medium"):
        return kev_prefix + "No action required." if kev_prefix else "No action required."

    has_cve = lookup_result.status == "ok" and lookup_result.cve_id
    if has_cve:
        if lookup_result.fixed_version:
            return kev_prefix + (
                f"Upgrade {package} to version {lookup_result.fixed_version} or later "
                f"to remediate {lookup_result.cve_id}."
            )
        return kev_prefix + (
            f"No fix available for {lookup_result.cve_id}. "
            "Manual mitigation required, such as replacing the dependency or applying a vendor patch."
        )

    if anomaly_flagged:
        return (
            "No known CVE was found for this dependency, but its behavioral profile is unusual. "
            "Manually audit this dependency before deploying."
        )

    return "No action required."
