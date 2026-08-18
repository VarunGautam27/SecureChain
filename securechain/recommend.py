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
    exploit_intel: Optional[ExploitIntelResult] = None,
    is_direct: bool = True,
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
            if is_direct:
                return kev_prefix + (
                    f"Upgrade {package} to version {lookup_result.fixed_version} or later "
                    f"to remediate {lookup_result.cve_id}."
                )
            # A transitive dependency's version isn't set directly in your own
            # manifest, it's whatever version the package that actually depends
            # on it resolves to, so "just edit package.json" doesn't apply here.
            return kev_prefix + (
                f"{package} is a transitive dependency, not one you depend on directly. "
                f"Force it to version {lookup_result.fixed_version} or later using npm's "
                f'"overrides" field in package.json (or "resolutions" for Yarn), or upgrade '
                f"whichever direct dependency brings it in, to remediate {lookup_result.cve_id}."
            )
        return kev_prefix + (
            f"No fix available for {lookup_result.cve_id}. "
            "Manual mitigation required, such as replacing the dependency or applying a vendor patch."
        )

    return "No action required."



# Deliberately small and hand-verified, not a general auto-suggestion engine -
# a real alternative-library lookup for an arbitrary package would need
# either a live knowledge source or a much larger curated database. Only
# entries here have actually been checked; everything else gets an honest
# generic fallback instead of an invented name.
_KNOWN_ALTERNATIVES = {
    "canvas": (
        "skia-canvas is a real, actively-maintained alternative offering a similar Canvas-API "
        "surface (uses Skia instead of Cairo) - verify it fits your exact use case before switching, "
        "it is not a guaranteed drop-in replacement."
    ),
}


def _alternative_suggestion(package: str) -> str:
    if package in _KNOWN_ALTERNATIVES:
        return f" A known alternative: {_KNOWN_ALTERNATIVES[package]}"
    return (
        " No specific alternative is suggested here - this tool does not have verified knowledge of "
        "this package's purpose, so search for an actively-maintained library providing equivalent "
        "functionality rather than trust an invented suggestion."
    )


def generate_static_scan_recommendation(package: str, static_scan) -> str:
    """For a dependency with no catalogued CVE at all - never assumed safe
    just because nothing was found. Recommendation depends on whether a
    static scan has actually run yet, and if so, what it found.
    """
    if static_scan.status != "ok":
        return (
            f"No CVE ID exists for {package} at this version - it has not been catalogued as "
            "vulnerable anywhere. This does not confirm it is safe - run a static code scan to check "
            "its real published source before proceeding."
        )
    if static_scan.flag_reason == "confirmed_chain":
        return (
            f"No CVE ID exists for {package} - it has not been catalogued as vulnerable anywhere, and "
            f"no official patch exists as a result. However, static analysis traced an actual data-flow "
            f"chain from a suspicious source into a dangerous sink in its real source code: this is "
            f"concrete evidence of critical, exploitable behavior, not a keyword coincidence. Since "
            f"there is no patch to apply for an uncatalogued issue, remove this dependency and replace "
            f"it with an alternative immediately; do not deploy it as-is." + _alternative_suggestion(package)
        )
    if static_scan.flag_reason == "install_hook":
        return (
            f"No CVE ID exists for {package} - it has not been catalogued as vulnerable anywhere. "
            f"However, static analysis found a suspicious pattern inside an install-time script, which "
            f"runs automatically the moment this package is installed, before it is even used. Manually "
            f"review that install script before allowing this dependency in your tree." + _alternative_suggestion(package)
        )
    return (
        f"Static analysis of {package}'s real published source code found no suspicious indicators. "
        "Safe to proceed."
    )
