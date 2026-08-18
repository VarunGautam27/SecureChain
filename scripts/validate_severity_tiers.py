"""Validates that the static-scan severity tiers (Critical / High / Safe)
are each reachable and produce correct, sensible reasoning - not just that
the code runs, but that it reaches the right conclusion for each case.

Three cases, each chosen for a specific reason:

1. CRITICAL - a reconstructed sample modeled on the real, publicly
   documented 2019 fake "python3-dateutil" incident technique (base64
   payload decoded and exec'd). Reconstructed, not the original file,
   because PyPI deletes confirmed malware outright (verified separately -
   the real incident packages all now 404).

2. HIGH - a REAL, currently-published, legitimate npm package: `canvas`
   (server-side Canvas API rendering, widely used). It genuinely defines an
   install-time script AND uses child_process to compile native bindings -
   real evidence, not a synthetic example - which is exactly the "install
   hook + suspicious pattern, no confirmed chain" case this tier exists for.

3. SAFE - a REAL, currently-published, legitimate package (`node-gyp`) that
   has indicators present (uses child_process) but no install hook and no
   confirmed chain, so it correctly stays Safe rather than being flagged on
   a single category alone.
"""

from __future__ import annotations

from securechain.behavioral import NpmRegistryClient
from securechain.recommend import generate_static_scan_recommendation
from securechain.severity import label_static_scan_status
from securechain.static_scan import StaticScanClient, find_taint_chains

CRITICAL_SAMPLE = '''
import base64
import os

_payload = base64.b64decode(
    "aW1wb3J0IG9zCnByaW50KCdyZWNvbnN0cnVjdGVkIGRlbW8gcGF5bG9hZCcp"
)
exec(_payload)
'''


def show_result(label: str, package: str, severity: str, recommendation: str, ml_risk_score) -> None:
    print(f"\n=== {label} ===")
    print(f"package: {package}")
    print(f"severity: {severity}")
    if ml_risk_score is not None:
        print(f"ml_risk_score: {ml_risk_score:.3f}")
    print(f"recommendation: {recommendation}")


def main() -> None:
    # --- CRITICAL: reconstructed incident sample ---
    chain_findings = find_taint_chains(CRITICAL_SAMPLE)
    flag_reason = "confirmed_chain" if chain_findings else None
    severity = label_static_scan_status("ok", flag_reason)

    from securechain.static_scan import StaticScanResult
    fake_result = StaticScanResult(status="ok", flagged=bool(flag_reason), flag_reason=flag_reason, indicators=chain_findings, files_scanned=1)
    recommendation = generate_static_scan_recommendation("malicious-demo-pkg", fake_result)
    show_result("CRITICAL (confirmed data-flow chain)", "malicious-demo-pkg (reconstructed sample)", severity, recommendation, None)
    assert severity == "Critical", f"expected Critical, got {severity}"

    # --- HIGH: real, live package ---
    client = StaticScanClient()
    registry = NpmRegistryClient()
    metadata = registry.fetch("canvas")
    latest = metadata["dist-tags"]["latest"]
    result = client.scan("canvas", latest, "npm", raw_npm_metadata=metadata)
    severity = label_static_scan_status(result.status, result.flag_reason)
    recommendation = generate_static_scan_recommendation("canvas", result)
    show_result("HIGH (install-time script + suspicious pattern)", f"canvas@{latest}", severity, recommendation, result.ml_risk_score)
    assert severity == "High", f"expected High, got {severity}"

    # --- SAFE: real, live package ---
    metadata = registry.fetch("node-gyp")
    latest = metadata["dist-tags"]["latest"]
    result = client.scan("node-gyp", latest, "npm", raw_npm_metadata=metadata)
    severity = label_static_scan_status(result.status, result.flag_reason)
    recommendation = generate_static_scan_recommendation("node-gyp", result)
    show_result("SAFE (indicator present, but below the flag threshold)", f"node-gyp@{latest}", severity, recommendation, result.ml_risk_score)
    assert severity == "Safe", f"expected Safe, got {severity}"

    print("\nAll three tiers reached correctly.")


if __name__ == "__main__":
    main()
