"""Orchestrates the full scan pipeline: manifest -> lookup -> severity ->
recommendation -> report assembly.

Two tracks per dependency:
  - A catalogued CVE (lookup_status == "ok") gets severity strictly from
    CVSS, plus exploit intelligence (EPSS/KEV) and a recommendation.
  - No catalogued CVE (lookup_status == "no_cve") is never assumed safe.
    It starts Unverified. A static source-code scan (see static_scan.py)
    only runs automatically when include_static_scan=True is passed - by
    default this is left for the GUI's manual, per-dependency "Scan" button
    (see scan_single_dependency_static below), since forcing a live source
    download for every unresolved dependency on every scan isn't always
    wanted. Only once that scan actually runs does the dependency become
    Safe (clean) or High/Critical (flagged).

Behavioral/anomaly analysis (the 4 registry-metadata features + Isolation
Forest, validated against real historical incidents - event-stream,
ua-parser-js - in this project's retrospective testing) runs automatically
for every dependency in both tracks. It is informational only and never
determines severity by itself anymore - that caused real confusion earlier
(a dependency shown "Safe" while also carrying a scary anomaly badge). Its
role now is triage: helping a reviewer decide which Unverified dependencies
are worth prioritizing for a manual static scan, restoring its validated
value without letting a fuzzy metadata signal silently set severity again.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from securechain.behavioral import CachedBehavioralClient, compute_behavioral_features
from securechain.exploit_intel import CachedExploitIntelClient
from securechain.manifest import find_lockfile, parse_lockfile, parse_manifest
from securechain.ml import anomaly as anomaly_module
from securechain.ml.explain import explain_anomaly
from securechain.ml.features import anomaly_vector
from securechain.recommend import generate_recommendation, generate_static_scan_recommendation
from securechain.report_json import build_dependency_record, build_report, DependencyRecord
from securechain.scorecard import CachedScorecardClient, extract_github_repo
from securechain.severity import label_severity, label_static_scan_status, label_unscanned_status
from securechain.static_scan import StaticScanClient, StaticScanResult
from securechain.static_scan_cache import get_cached_result, save_cached_result
from securechain.vuln_lookup import CachedLookupClient, base_cvss_score


def _resolve_no_cve_dependency(
    dep,
    lookup_result,
    static_scan_client: StaticScanClient,
    raw_metadata: dict,
    offline: bool,
    include_static_scan: bool,
    anomaly_flagged: bool,
    manifest_dir: Path,
) -> tuple[str, StaticScanResult, str]:
    """Returns (severity, static_scan_result, recommendation) for a
    dependency with no catalogued CVE.

    Checks the local static-scan cache (.static_scan_cache.json, next to the
    manifest) first - a dependency already verified in a previous scan of
    this same project does not need to be re-scanned every time, which
    would otherwise mean re-downloading and re-parsing its real source on
    every single scan. Only when nothing is cached does static scan
    actually run (a real source download), and only when include_static_scan
    is True and not offline.
    """
    cached = get_cached_result(manifest_dir, dep.name, dep.version)
    if cached is not None:
        return cached["severity"], StaticScanResult(**cached["static_scan"]), cached["recommendation"]

    if include_static_scan and not offline:
        static_scan_result = static_scan_client.scan(
            dep.name,
            dep.version,
            dep.ecosystem,
            raw_npm_metadata=raw_metadata if dep.ecosystem == "npm" else None,
        )
        severity = label_static_scan_status(static_scan_result.status, static_scan_result.flag_reason)
    else:
        static_scan_result = StaticScanResult.not_run()
        severity = label_unscanned_status()

    recommendation = generate_static_scan_recommendation(dep.name, static_scan_result)
    if severity == "Unverified" and anomaly_flagged:
        recommendation += (
            " Its publishing pattern also looks unusual (behavioral anomaly detected) - "
            "prioritize scanning this one over other Unverified dependencies."
        )

    if include_static_scan and not offline:
        save_cached_result(manifest_dir, dep.name, dep.version, severity, static_scan_result.to_dict(), recommendation)

    return severity, static_scan_result, recommendation


def run_scan(
    manifest_path: str | Path,
    cache_dir: Optional[str | Path] = None,
    offline: bool = False,
    include_transitive: bool = False,
    include_static_scan: bool = False,
) -> dict:
    dependencies = parse_manifest(manifest_path)

    if include_transitive:
        direct_names = {dep.name for dep in dependencies}
        lockfile = find_lockfile(manifest_path)
        if lockfile is not None:
            transitive_only = [
                dep for dep in parse_lockfile(lockfile, direct_names) if not dep.is_direct
            ]
            dependencies = list(dependencies) + transitive_only

    lookup_client = CachedLookupClient(cache_dir=cache_dir, offline=offline)
    exploit_intel_client = CachedExploitIntelClient(cache_dir=cache_dir, offline=offline)
    scorecard_client = CachedScorecardClient(cache_dir=cache_dir, offline=offline)
    static_scan_client = StaticScanClient()
    behavioral_client = CachedBehavioralClient(cache_dir=cache_dir, offline=offline)
    anomaly_model = anomaly_module.load_anomaly_detector()

    records: list[DependencyRecord] = []
    for dep in dependencies:
        lookup_result = lookup_client.lookup(dep.name, dep.version, ecosystem=dep.ecosystem)
        exploit_intel_result = exploit_intel_client.lookup(lookup_result.cve_id)

        behavioral = compute_behavioral_features(dep.name, behavioral_client, ecosystem=dep.ecosystem)
        anom_vector = anomaly_vector(behavioral)
        anomaly_flagged = anomaly_module.predict_anomaly_flag(anomaly_model, anom_vector)
        anomaly_explanation = explain_anomaly(anomaly_model, anom_vector, anomaly_flagged)

        # Cache-first, so this only costs a real network call in live mode;
        # the metadata was already fetched above to compute behavioral
        # features, fetched again here (cheap when cached) purely to read
        # its repository URL for Scorecard.
        raw_metadata = behavioral_client.fetch_metadata(dep.name, ecosystem=dep.ecosystem) or {}
        github_repo = extract_github_repo(raw_metadata)
        scorecard_result = scorecard_client.lookup(github_repo)

        if lookup_result.status == "ok":
            cvss_score = base_cvss_score(lookup_result)
            severity_result = label_severity(cvss_score)
            severity = severity_result.severity
            static_scan_result = StaticScanResult.not_run()
            recommendation = generate_recommendation(
                dep.name, severity, lookup_result, exploit_intel_result, is_direct=dep.is_direct,
            )
        else:
            severity, static_scan_result, recommendation = _resolve_no_cve_dependency(
                dep, lookup_result, static_scan_client, raw_metadata, offline, include_static_scan,
                anomaly_flagged, Path(manifest_path).parent,
            )

        record = build_dependency_record(
            package=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            is_direct=dep.is_direct,
            lookup_result=lookup_result,
            severity=severity,
            recommendation=recommendation,
            exploit_intel=exploit_intel_result,
            behavioral=behavioral,
            anomaly_flagged=anomaly_flagged,
            anomaly_explanation=anomaly_explanation,
            scorecard=scorecard_result,
            static_scan=static_scan_result,
        )
        records.append(record)

    return build_report(str(manifest_path), records)


def scan_single_dependency_static(package: str, version: str, ecosystem: str, folder: str | Path) -> dict:
    """The GUI's manual, per-dependency "Scan static code" button calls this
    directly (via a dedicated API endpoint) rather than re-running the whole
    pipeline - only makes sense for a dependency already known to have no
    catalogued CVE. Always live (never offline), since running it at all
    means the user explicitly asked for a real scan right now.

    Persists the result to the local static-scan cache (next to the
    manifest in `folder`), so a subsequent full scan of the same project
    picks it up automatically via _resolve_no_cve_dependency above, instead
    of reverting to Unverified and needing to be scanned all over again.
    """
    static_scan_client = StaticScanClient()
    raw_npm_metadata = None
    if ecosystem == "npm":
        from securechain.behavioral import NpmRegistryClient

        raw_npm_metadata = NpmRegistryClient().fetch(package)

    static_scan_result = static_scan_client.scan(package, version, ecosystem, raw_npm_metadata=raw_npm_metadata)
    severity = label_static_scan_status(static_scan_result.status, static_scan_result.flag_reason)
    recommendation = generate_static_scan_recommendation(package, static_scan_result)

    save_cached_result(folder, package, version, severity, static_scan_result.to_dict(), recommendation)

    return {
        "severity": severity,
        "static_scan": static_scan_result.to_dict(),
        "recommendation": recommendation,
    }
