"""Orchestrates the full scan pipeline: manifest -> lookup -> behavioral ->
ML scoring -> severity -> recommendation -> report assembly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from securechain.behavioral import CachedBehavioralClient, compute_behavioral_features
from securechain.exploit_intel import CachedExploitIntelClient
from securechain.manifest import find_lockfile, parse_lockfile, parse_manifest
from securechain.ml import classifier as classifier_module
from securechain.ml import anomaly as anomaly_module
from securechain.ml.explain import explain_anomaly, explain_classifier
from securechain.ml.features import anomaly_vector, classifier_vector
from securechain.recommend import generate_recommendation
from securechain.report_json import build_dependency_record, build_report, DependencyRecord
from securechain.scorecard import CachedScorecardClient, extract_github_repo
from securechain.severity import label_severity
from securechain.vuln_lookup import CachedLookupClient, base_cvss_score


def run_scan(
    manifest_path: str | Path,
    cache_dir: Optional[str | Path] = None,
    offline: bool = False,
    classifier_model=None,
    anomaly_model=None,
    include_transitive: bool = False,
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
    behavioral_client = CachedBehavioralClient(cache_dir=cache_dir, offline=offline)
    exploit_intel_client = CachedExploitIntelClient(cache_dir=cache_dir, offline=offline)
    scorecard_client = CachedScorecardClient(cache_dir=cache_dir, offline=offline)

    if classifier_model is None:
        classifier_model = classifier_module.load_classifier()
    if anomaly_model is None:
        anomaly_model = anomaly_module.load_anomaly_detector()

    records: list[DependencyRecord] = []
    for dep in dependencies:
        lookup_result = lookup_client.lookup(dep.name, dep.version, ecosystem=dep.ecosystem)
        exploit_intel_result = exploit_intel_client.lookup(lookup_result.cve_id)
        behavioral = compute_behavioral_features(dep.name, behavioral_client, ecosystem=dep.ecosystem)

        # Cache-first, so this only costs a real network call in live (non-cached)
        # mode; the metadata was already fetched once above to compute behavioral
        # features and is fetched again here (cheap when cached) purely to read
        # its repository URL, since compute_behavioral_features only returns the
        # four numeric features, not the raw registry document.
        raw_metadata = behavioral_client.fetch_metadata(dep.name, ecosystem=dep.ecosystem) or {}
        github_repo = extract_github_repo(raw_metadata)
        scorecard_result = scorecard_client.lookup(github_repo)

        cvss_score = base_cvss_score(lookup_result)

        clf_vector = classifier_vector(cvss_score, behavioral)
        risk_score = classifier_module.predict_risk_score(classifier_model, clf_vector)
        classifier_explanation = explain_classifier(classifier_model, clf_vector)

        anom_vector = anomaly_vector(behavioral)
        anomaly_flagged = anomaly_module.predict_anomaly_flag(anomaly_model, anom_vector)
        anomaly_explanation = explain_anomaly(anomaly_model, anom_vector, anomaly_flagged)

        severity_result = label_severity(cvss_score, anomaly_flagged)
        recommendation = generate_recommendation(
            dep.name, severity_result.severity, lookup_result, anomaly_flagged, exploit_intel_result,
            is_direct=dep.is_direct,
        )

        record = build_dependency_record(
            package=dep.name,
            version=dep.version,
            ecosystem=dep.ecosystem,
            is_direct=dep.is_direct,
            lookup_result=lookup_result,
            behavioral=behavioral,
            risk_score=risk_score,
            anomaly_flagged=anomaly_flagged,
            base_severity=severity_result.base_severity,
            severity=severity_result.severity,
            escalated=severity_result.escalated,
            recommendation=recommendation,
            classifier_explanation=classifier_explanation,
            anomaly_explanation=anomaly_explanation,
            exploit_intel=exploit_intel_result,
            scorecard=scorecard_result,
        )
        records.append(record)

    return build_report(str(manifest_path), records)
