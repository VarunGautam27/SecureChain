from securechain.recommend import generate_recommendation
from securechain.vuln_lookup import LookupResult


def test_cve_with_fixed_version_produces_upgrade_instruction():
    lookup = LookupResult(status="ok", cve_id="CVE-2020-7598", cvss_score=5.6, fixed_version="1.2.6")
    recommendation = generate_recommendation("minimist", "Medium", lookup, anomaly_flagged=False)
    assert "1.2.6" in recommendation
    assert "minimist" in recommendation


def test_cve_without_fixed_version_produces_manual_mitigation_message():
    lookup = LookupResult(status="ok", cve_id="GHSA-cph5-hqp9-c525", cvss_score=None, fixed_version=None)
    recommendation = generate_recommendation("event-stream", "Medium", lookup, anomaly_flagged=True)
    assert "no fix available" in recommendation.lower()


def test_anomaly_only_medium_produces_behavioral_audit_message():
    lookup = LookupResult.no_cve()
    recommendation = generate_recommendation("event-stream", "Medium", lookup, anomaly_flagged=True)
    assert "audit" in recommendation.lower()


def test_low_severity_requires_no_action():
    lookup = LookupResult.no_cve()
    recommendation = generate_recommendation("express", "Low", lookup, anomaly_flagged=True)
    assert recommendation == "No action required."


def test_safe_severity_requires_no_action():
    lookup = LookupResult.no_cve()
    recommendation = generate_recommendation("lodash", "Safe", lookup, anomaly_flagged=False)
    assert recommendation == "No action required."
