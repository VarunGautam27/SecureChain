from securechain.exploit_intel import ExploitIntelResult
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


def test_kev_listed_cve_gets_an_urgent_prefix_regardless_of_fix_availability():
    lookup = LookupResult(status="ok", cve_id="CVE-2022-31129", cvss_score=7.5, fixed_version="2.29.4")
    exploit_intel = ExploitIntelResult(status="ok", epss_score=0.049, epss_percentile=0.91, in_kev=True, kev_date_added="2022-09-01")
    recommendation = generate_recommendation("moment", "High", lookup, anomaly_flagged=False, exploit_intel=exploit_intel)
    assert "URGENT" in recommendation
    assert "CVE-2022-31129" in recommendation
    assert "2.29.4" in recommendation  # the underlying upgrade instruction is still present


def test_kev_prefix_applies_even_below_the_medium_threshold():
    lookup = LookupResult(status="ok", cve_id="CVE-9999-00001", cvss_score=2.0, fixed_version=None)
    exploit_intel = ExploitIntelResult(status="ok", in_kev=True, kev_date_added="2024-01-01")
    recommendation = generate_recommendation("some-pkg", "Low", lookup, anomaly_flagged=False, exploit_intel=exploit_intel)
    assert "URGENT" in recommendation


def test_not_in_kev_produces_no_urgent_prefix():
    lookup = LookupResult(status="ok", cve_id="CVE-2023-45857", cvss_score=6.5, fixed_version="1.6.0")
    exploit_intel = ExploitIntelResult(status="ok", epss_score=0.005, epss_percentile=0.42, in_kev=False)
    recommendation = generate_recommendation("axios", "Medium", lookup, anomaly_flagged=False, exploit_intel=exploit_intel)
    assert "URGENT" not in recommendation


def test_missing_exploit_intel_is_backward_compatible():
    lookup = LookupResult(status="ok", cve_id="CVE-2020-7598", cvss_score=5.6, fixed_version="1.2.6")
    recommendation = generate_recommendation("minimist", "Medium", lookup, anomaly_flagged=False)
    assert "URGENT" not in recommendation
    assert "1.2.6" in recommendation
