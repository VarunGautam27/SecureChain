from securechain.exploit_intel import ExploitIntelResult
from securechain.recommend import generate_recommendation, generate_static_scan_recommendation
from securechain.static_scan import StaticScanResult
from securechain.vuln_lookup import LookupResult


def test_cve_with_fixed_version_produces_upgrade_instruction():
    lookup = LookupResult(status="ok", cve_id="CVE-2020-7598", cvss_score=5.6, fixed_version="1.2.6")
    recommendation = generate_recommendation("minimist", "Medium", lookup)
    assert "1.2.6" in recommendation
    assert "minimist" in recommendation


def test_cve_without_fixed_version_produces_manual_mitigation_message():
    lookup = LookupResult(status="ok", cve_id="GHSA-cph5-hqp9-c525", cvss_score=None, fixed_version=None)
    recommendation = generate_recommendation("event-stream", "Medium", lookup)
    assert "no fix available" in recommendation.lower()


def test_low_severity_requires_no_action():
    lookup = LookupResult(status="ok", cve_id="CVE-0000-00000", cvss_score=2.0, fixed_version=None)
    recommendation = generate_recommendation("express", "Low", lookup)
    assert recommendation == "No action required."


def test_safe_severity_requires_no_action():
    lookup = LookupResult(status="ok", cve_id="CVE-0000-00001", cvss_score=0.0, fixed_version=None)
    recommendation = generate_recommendation("lodash", "Safe", lookup)
    assert recommendation == "No action required."


def test_kev_listed_cve_gets_an_urgent_prefix_regardless_of_fix_availability():
    lookup = LookupResult(status="ok", cve_id="CVE-2022-31129", cvss_score=7.5, fixed_version="2.29.4")
    exploit_intel = ExploitIntelResult(status="ok", epss_score=0.049, epss_percentile=0.91, in_kev=True, kev_date_added="2022-09-01")
    recommendation = generate_recommendation("moment", "High", lookup, exploit_intel=exploit_intel)
    assert "URGENT" in recommendation
    assert "CVE-2022-31129" in recommendation
    assert "2.29.4" in recommendation  # the underlying upgrade instruction is still present


def test_kev_prefix_applies_even_below_the_medium_threshold():
    lookup = LookupResult(status="ok", cve_id="CVE-9999-00001", cvss_score=2.0, fixed_version=None)
    exploit_intel = ExploitIntelResult(status="ok", in_kev=True, kev_date_added="2024-01-01")
    recommendation = generate_recommendation("some-pkg", "Low", lookup, exploit_intel=exploit_intel)
    assert "URGENT" in recommendation


def test_not_in_kev_produces_no_urgent_prefix():
    lookup = LookupResult(status="ok", cve_id="CVE-2023-45857", cvss_score=6.5, fixed_version="1.6.0")
    exploit_intel = ExploitIntelResult(status="ok", epss_score=0.005, epss_percentile=0.42, in_kev=False)
    recommendation = generate_recommendation("axios", "Medium", lookup, exploit_intel=exploit_intel)
    assert "URGENT" not in recommendation


def test_missing_exploit_intel_is_backward_compatible():
    lookup = LookupResult(status="ok", cve_id="CVE-2020-7598", cvss_score=5.6, fixed_version="1.2.6")
    recommendation = generate_recommendation("minimist", "Medium", lookup)
    assert "URGENT" not in recommendation
    assert "1.2.6" in recommendation


def test_transitive_dependency_recommends_overrides_not_a_direct_edit():
    lookup = LookupResult(status="ok", cve_id="CVE-2023-45857", cvss_score=6.5, fixed_version="1.6.0")
    recommendation = generate_recommendation("axios", "Medium", lookup, is_direct=False)
    assert "transitive" in recommendation.lower()
    assert "overrides" in recommendation.lower()
    assert "1.6.0" in recommendation


def test_direct_dependency_still_gets_the_plain_upgrade_instruction():
    lookup = LookupResult(status="ok", cve_id="CVE-2023-45857", cvss_score=6.5, fixed_version="1.6.0")
    recommendation = generate_recommendation("axios", "Medium", lookup, is_direct=True)
    assert "transitive" not in recommendation.lower()
    assert recommendation == "Upgrade axios to version 1.6.0 or later to remediate CVE-2023-45857."


def test_static_scan_not_run_recommends_scanning_before_trusting_it():
    recommendation = generate_static_scan_recommendation("newlib", StaticScanResult.not_run())
    assert "does not confirm it is" in recommendation.lower()
    assert "newlib" in recommendation


def test_static_scan_clean_recommends_proceeding():
    result = StaticScanResult(status="ok", flagged=False, indicators=[], files_scanned=3)
    recommendation = generate_static_scan_recommendation("newlib", result)
    assert "safe to proceed" in recommendation.lower()


def test_static_scan_confirmed_chain_recommends_an_alternative():
    result = StaticScanResult(
        status="ok", flagged=True, flag_reason="confirmed_chain",
        indicators=["tainted data flows into eval()"], files_scanned=3,
    )
    recommendation = generate_static_scan_recommendation("newlib", result)
    assert "alternative" in recommendation.lower()
    assert "no patch" in recommendation.lower()


def test_static_scan_install_hook_recommends_manual_review():
    result = StaticScanResult(
        status="ok", flagged=True, flag_reason="install_hook",
        indicators=["defines an install-time script"], files_scanned=3,
    )
    recommendation = generate_static_scan_recommendation("newlib", result)
    assert "review" in recommendation.lower()
    assert "install" in recommendation.lower()
