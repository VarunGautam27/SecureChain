import requests

from securechain.vuln_lookup import (
    CachedLookupClient,
    GitHubAdvisoryClient,
    NVDClient,
    base_cvss_score,
)
from tests.conftest import FakeResponse, FakeSession


def _ghsa_payload(vulnerable_range, cvss_score, cve_id, fixed_version, severity="HIGH"):
    return {
        "data": {
            "securityVulnerabilities": {
                "nodes": [
                    {
                        "advisory": {
                            "summary": "Test advisory",
                            "severity": severity,
                            "cvss": {"score": cvss_score},
                            "identifiers": [{"type": "CVE", "value": cve_id}],
                        },
                        "vulnerableVersionRange": vulnerable_range,
                        "firstPatchedVersion": {"identifier": fixed_version} if fixed_version else None,
                    }
                ]
            }
        }
    }


def test_known_cve_maps_to_correct_cvss_and_fixed_version():
    client = GitHubAdvisoryClient(token="fake-token")
    client.session = FakeSession(
        post_result=FakeResponse(_ghsa_payload(">= 1.0.0, < 1.2.6", 5.6, "CVE-2020-7598", "1.2.6"))
    )

    result = client.lookup("minimist", "1.2.0")

    assert result.status == "ok"
    assert result.cve_id == "CVE-2020-7598"
    assert result.cvss_score == 5.6
    assert result.fixed_version == "1.2.6"


def test_no_matching_cve_maps_to_no_cve_status():
    client = GitHubAdvisoryClient(token="fake-token")
    client.session = FakeSession(post_result=FakeResponse({"data": {"securityVulnerabilities": {"nodes": []}}}))

    result = client.lookup("lodash", "4.17.21")

    assert result.status == "no_cve"


def test_version_outside_vulnerable_range_is_not_matched():
    client = GitHubAdvisoryClient(token="fake-token")
    client.session = FakeSession(
        post_result=FakeResponse(_ghsa_payload("< 1.2.6", 5.6, "CVE-2020-7598", "1.2.6"))
    )

    # 1.2.6 is the fixed version, so it should NOT be matched by "< 1.2.6".
    result = client.lookup("minimist", "1.2.6")

    assert result.status == "no_cve"


def test_api_timeout_degrades_gracefully_to_lookup_failed():
    client = GitHubAdvisoryClient(token="fake-token")
    client.session = FakeSession(post_result=requests.Timeout("simulated timeout"))

    result = client.lookup("some-package", "1.0.0")

    assert result.status == "lookup_failed"


def test_missing_github_token_degrades_gracefully():
    client = GitHubAdvisoryClient(token=None)
    result = client.lookup("some-package", "1.0.0")
    assert result.status == "lookup_failed"


def test_nvd_client_handles_api_failure_gracefully():
    client = NVDClient()
    client.session = FakeSession(get_result=requests.ConnectionError("simulated failure"))

    result = client.lookup("some-package", "1.0.0")

    assert result.status == "lookup_failed"


def test_nvd_client_no_results_maps_to_no_cve():
    client = NVDClient()
    client.session = FakeSession(get_result=FakeResponse({"vulnerabilities": []}))

    result = client.lookup("some-package", "1.0.0")

    assert result.status == "no_cve"


def test_cached_lookup_client_reads_cache_before_live_apis(tmp_path):
    cache_dir = tmp_path
    (cache_dir / "advisories.json").write_text(
        '{"xml2js@0.4.19": {"status": "ok", "cve_id": "GHSA-776f-qq4e-3rc3", '
        '"cvss_score": 9.8, "fixed_version": "0.5.0"}}'
    )

    client = CachedLookupClient(cache_dir=cache_dir, offline=True)
    result = client.lookup("xml2js", "0.4.19")

    assert result.status == "ok"
    assert result.cve_id == "GHSA-776f-qq4e-3rc3"
    assert result.cvss_score == 9.8


def test_offline_mode_without_cache_entry_reports_lookup_failed(tmp_path):
    client = CachedLookupClient(cache_dir=tmp_path, offline=True)
    result = client.lookup("unlisted-package", "1.0.0")
    assert result.status == "lookup_failed"


def test_base_cvss_score_falls_back_to_qualitative_severity():
    client = CachedLookupClient(cache_dir=None, offline=True)
    result = client.lookup("anything", "1.0.0")
    assert result.status == "lookup_failed"
    assert base_cvss_score(result) is None
