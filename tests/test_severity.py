import pytest

from securechain.severity import (
    UNVERIFIED,
    label_severity,
    label_static_scan_status,
    label_unscanned_status,
    tier_index,
)

# cvss_score -> expected severity (CVE-found path: strictly CVSS-based, no escalation)
CASES = [
    (None, "Safe"),
    (0.1, "Low"),
    (2.0, "Low"),
    (5.0, "Medium"),
    (7.5, "High"),
    (9.8, "Critical"),
]


@pytest.mark.parametrize("cvss_score,expected", CASES)
def test_severity_matrix(cvss_score, expected):
    result = label_severity(cvss_score)
    assert result.base_severity == expected
    assert result.severity == expected


def test_label_unscanned_status_is_unverified():
    assert label_unscanned_status() == UNVERIFIED


def test_label_static_scan_status_not_yet_run_is_unverified():
    assert label_static_scan_status("not_run", None) == UNVERIFIED
    assert label_static_scan_status("lookup_failed", None) == UNVERIFIED


def test_label_static_scan_status_clean_is_safe():
    assert label_static_scan_status("ok", None) == "Safe"


def test_label_static_scan_status_confirmed_chain_is_critical():
    assert label_static_scan_status("ok", "confirmed_chain") == "Critical"


def test_label_static_scan_status_install_hook_is_high():
    assert label_static_scan_status("ok", "install_hook") == "High"


def test_tier_index_treats_unverified_same_as_low():
    assert tier_index(UNVERIFIED) == tier_index("Low")
