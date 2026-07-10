import pytest

from securechain.severity import label_severity

# (cvss_score, anomaly_flagged) -> expected (base_severity, severity)
CASES = [
    (None, False, "Safe", "Safe"),
    (None, True, "Safe", "Low"),  # escalation cap: no CVE + anomaly -> Low, never higher
    (2.0, False, "Low", "Low"),
    (2.0, True, "Low", "Medium"),
    (5.0, False, "Medium", "Medium"),
    (5.0, True, "Medium", "High"),
    (7.5, False, "High", "High"),
    (7.5, True, "High", "Critical"),
    (9.8, False, "Critical", "Critical"),
    (9.8, True, "Critical", "Critical"),  # already at ceiling, cannot escalate further
]


@pytest.mark.parametrize("cvss_score,anomaly_flagged,expected_base,expected_final", CASES)
def test_severity_matrix(cvss_score, anomaly_flagged, expected_base, expected_final):
    result = label_severity(cvss_score, anomaly_flagged)
    assert result.base_severity == expected_base
    assert result.severity == expected_final


def test_escalation_cap_never_jumps_two_tiers():
    result = label_severity(None, True)
    assert result.severity == "Low"
    assert result.severity != "Medium"
    assert result.severity != "High"
    assert result.severity != "Critical"


def test_critical_with_no_anomaly_is_not_downgraded():
    result = label_severity(9.9, False)
    assert result.severity == "Critical"
    assert result.escalated is False


def test_escalated_flag_reflects_whether_a_tier_change_occurred():
    escalated = label_severity(2.0, True)
    not_escalated = label_severity(2.0, False)
    assert escalated.escalated is True
    assert not_escalated.escalated is False
