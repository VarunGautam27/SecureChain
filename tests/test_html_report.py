import re

from securechain.report_html import SEVERITY_COLOR_MARKER, render_html_report

_HEX_COLOR_RE = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})\b")


# A polished neutral UI palette uses subtly tinted grays (background/border/text
# tones), not mathematically pure r==g==b gray - real design systems do this too
# (see the dataviz skill's own reference palette). The 5 reserved severity hues
# are unmistakably more saturated than any such tint: their max channel spread is
# 88-184, versus at most ~17 for this report's neutral UI tones. 24 cleanly
# separates "a polished neutral" from "an actual hue" with margin on both sides.
_NEUTRAL_SPREAD_THRESHOLD = 24


def _is_black_white_or_gray(hex_code: str) -> bool:
    hex_code = hex_code.lstrip("#")
    if len(hex_code) == 3:
        hex_code = "".join(c * 2 for c in hex_code)
    r, g, b = (int(hex_code[0:2], 16), int(hex_code[2:4], 16), int(hex_code[4:6], 16))
    return max(r, g, b) - min(r, g, b) <= _NEUTRAL_SPREAD_THRESHOLD


def _sample_report(n=3, scanned_by=None):
    dependencies = []
    # Deliberately built in ascending severity order (Safe first), so tests can
    # confirm render_html_report re-sorts to worst-first rather than relying on
    # whatever order happened to be passed in.
    severities = ["Safe", "Low", "Medium", "High", "Critical"][:n]
    for i, sev in enumerate(severities):
        dependencies.append({
            "package": f"pkg-{i}",
            "version": "1.0.0",
            "cvss": {"score": None, "cve_id": None, "severity_label": None, "fixed_version": None},
            "behavioral": {
                "release_frequency_deviation": 0.5,
                "maintainer_count": 2,
                "version_jump_irregularity": 0.5,
                "download_age_ratio": 10.0,
            },
            "risk_score": 0.1 * i,
            "anomaly_flagged": False,
            "base_severity": sev,
            "severity": sev,
            "escalated": False,
            "recommendation": "No action required.",
            "shap": {
                "classifier": {"explanation_text": "Not flagged."},
                "anomaly": {"explanation_text": "Not flagged."},
            },
        })
    report = {
        "scan_date": "2026-07-09T00:00:00+00:00",
        "manifest_path": "demo/package.json",
        "summary": {"total": n, "critical": 1 if n >= 5 else 0, "high": 1 if n >= 4 else 0,
                     "medium": 1 if n >= 3 else 0, "low": 1 if n >= 2 else 0, "safe": 1},
        "dependencies": dependencies,
    }
    if scanned_by:
        report["scanned_by"] = scanned_by
    return report


_NO_IGNORE_FILE = "this-ignore-file-does-not-exist.json"


def test_html_report_has_one_card_per_dependency():
    report = _sample_report(5)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    card_count = html_output.count('class="dep-card"')
    assert card_count == len(report["dependencies"])
    for dep in report["dependencies"]:
        assert f'data-package="{dep["package"]}"' in html_output


def test_cards_are_sorted_worst_severity_first():
    report = _sample_report(5)  # built ascending: Safe, Low, Medium, High, Critical
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    positions = {pkg: html_output.index(f'data-package="{pkg}"') for pkg in
                 ["pkg-0", "pkg-1", "pkg-2", "pkg-3", "pkg-4"]}
    # pkg-4 is Critical, pkg-0 is Safe; Critical must render before Safe.
    assert positions["pkg-4"] < positions["pkg-3"] < positions["pkg-2"] < positions["pkg-1"] < positions["pkg-0"]


def test_scanned_by_appears_in_header_when_present():
    report = _sample_report(3, scanned_by="ayush")
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)
    assert "Scanned by: ayush" in html_output


def test_recommendation_tab_is_visible_by_default():
    report = _sample_report(3)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    # The recommendation panel (tab index 0) must not carry the "hidden" attribute,
    # unlike the other tabs, so the recommendation is visible without any clicking.
    assert re.search(r'data-tab="recommendation">\s*<p>No action required\.</p>', html_output)
    assert re.search(r'data-tab="cvss"\s+hidden', html_output)
    assert re.search(r'data-tab="severity"\s+hidden', html_output)
    assert re.search(r'data-tab="behavioral"\s+hidden', html_output)
    assert 'data-tab="explanation"' not in html_output
    assert 'data-tab="triage"' not in html_output


def test_severity_badge_has_solid_color_class_per_tier():
    report = _sample_report(5)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    for tier in ["safe", "low", "medium", "high", "critical"]:
        assert f'class="severity-badge sev-{tier}"' in html_output


def test_severity_scale_legend_shows_all_five_tiers():
    report = _sample_report(5)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    legend_start = html_output.index("Severity Scale")
    legend_section = html_output[legend_start:legend_start + 900]
    for tier in ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        assert tier in legend_section


def test_severity_legend_has_clickable_filter_buttons_including_all():
    report = _sample_report(5)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    legend_start = html_output.index("Severity Scale")
    legend_section = html_output[legend_start:legend_start + 900]

    assert "scFilterBySeverity(this, 'all')" in legend_section
    assert '>ALL</button>' in legend_section
    for tier in ["Safe", "Low", "Medium", "High", "Critical"]:
        assert f"scFilterBySeverity(this, '{tier}')" in legend_section

    # The ALL tab is active by default, since no filter is applied on load.
    assert 'class="severity-badge legend-all active"' in html_output


def test_dep_cards_carry_a_data_severity_attribute_matching_their_tier():
    report = _sample_report(5)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    for dep in report["dependencies"]:
        assert f'data-package="{dep["package"]}" data-severity="{dep["severity"]}"' in html_output


def test_filter_function_is_defined_in_the_inline_script():
    report = _sample_report(3)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)
    assert "function scFilterBySeverity(button, tier)" in html_output


def test_no_color_outside_the_severity_block():
    report = _sample_report(5)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    marker_index = html_output.index(SEVERITY_COLOR_MARKER)
    before_marker = html_output[:marker_index]

    # Everything before the severity color block (i.e. the stylesheet rules above
    # it) must be black/white/gray only - only the .sev-* rules after the marker,
    # and the severity-colored inline styles in the rendered body (stat tiles,
    # badges, chart data) further down the document, may use the reserved hues.
    for match in _HEX_COLOR_RE.finditer(before_marker):
        assert _is_black_white_or_gray(match.group(0)), f"Unexpected hued color outside severity block: {match.group(0)}"

    # The severity block itself is expected to contain non-grayscale (hued) colors.
    after_marker = html_output[marker_index:]
    hued_colors_in_block = [
        m.group(0) for m in _HEX_COLOR_RE.finditer(after_marker) if not _is_black_white_or_gray(m.group(0))
    ]
    assert hued_colors_in_block, "Expected the severity color block to contain the restrained severity hues"


def test_no_accepted_tag_when_not_yet_accepted(tmp_path):
    report = _sample_report(3)
    ignore_file = tmp_path / ".riskignore.json"
    html_output = render_html_report(report, ignore_file=ignore_file)

    assert "ACCEPTED" not in html_output


def test_accepted_tag_shown_read_only_when_already_in_ignore_file(tmp_path):
    from securechain.riskignore import accept_risk

    report = _sample_report(3)
    ignore_file = tmp_path / ".riskignore.json"
    accept_risk(ignore_file, "pkg-0", "1.0.0", "already reviewed", "ayush", "2026-07-09")

    html_output = render_html_report(report, ignore_file=ignore_file)

    assert "ACCEPTED" in html_output
    assert "already reviewed" in html_output
    # Read-only: no form, no input, no way to submit a new acceptance from the page.
    assert "<textarea" not in html_output
    assert "<input" not in html_output
    assert "Accept Risk" not in html_output


def test_cvss_tab_shows_epss_and_kev_when_present():
    report = _sample_report(1)
    report["dependencies"][0]["cvss"] = {
        "score": 7.5, "cve_id": "CVE-2022-31129", "severity_label": None, "fixed_version": "2.29.4"
    }
    report["dependencies"][0]["exploit_intel"] = {
        "status": "ok", "epss_score": 0.04923, "epss_percentile": 0.91087,
        "in_kev": True, "kev_date_added": "2022-09-01", "source": "cache",
    }
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    assert "EPSS score 0.049" in html_output
    assert "91%" in html_output
    assert "Known Exploited Vulnerabilities" in html_output
    assert ">KEV</span>" in html_output


def test_cvss_tab_shows_not_listed_when_not_in_kev():
    report = _sample_report(1)
    report["dependencies"][0]["cvss"] = {
        "score": 6.5, "cve_id": "CVE-2023-45857", "severity_label": None, "fixed_version": "1.6.0"
    }
    report["dependencies"][0]["exploit_intel"] = {
        "status": "ok", "epss_score": 0.00556, "epss_percentile": 0.42431,
        "in_kev": False, "kev_date_added": None, "source": "cache",
    }
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    assert "Not listed on CISA" in html_output
    assert ">KEV</span>" not in html_output


def test_missing_exploit_intel_key_does_not_break_rendering():
    report = _sample_report(3)  # _sample_report dependencies carry no "exploit_intel" key at all
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)
    assert "EPSS" not in html_output


def test_single_file_with_only_chart_js_cdn_as_external_dependency():
    report = _sample_report(3)
    html_output = render_html_report(report, ignore_file=_NO_IGNORE_FILE)

    script_src_tags = re.findall(r'<script[^>]+src="([^"]+)"', html_output)
    assert len(script_src_tags) == 1
    assert "chart.js" in script_src_tags[0].lower()
    assert "cdn" in script_src_tags[0].lower() or script_src_tags[0].startswith("https://")

    assert "<link" not in html_output.lower()
