"""Generates the static, self-contained HTML report.

Single .html file: inline CSS (light/dark theme, both selected explicitly and
each validated for contrast, not an automatic invert) and one inline <script>
block (Chart.js init, the theme toggle, tab switching, and the severity
filter) plus one <script src="..."> tag loading Chart.js from a CDN - the only
external reference in the document, so the file still opens directly by
double-clicking with no server or build step. This report is produced only by
a `scan` (typically run inside CI/CD on push); there is no local server and
nothing in this file writes anywhere - reviewing a flagged dependency and
deciding whether to fix it or accept it happens outside this file entirely
(edit package.json to fix, or run `securechain accept` to record an exception).

Layout: a summary stat strip, then a severity scale legend that doubles as a
filter - an ALL tab (the default) plus one tab per tier (Safe/Low/Medium/High/
Critical); clicking a tier shows only cards at that exact severity, clicking
ALL shows every card again. Below that, one card per scanned dependency,
sorted worst-severity-first (Critical, High, Medium, Low, Safe) so the things
that need attention are always at the top regardless of where they appear in
the manifest, and regardless of which filter is active. Each card has a solid
severity badge (always visible) and a row of tabs - Recommendation (open by
default), CVSS, Severity, Behavioral - so a reviewer can drill into exactly
the detail they want. The CVSS tab also surfaces exploit intelligence (EPSS
score/percentile from FIRST.org, and CISA KEV catalog membership) when the
dependency has a CVE-identified advisory - CVSS alone measures potential
impact, not whether a vulnerability is actually being exploited anywhere, so
this fills that gap. It stays inside the CVSS tab rather than getting a tab of
its own (it's more context on the same CVE, not a separate assessment) but is
set off from the CVSS facts above it by a small "Exploit Intelligence"
subheading, so the two aren't read as one undifferentiated list. A KEV-listed
dependency also gets a badge next to its severity tag, visible without
opening any tab. There is deliberately no
separate "Explanation" tab: the
classifier's SHAP explanation lives inside Severity (it explains the risk
score right next to the tier it produced) and the anomaly detector's SHAP
explanation lives inside Behavioral (it explains why the raw feature values
were, or weren't, considered suspicious).

Severity color is a fixed, reserved 5-step scale (green Safe -> blue Low ->
amber Medium -> orange High -> red Critical), each validated for >= 4.5:1 text
contrast against its own fill (see the palette comment below) and isolated in a
clearly delimited CSS block (SEVERITY_COLOR_MARKER) so it can be mechanically
verified that no other hued color rule exists anywhere else in the document.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from securechain.riskignore import is_accepted, load_riskignore
from securechain.severity import tier_index

CHART_JS_CDN_URL = "https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"

SEVERITY_COLOR_MARKER = "/* ==== severity colors: the only color usage in this document ==== */"

SEVERITY_CLASS = {
    "Critical": "sev-critical",
    "High": "sev-high",
    "Medium": "sev-medium",
    "Low": "sev-low",
    "Safe": "sev-safe",
    "Unverified": "sev-unverified",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unverified", "Safe"]
SEVERITY_SCALE_ORDER = ["Safe", "Unverified", "Low", "Medium", "High", "Critical"]

# A fixed, reserved traffic-light scale (green -> blue -> amber -> orange -> red).
# Each fill's badge text color is whichever of white/dark clears >= 4.5:1 against
# it (checked with the WCAG text-contrast formula, not eyeballed); critical/high/
# low/safe use white text, medium (amber) uses dark text since white fails on it.
SEVERITY_GRADIENT = {
    "Critical": "#b0261a",
    "High": "#b85c00",
    "Medium": "#c99a1e",
    "Low": "#2c5f9e",
    "Unverified": "#6b6b76",
    "Safe": "#227a3d",
}

_STYLE = f"""
* {{ box-sizing: border-box; }}
:root {{
  color-scheme: light dark;
  --bg: #0b0d10;
  --surface: #15181d;
  --surface-2: #1d2127;
  --border: #2a2f37;
  --text: #f2f3f5;
  --text-secondary: #a7adb8;
  --shadow: none;
}}
@media (prefers-color-scheme: light) {{
  :root {{
    --bg: #f7f7f8;
    --surface: #ffffff;
    --surface-2: #f0f1f3;
    --border: #dfe1e6;
    --text: #14161a;
    --text-secondary: #5b6069;
    --shadow: 0 1px 3px rgba(11,11,11,0.08);
  }}
}}
:root[data-theme="dark"] {{
  --bg: #0b0d10;
  --surface: #15181d;
  --surface-2: #1d2127;
  --border: #2a2f37;
  --text: #f2f3f5;
  --text-secondary: #a7adb8;
  --shadow: none;
}}
:root[data-theme="light"] {{
  --bg: #f7f7f8;
  --surface: #ffffff;
  --surface-2: #f0f1f3;
  --border: #dfe1e6;
  --text: #14161a;
  --text-secondary: #5b6069;
  --shadow: 0 1px 3px rgba(11,11,11,0.08);
}}

body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg);
  color: var(--text);
  margin: 0;
  padding: 2rem;
  line-height: 1.5;
}}

.page-header {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 1rem;
  margin-bottom: 1.25rem;
}}
h1 {{ font-weight: bold; font-size: 1.6rem; margin: 0 0 0.25rem; }}
h2 {{ font-weight: bold; font-size: 1rem; margin: 0 0 0.6rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }}
.meta {{ color: var(--text-secondary); font-size: 0.85rem; margin: 0.15rem 0; }}

.theme-toggle {{
  border: 1px solid var(--border);
  background-color: var(--surface);
  color: var(--text);
  border-radius: 999px;
  padding: 0.4rem 0.9rem;
  font-size: 0.8rem;
  font-family: inherit;
  cursor: pointer;
}}

.stat-row {{ display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 1.75rem; }}
.stat-tile {{
  flex: 1 1 110px;
  border-radius: 10px;
  border: 1px solid var(--border);
  background-color: var(--surface);
  box-shadow: var(--shadow);
  padding: 0.7rem 0.9rem;
}}
.stat-tile .stat-value {{ font-size: 1.5rem; font-weight: bold; }}
.stat-tile .stat-label {{ font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.03em; }}

.severity-scale {{ margin-bottom: 2rem; }}
.severity-legend {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}

.severity-badge {{
  display: inline-block;
  border-radius: 999px;
  padding: 0.25rem 0.85rem;
  font-weight: bold;
  font-size: 0.75rem;
  letter-spacing: 0.03em;
  border: 1px solid var(--border);
}}

.severity-legend .severity-badge {{
  font-family: inherit;
  cursor: pointer;
  appearance: none;
}}
.severity-legend .severity-badge.legend-all {{
  background-color: var(--surface-2);
  color: var(--text);
}}
.severity-legend .severity-badge.active {{
  box-shadow: 0 0 0 2px var(--text);
}}

.accepted-tag {{
  display: inline-block;
  border-radius: 999px;
  padding: 0.2rem 0.7rem;
  font-size: 0.7rem;
  font-weight: bold;
  letter-spacing: 0.03em;
  border: 1px solid var(--border);
  color: var(--text-secondary);
  background-color: var(--surface-2);
}}

.dep-card {{
  border-radius: 14px;
  border: 1px solid var(--border);
  background-color: var(--surface);
  box-shadow: var(--shadow);
  margin-bottom: 1.25rem;
  overflow: hidden;
}}
.dep-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
  padding: 0.9rem 1.1rem;
  border-bottom: 1px solid var(--border);
}}
.dep-name-group {{ display: flex; align-items: baseline; gap: 0.6rem; flex-wrap: wrap; }}
.dep-name {{ font-weight: bold; font-size: 1.05rem; }}
.dep-version {{ font-weight: normal; font-size: 0.85rem; color: var(--text-secondary); }}
.dep-badges {{ display: flex; align-items: center; gap: 0.5rem; }}

.tab-bar {{ display: flex; flex-wrap: wrap; gap: 0.25rem; padding: 0.6rem 0.7rem 0; }}
.tab-btn {{
  border: none;
  border-radius: 8px;
  padding: 0.45rem 0.75rem;
  background-color: transparent;
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.82rem;
  font-weight: bold;
  cursor: pointer;
}}
.tab-btn.active {{ background-color: var(--surface-2); color: var(--text); }}

.tab-panel {{ padding: 1rem 1.1rem 1.2rem; }}
.tab-panel p {{ margin: 0.3rem 0; }}
.tab-panel .muted {{ color: var(--text-secondary); font-size: 0.85rem; }}
.tab-subheading {{
  margin: 0.9rem 0 0.4rem;
  padding-top: 0.7rem;
  border-top: 1px solid var(--border);
  font-size: 0.72rem;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
}}

.chart-container {{ max-width: 560px; margin: 2.5rem 0; }}
footer {{ margin-top: 2rem; font-size: 0.8rem; color: var(--text-secondary); }}

{SEVERITY_COLOR_MARKER}
.sev-critical {{ background-color: #b0261a; color: #ffffff; }}
.sev-high {{ background-color: #b85c00; color: #ffffff; }}
.sev-medium {{ background-color: #c99a1e; color: #14161a; }}
.sev-low {{ background-color: #2c5f9e; color: #ffffff; }}
.sev-unverified {{ background-color: #6b6b76; color: #ffffff; }}
.sev-safe {{ background-color: #227a3d; color: #ffffff; }}
"""


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _paragraphs(lines: list[str]) -> str:
    return "".join(f"<p>{_esc(line)}</p>" for line in lines if line)


def _exploit_intel_lines(dependency: dict) -> list[str]:
    """CVSS measures potential impact if exploited; it says nothing about whether
    a CVE is actually being exploited anywhere. These lines add that missing
    axis: EPSS (FIRST.org's predicted real-world exploitation probability) and
    CISA KEV (confirmed active exploitation). Only meaningful for CVE-identified
    advisories - GHSA-only identifiers have nothing to look up in either feed.
    """
    exploit_intel = dependency.get("exploit_intel") or {}
    status = exploit_intel.get("status")
    if status != "ok":
        return []

    lines: list[str] = []
    if exploit_intel.get("epss_score") is not None:
        lines.append(
            f"EPSS score {exploit_intel['epss_score']:.3f} "
            f"(percentile {exploit_intel['epss_percentile']:.0%}) - FIRST.org's predicted "
            "probability of real-world exploitation in the next 30 days."
        )
    if exploit_intel.get("in_kev"):
        lines.append(
            "Listed on CISA's Known Exploited Vulnerabilities catalog "
            f"since {exploit_intel.get('kev_date_added') or 'an unspecified date'} - "
            "confirmed active exploitation."
        )
    else:
        lines.append("Not listed on CISA's Known Exploited Vulnerabilities catalog.")
    return lines


def _cvss_lines(dependency: dict) -> list[str]:
    cvss = dependency["cvss"]
    lines: list[str] = []
    if cvss.get("score") is not None:
        lines.append(f"CVSS score {cvss['score']:.1f}")
    elif cvss.get("severity_label"):
        lines.append(f"Qualitative severity {cvss['severity_label']}, no numeric CVSS score was published.")
    else:
        lines.append("No CVSS score or CVE record was found for this version.")
    if cvss.get("cve_id"):
        lines.append(f"Identifier {cvss['cve_id']}")
    if cvss.get("cwes"):
        lines.append(f"Weakness category: {', '.join(cvss['cwes'])}")
    if cvss.get("fixed_version"):
        lines.append(f"Fixed in version {cvss['fixed_version']}")
    return lines


def _render_cvss_tab(dependency: dict) -> str:
    """Keeps the CVSS facts and the exploit-intelligence facts in the same tab
    (they're about the same CVE, not a separate assessment) but visually
    separated by a subheading, rather than one undifferentiated list of
    paragraphs, so a reader can tell at a glance which line is which.
    """
    content = _paragraphs(_cvss_lines(dependency))
    exploit_lines = _exploit_intel_lines(dependency)
    if exploit_lines:
        content += '<p class="tab-subheading">Exploit Intelligence (EPSS / CISA KEV)</p>'
        content += _paragraphs(exploit_lines)
    return content


def _severity_reason_lines(dependency: dict) -> list[str]:
    """Why this tier: for a catalogued CVE, severity comes strictly from its
    CVSS score (see the CVSS tab for the score itself). For a dependency
    with no catalogued CVE, severity reflects whether a static source-code
    scan has actually run yet - see the Static Analysis tab.
    """
    severity = dependency["severity"]
    if dependency["lookup_status"] == "ok":
        return [f"Severity is {severity}, based on this version's CVSS score. See the CVSS tab for details."]
    if severity == "Unverified":
        return [
            "Unverified: no CVE has been catalogued for this version, but that does not confirm it is "
            "safe. See the Static Analysis tab to run a real scan of its published source."
        ]
    if severity == "Safe":
        return ["Safe: no CVE has been catalogued, and a static scan of its real published source found nothing suspicious."]
    if severity == "Critical":
        return [
            "Critical: no CVE has been catalogued, but static analysis traced a confirmed data-flow "
            "chain from a suspicious source into a dangerous sink in its real source code - concrete "
            "evidence, not a keyword coincidence. See the Static Analysis tab for details."
        ]
    return [
        "High: no CVE has been catalogued, but static analysis found a suspicious pattern inside an "
        "install-time script, which runs automatically as soon as this package is installed. See the "
        "Static Analysis tab for details."
    ]


def _exploit_summary_lines(dependency: dict) -> list[str]:
    """What an attacker could actually do, pulled from the advisory's own
    summary when one exists, real advisories almost always describe the
    attack itself, not just a score.
    """
    attack_summary = dependency.get("cvss", {}).get("summary")
    return [attack_summary] if attack_summary else []


def _render_severity_tab(dependency: dict) -> str:
    """The tier decision itself, then, only when it exists, a labeled
    subheading before what an attacker could actually do - mirroring the
    same visually-separated pattern used in the CVSS tab.
    """
    content = _paragraphs(_severity_reason_lines(dependency))

    exploit_lines = _exploit_summary_lines(dependency)
    if exploit_lines:
        content += '<p class="tab-subheading">How This Could Be Exploited</p>'
        content += _paragraphs(exploit_lines)
    return content


def _scorecard_lines(dependency: dict) -> list[str]:
    """Every OpenSSF Scorecard check actually captured for this dependency's
    own repository, not only the single worst one, so a reader can see the
    full picture instead of one cherry picked number.
    """
    scorecard = dependency.get("scorecard") or {}
    if scorecard.get("status") != "ok" or scorecard.get("score") is None:
        return []

    lines = [
        f"Overall score for {scorecard.get('repo')}: {scorecard['score']:.1f} out of 10, a measure "
        "of the project's own repository health (code review, maintenance, branch protection), "
        "not of this specific pinned version."
    ]
    for check in scorecard.get("checks") or []:
        score = check.get("score")
        if score == -1:
            lines.append(f"{check.get('name')}: not applicable to this project.")
        elif isinstance(score, (int, float)):
            lines.append(f"{check.get('name')}: {score} out of 10.")
    return lines


def _render_scorecard_tab(dependency: dict) -> str:
    scorecard_lines = _scorecard_lines(dependency)
    if not scorecard_lines:
        return _paragraphs(["No OpenSSF Scorecard data available for this dependency's repository."])
    return _paragraphs(scorecard_lines)


def _behavioral_lines(dependency: dict) -> list[str]:
    """The 4 raw registry-metadata features, the anomaly flag, and the SHAP
    explanation of what made the Isolation Forest consider this normal or
    suspicious. Informational only - this never determines severity by
    itself (that caused real confusion earlier: a dependency shown "Safe"
    while also carrying a scary anomaly badge). Its role is triage: helping
    a reviewer decide which Unverified dependencies deserve a static scan
    first, restoring the same publish-pattern signal validated against real
    historical incidents (event-stream, ua-parser-js) without letting it
    silently set severity again.
    """
    behavioral = dependency.get("behavioral") or {}
    if not behavioral:
        return ["No behavioral data available for this dependency."]
    anomaly_explanation = dependency.get("anomaly_explanation", {}).get("explanation_text", "")
    lines = [
        f"Release frequency deviation {behavioral['release_frequency_deviation']:.2f}",
        f"Maintainer count {behavioral['maintainer_count']}",
        f"Version jump irregularity {behavioral['version_jump_irregularity']:.2f}",
        f"Download to age ratio {behavioral['download_age_ratio']:.2f}",
        "Anomaly detected - publishing pattern looks unusual" if dependency.get("anomaly_flagged")
        else "No anomaly detected - publishing pattern looks typical",
    ]
    if anomaly_explanation:
        lines.append(anomaly_explanation)
    if dependency.get("anomaly_flagged") and dependency.get("severity") == "Unverified":
        lines.append(
            "This dependency has no catalogued CVE and its publishing pattern looks unusual - "
            "prioritize running a static scan on it over other Unverified dependencies."
        )
    return lines


def _render_behavioral_tab(dependency: dict) -> str:
    return _paragraphs(_behavioral_lines(dependency))


def _static_scan_reason_lines(dependency: dict) -> list[str]:
    """This only ever runs for a dependency with no catalogued CVE at all, and
    only outside offline/cached-demo mode, since it downloads and reads the
    package's real published source text. The raw indicators (dynamic code
    execution, process spawning, raw network access, encoded payloads,
    hardcoded IPs, install-time hooks, a confirmed taint chain for Python)
    are shown as context; whether the dependency is actually flagged is
    decided by the trained static-scan classifier below, not by a hard rule
    on these indicators directly, since a single matched keyword or even
    several together proves nothing on its own in isolation.
    """
    static_scan = dependency.get("static_scan") or {}
    status = static_scan.get("status")

    if status == "not_run":
        return [
            "Not run for this dependency. This scan only runs when no CVE was found for "
            "this version at all, and only outside cached-demo mode, since it downloads "
            "the package's real published source."
        ]
    if status == "lookup_failed":
        reason = (static_scan.get("indicators") or ["unknown reason"])[0]
        return [f"Could not complete: {reason}"]

    files_scanned = static_scan.get("files_scanned", 0)
    indicators = static_scan.get("indicators") or []
    if not indicators:
        return [
            f"Scanned {files_scanned} source file(s) from the package's real published "
            "release. No indicators from the checked list were found."
        ]

    lines = [
        f"Scanned {files_scanned} source file(s) from the package's real published release.",
        "Indicators present: " + "; ".join(indicators) + ".",
    ]
    if not static_scan.get("flagged"):
        lines.append(
            "Not flagged even so - this is not a determination of malicious intent, it "
            "narrows down where a human reviewer might look, nothing more."
        )
    return lines


def _static_scan_risk_lines(dependency: dict) -> list[str]:
    """The static-scan classifier's own score and SHAP explanation - trained
    on a documented synthetic dataset (see ml/training_data.py's
    generate_static_scan_dataset), same methodology as the rest of this
    tool's models, not on real confirmed malware samples.
    """
    static_scan = dependency.get("static_scan") or {}
    if static_scan.get("status") != "ok" or static_scan.get("ml_risk_score") is None:
        return []
    lines = [f"Static-scan risk score {static_scan['ml_risk_score']:.2f} from the trained classifier."]
    explanation = (static_scan.get("ml_explanation") or {}).get("explanation_text", "")
    if explanation:
        lines.append(explanation)
    return lines


def _render_static_scan_tab(dependency: dict) -> str:
    content = _paragraphs(_static_scan_reason_lines(dependency))
    risk_lines = _static_scan_risk_lines(dependency)
    if risk_lines:
        content += '<p class="tab-subheading">Static Analysis Risk Score</p>'
        content += _paragraphs(risk_lines)
    return content


def _render_severity_scale() -> str:
    all_button = (
        '<button type="button" class="severity-badge legend-all active" '
        'onclick="scFilterBySeverity(this, \'all\')">ALL</button>'
    )
    tier_buttons = "".join(
        f'<button type="button" class="severity-badge {SEVERITY_CLASS[tier]}" '
        f"onclick=\"scFilterBySeverity(this, '{tier}')\">{_esc(tier.upper())}</button>"
        for tier in SEVERITY_SCALE_ORDER
    )
    return f"""
    <div class="severity-scale">
      <h2>Severity Scale</h2>
      <div class="severity-legend">{all_button}{tier_buttons}</div>
    </div>"""


def _render_card(dependency: dict, index: int, ignore_store: dict) -> str:
    severity = dependency["severity"]
    sev_class = SEVERITY_CLASS.get(severity, "sev-safe")
    dep_id = f"dep-{index}"
    existing = is_accepted(ignore_store, dependency["package"], dependency["version"])

    tabs = [
        ("recommendation", "Recommendation", _paragraphs([dependency["recommendation"]])),
        ("cvss", "CVSS", _render_cvss_tab(dependency)),
        ("severity", "Severity", _render_severity_tab(dependency)),
        ("behavioral", "Behavioral", _render_behavioral_tab(dependency)),
        ("scorecard", "Scorecard", _render_scorecard_tab(dependency)),
    ]
    # Only meaningful for a dependency with no catalogued CVE - for a known
    # vulnerability this tab would only ever say "not run", which is clutter,
    # not information.
    if dependency["lookup_status"] != "ok":
        tabs.append(("static_scan", "Static Analysis", _render_static_scan_tab(dependency)))

    tab_buttons = "".join(
        f'<button type="button" class="tab-btn{" active" if i == 0 else ""}" '
        f"onclick=\"scShowTab(this, '{dep_id}', '{key}')\">{_esc(label)}</button>"
        for i, (key, label, _content) in enumerate(tabs)
    )
    tab_panels = "".join(
        f'<div class="tab-panel" data-dep="{dep_id}" data-tab="{key}"{"" if i == 0 else " hidden"}>'
        f"{content}</div>"
        for i, (key, label, content) in enumerate(tabs)
    )

    accepted_tag = ""
    if existing is not None:
        accepted_tag = (
            f'<span class="accepted-tag" title="Accepted on {_esc(existing.date)} by '
            f'{_esc(existing.accepted_by)}: {_esc(existing.reason)}">ACCEPTED</span>'
        )

    exploit_intel = dependency.get("exploit_intel") or {}
    kev_tag = ""
    if exploit_intel.get("status") == "ok" and exploit_intel.get("in_kev"):
        kev_tag = (
            '<span class="accepted-tag" title="Listed on CISA\'s Known Exploited '
            'Vulnerabilities catalog: confirmed active exploitation">KEV</span>'
        )

    static_scan = dependency.get("static_scan") or {}
    static_scan_tag = ""
    if static_scan.get("status") == "ok":
        static_scan_tag = (
            '<span class="accepted-tag">STATIC SCAN: REVIEW</span>'
            if static_scan.get("flagged")
            else '<span class="accepted-tag">STATIC SCAN: CLEAN</span>'
        )

    priority_tag = ""
    if dependency.get("anomaly_flagged") and severity == "Unverified":
        priority_tag = (
            '<span class="accepted-tag" title="Publishing pattern looks unusual - see the '
            'Behavioral tab">PRIORITIZE SCAN</span>'
        )

    return f"""
    <section class="dep-card" data-package="{_esc(dependency['package'])}" data-severity="{_esc(severity)}">
      <div class="dep-header">
        <div class="dep-name-group">
          <span class="dep-name">{_esc(dependency['package'])}</span>
          <span class="dep-version">{_esc(dependency['version'])}</span>
          <span class="accepted-tag">{_esc(dependency.get('ecosystem', 'npm').upper())}</span>
          {'<span class="accepted-tag">TRANSITIVE</span>' if dependency.get('is_direct') is False else ''}
        </div>
        <div class="dep-badges">
          {accepted_tag}
          {kev_tag}
          {static_scan_tag}
          {priority_tag}
          <span class="severity-badge {sev_class}">{_esc(severity.upper())}</span>
        </div>
      </div>
      <div class="tab-bar">{tab_buttons}</div>
      {tab_panels}
    </section>"""


def _render_header(report: dict) -> str:
    scanned_by = report.get("scanned_by")
    scanned_by_line = f'<p class="meta">Scanned by: {_esc(scanned_by)}</p>' if scanned_by else ""
    return f"""
    <div class="page-header">
      <div>
        <h1>SecureChain Dependency Risk Report</h1>
        <p class="meta">Scan date: {_esc(report['scan_date'])}</p>
        <p class="meta">Manifest: {_esc(report['manifest_path'])}</p>
        {scanned_by_line}
      </div>
      <button type="button" class="theme-toggle" onclick="scToggleTheme()">Toggle theme</button>
    </div>"""


def _render_stat_row(report: dict) -> str:
    summary = report["summary"]
    total_tile = (
        '<div class="stat-tile"><div class="stat-value">'
        f'{summary["total"]}</div><div class="stat-label">Total</div></div>'
    )
    tier_tiles = "".join(
        f'<div class="stat-tile"><div class="stat-value" style="color:{SEVERITY_GRADIENT[tier]}">'
        f'{summary.get(tier.lower(), 0)}</div><div class="stat-label">{_esc(tier)}</div></div>'
        for tier in SEVERITY_ORDER
    )
    return f'<div class="stat-row">{total_tile}{tier_tiles}</div>'


def render_html_report(report: dict, ignore_file: str | Path = ".riskignore.json") -> str:
    ignore_store: dict = {}
    try:
        ignore_store = load_riskignore(ignore_file)
    except ValueError:
        ignore_store = {"exceptions": []}

    # Worst severity first (Critical -> Safe), so what needs attention is always
    # at the top regardless of the order dependencies happen to appear in the
    # manifest.
    sorted_dependencies = sorted(
        report["dependencies"], key=lambda dep: -tier_index(dep["severity"])
    )

    cards_html = "".join(
        _render_card(dep, i, ignore_store) for i, dep in enumerate(sorted_dependencies)
    )
    header_html = _render_header(report)
    stat_row_html = _render_stat_row(report)
    severity_scale_html = _render_severity_scale()
    chart_data = {
        "labels": SEVERITY_ORDER,
        "counts": [report["summary"].get(tier.lower(), 0) for tier in SEVERITY_ORDER],
        "colors": [SEVERITY_GRADIENT[tier] for tier in SEVERITY_ORDER],
    }

    return f"""<title>SecureChain Dependency Risk Report</title>
<style>{_STYLE}</style>
{header_html}
{stat_row_html}
{severity_scale_html}
{cards_html}
<div class="chart-container">
  <canvas id="severityChart" width="560" height="360"></canvas>
</div>
<footer>Generated by SecureChain. This report is static; re-run a scan to refresh it.</footer>
<script src="{CHART_JS_CDN_URL}"></script>
<script>
  function scShowTab(button, depId, tabName) {{
    var panels = document.querySelectorAll('.tab-panel[data-dep="' + depId + '"]');
    for (var i = 0; i < panels.length; i++) {{
      panels[i].hidden = panels[i].getAttribute('data-tab') !== tabName;
    }}
    var buttons = button.parentElement.querySelectorAll('.tab-btn');
    for (var j = 0; j < buttons.length; j++) {{
      buttons[j].classList.remove('active');
    }}
    button.classList.add('active');
  }}

  function scFilterBySeverity(button, tier) {{
    var cards = document.querySelectorAll('.dep-card');
    for (var i = 0; i < cards.length; i++) {{
      var show = (tier === 'all' || cards[i].getAttribute('data-severity') === tier);
      cards[i].style.display = show ? '' : 'none';
    }}
    var badges = button.parentElement.querySelectorAll('.severity-badge');
    for (var j = 0; j < badges.length; j++) {{
      badges[j].classList.remove('active');
    }}
    button.classList.add('active');
  }}

  function scToggleTheme() {{
    var root = document.documentElement;
    var current = root.getAttribute('data-theme');
    var next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try {{ localStorage.setItem('securechain-theme', next); }} catch (e) {{}}
  }}
  (function () {{
    try {{
      var saved = localStorage.getItem('securechain-theme');
      if (saved) document.documentElement.setAttribute('data-theme', saved);
    }} catch (e) {{}}
  }})();

  var chartData = {json.dumps(chart_data)};
  new Chart(document.getElementById('severityChart'), {{
    type: 'bar',
    data: {{
      labels: chartData.labels,
      datasets: [{{
        label: 'Dependencies per severity tier',
        data: chartData.counts,
        backgroundColor: chartData.colors
      }}]
    }},
    options: {{
      plugins: {{ legend: {{ display: false }} }},
      scales: {{ y: {{ beginAtZero: true, ticks: {{ precision: 0 }} }} }}
    }}
  }});
</script>
"""


def write_html_report(report: dict, output_path: str | Path, ignore_file: str | Path = ".riskignore.json") -> None:
    Path(output_path).write_text(render_html_report(report, ignore_file=ignore_file), encoding="utf-8")
