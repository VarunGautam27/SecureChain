"""Full pipeline regression test: scan -> check -> HTML generation against the
documented 15-dependency demo manifest, tying every component together.
"""

from securechain.gate import evaluate_gate
from securechain.pipeline import run_scan
from securechain.report_html import render_html_report

EXPECTED_SEVERITIES = {
    "lodash": "Safe",
    "chalk": "Safe",
    "uuid": "Safe",
    "debug": "Safe",
    "semver": "Safe",
    "commander": "Safe",
    "dotenv": "Safe",
    "yargs": "Safe",
    "picocolors": "Safe",
    "colors": "Low",
    "minimist": "Medium",
    "axios": "Medium",
    "moment": "High",
    "xml2js": "Critical",
    "node-ipc": "Critical",
}

# Every non-Safe dependency here has no accepted exception in a nonexistent
# ignore file, so all 6 must block under the default "safe" threshold.
_EXPECTED_BLOCKERS = ["colors", "minimist", "axios", "moment", "xml2js", "node-ipc"]


def test_end_to_end_demo_pipeline_matches_documented_severities(demo_manifest_path, demo_cache_dir):
    report = run_scan(demo_manifest_path, cache_dir=demo_cache_dir, offline=True)

    actual_severities = {dep["package"]: dep["severity"] for dep in report["dependencies"]}
    assert actual_severities == EXPECTED_SEVERITIES

    # CI/CD gate (default threshold: safe): every non-Safe dependency here is
    # unaccepted, so the build must fail.
    gate_result = evaluate_gate(report, ignore_file="does-not-exist.json")
    assert gate_result.exit_code != 0
    for package in _EXPECTED_BLOCKERS:
        assert any(package in failure for failure in gate_result.failures)

    # HTML report renders without error, includes every dependency, and sorts
    # worst severity first (xml2js/node-ipc Critical) down to safest last
    # (the 9 Safe packages).
    html_output = render_html_report(report, ignore_file="does-not-exist.json")
    for package in EXPECTED_SEVERITIES:
        assert package in html_output
    positions = {pkg: html_output.index(f'data-package="{pkg}"') for pkg in EXPECTED_SEVERITIES}
    assert positions["xml2js"] < positions["moment"] < positions["minimist"] < positions["colors"] < positions["lodash"]
