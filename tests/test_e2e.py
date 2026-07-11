"""Full pipeline regression test: scan -> check -> HTML generation against the
documented 20-dependency demo manifest, tying every component together.
"""

import shutil

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
    "ansi-regex": "High",
    "glob-parent": "High",
    "json5": "High",
    "word-wrap": "Medium",
    "tar": "High",
}

# Every non-Safe dependency here has no accepted exception in a nonexistent
# ignore file, so all 11 must block under the default "safe" threshold.
_EXPECTED_BLOCKERS = [
    "colors", "minimist", "axios", "moment", "xml2js", "node-ipc",
    "ansi-regex", "glob-parent", "json5", "word-wrap", "tar",
]

# minimist/axios/moment carry a real CVE ID in the demo fixtures, so exploit
# intelligence (EPSS/KEV) is looked up for them; xml2js/node-ipc use GHSA
# identifiers (no CVE was ever assigned), so EPSS/KEV is "not_applicable" -
# both feeds are indexed strictly by CVE ID.
_EXPECTED_EXPLOIT_INTEL_STATUS = {
    "minimist": "ok",
    "axios": "ok",
    "moment": "ok",
    "xml2js": "not_applicable",
    "node-ipc": "not_applicable",
    "lodash": "not_applicable",
    "ansi-regex": "ok",
    "glob-parent": "ok",
    "json5": "ok",
    "word-wrap": "ok",
    "tar": "ok",
}


def test_end_to_end_demo_pipeline_matches_documented_severities(demo_manifest_path, demo_cache_dir):
    report = run_scan(demo_manifest_path, cache_dir=demo_cache_dir, offline=True)

    actual_severities = {dep["package"]: dep["severity"] for dep in report["dependencies"]}
    assert actual_severities == EXPECTED_SEVERITIES

    actual_exploit_intel = {dep["package"]: dep["exploit_intel"]["status"] for dep in report["dependencies"]}
    for package, expected_status in _EXPECTED_EXPLOIT_INTEL_STATUS.items():
        assert actual_exploit_intel[package] == expected_status
    # None of the curated demo CVEs are on CISA's KEV catalog.
    for dep in report["dependencies"]:
        if dep["exploit_intel"]["status"] == "ok":
            assert dep["exploit_intel"]["in_kev"] is False
            assert dep["exploit_intel"]["epss_score"] is not None

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


PYPI_EXPECTED_SEVERITIES = {
    "pyyaml": "Critical",
    "pillow": "Critical",
    "werkzeug": "High",
    "urllib3": "Medium",
    "jinja2": "Medium",
    "certifi": "Safe",
    "idna": "Safe",
    "charset-normalizer": "Safe",
    "six": "Safe",
}


def test_end_to_end_pypi_demo_pipeline_matches_documented_severities(demo_pypi_manifest_path, demo_cache_dir):
    """The PyPI counterpart to the npm end-to-end test above: same pipeline,
    same models, a requirements.txt manifest instead of package.json.
    """
    report = run_scan(demo_pypi_manifest_path, cache_dir=demo_cache_dir, offline=True)

    actual_severities = {dep["package"]: dep["severity"] for dep in report["dependencies"]}
    assert actual_severities == PYPI_EXPECTED_SEVERITIES

    assert all(dep["ecosystem"] == "pypi" for dep in report["dependencies"])

    # Every flagged dependency here has a real CVE, so exploit intelligence
    # should resolve for all of them, and none are on CISA's KEV catalog.
    for dep in report["dependencies"]:
        if dep["severity"] != "Safe":
            assert dep["exploit_intel"]["status"] == "ok"
            assert dep["exploit_intel"]["in_kev"] is False
            assert dep["cvss"]["cwes"], f"{dep['package']} should carry a CWE category"

    gate_result = evaluate_gate(report, ignore_file="does-not-exist.json")
    assert gate_result.exit_code != 0
    assert len(gate_result.failures) == 5  # pyyaml, pillow, werkzeug, urllib3, jinja2


def test_include_transitive_adds_lockfile_only_dependencies(demo_manifest_path, demo_cache_dir, tmp_path):
    """Scanning with include_transitive=True pulls in every package.json a
    package-lock.json resolves, not only the ones package.json itself names,
    and marks each one is_direct accordingly.
    """
    manifest_copy = tmp_path / "package.json"
    shutil.copy(demo_manifest_path, manifest_copy)
    shutil.copy(demo_manifest_path.parent / "package-lock.json", tmp_path / "package-lock.json")

    without_transitive = run_scan(manifest_copy, cache_dir=demo_cache_dir, offline=True)
    with_transitive = run_scan(manifest_copy, cache_dir=demo_cache_dir, offline=True, include_transitive=True)

    assert len(with_transitive["dependencies"]) > len(without_transitive["dependencies"])
    assert all(dep["is_direct"] for dep in without_transitive["dependencies"])

    direct = [dep for dep in with_transitive["dependencies"] if dep["is_direct"]]
    transitive = [dep for dep in with_transitive["dependencies"] if not dep["is_direct"]]
    assert len(direct) == len(without_transitive["dependencies"])
    assert len(transitive) > 0

    transitive_names = {dep["package"] for dep in transitive}
    direct_names = {dep["package"] for dep in direct}
    assert transitive_names.isdisjoint(direct_names)

    # A transitive-only dependency has no offline fixture coverage in this
    # test, so its lookup degrades gracefully instead of crashing the scan.
    assert all(dep["lookup_status"] == "lookup_failed" for dep in transitive)
