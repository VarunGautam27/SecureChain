from securechain.gate import evaluate_gate
from securechain.pipeline import run_scan
from securechain.riskignore import accept_risk

# No CVE exists for any of these, and this test runs offline (a static scan
# is never performed offline, since it requires a real source download), so
# all 10 are genuinely Unverified - not silently "Safe" - and all 10 need
# either a real static scan (live mode) or an explicit accepted exception to
# clear the gate.
_UNVERIFIED = [
    ("lodash", "4.17.21"),
    ("chalk", "5.3.0"),
    ("uuid", "9.0.1"),
    ("debug", "4.3.4"),
    ("semver", "7.5.4"),
    ("commander", "11.1.0"),
    ("dotenv", "16.3.1"),
    ("yargs", "17.7.2"),
    ("picocolors", "1.0.0"),
    ("colors", "1.4.1"),
]

# minimist, axios, moment, xml2js, node-ipc, ansi-regex, glob-parent, json5,
# word-wrap, tar all have real fixed versions.
_FIXABLE = [
    ("minimist", "1.2.0", "1.2.6"),
    ("axios", "1.5.0", "1.6.0"),
    ("moment", "2.29.1", "2.29.4"),
    ("xml2js", "0.4.19", "0.5.0"),
    ("node-ipc", "9.2.1", "9.2.2"),
    ("ansi-regex", "5.0.0", "5.0.1"),
    ("glob-parent", "5.1.1", "5.1.2"),
    ("json5", "2.2.1", "2.2.2"),
    ("word-wrap", "1.2.3", "1.2.4"),
    ("tar", "6.1.0", "6.1.1"),
]


def test_demo_manifest_fails_the_gate_by_default(demo_manifest_path, demo_cache_dir):
    report = run_scan(demo_manifest_path, cache_dir=demo_cache_dir, offline=True)
    result = evaluate_gate(report, ignore_file="does-not-exist.json")
    assert result.exit_code != 0
    assert len(result.failures) == 20  # the 10 Unverified plus the 10 fixable ones


def test_accepting_unverified_ones_still_leaves_the_10_fixable_ones_blocking(
    demo_manifest_path, demo_cache_dir, tmp_path
):
    report = run_scan(demo_manifest_path, cache_dir=demo_cache_dir, offline=True)

    ignore_file = tmp_path / ".riskignore.json"
    for package, version in _UNVERIFIED:
        accept_risk(ignore_file, package, version, "no CVE found, accepted pending static scan", "ayush", "2026-07-10")

    result = evaluate_gate(report, ignore_file=str(ignore_file))

    assert result.exit_code != 0
    assert len(result.failures) == 10
    assert result.warnings
    assert any("colors" in w for w in result.warnings)


def test_accepting_everything_turns_a_failing_gate_into_all_warnings(
    demo_manifest_path, demo_cache_dir, tmp_path
):
    report = run_scan(demo_manifest_path, cache_dir=demo_cache_dir, offline=True)

    ignore_file = tmp_path / ".riskignore.json"
    for package, version in _UNVERIFIED:
        accept_risk(ignore_file, package, version, "no CVE found, accepted pending static scan", "ayush", "2026-07-10")
    for package, version, _fixed in _FIXABLE:
        accept_risk(ignore_file, package, version, "accepted for demo", "ayush", "2026-07-10")

    result = evaluate_gate(report, ignore_file=str(ignore_file))

    assert result.exit_code == 0
    assert not result.failures
    assert len(result.warnings) == 20
