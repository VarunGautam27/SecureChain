from securechain.gate import evaluate_gate
from securechain.pipeline import run_scan
from securechain.riskignore import accept_risk

# colors is Low purely from a behavioral anomaly (single maintainer, dormancy,
# irregular version jump - the real Jan 2022 colors/faker self-sabotage
# incident); there's no CVE and no fixed version, and pinning to an older
# version doesn't clear it either (the anomaly reflects the package's overall
# registry history, not the specific version pinned) - so accepting it is the
# only way to clear it short of removing the dependency entirely.
_UNFIXABLE = ("colors", "1.4.1")

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
    assert len(result.failures) == 11  # colors + the 10 fixable ones


def test_accepting_colors_still_leaves_the_10_fixable_ones_blocking(
    demo_manifest_path, demo_cache_dir, tmp_path
):
    report = run_scan(demo_manifest_path, cache_dir=demo_cache_dir, offline=True)

    ignore_file = tmp_path / ".riskignore.json"
    accept_risk(ignore_file, *_UNFIXABLE, "no fix possible, reviewed and accepted", "ayush", "2026-07-10")

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
    accept_risk(ignore_file, *_UNFIXABLE, "no fix possible, reviewed and accepted", "ayush", "2026-07-10")
    for package, version, _fixed in _FIXABLE:
        accept_risk(ignore_file, package, version, "accepted for demo", "ayush", "2026-07-10")

    result = evaluate_gate(report, ignore_file=str(ignore_file))

    assert result.exit_code == 0
    assert not result.failures
    assert len(result.warnings) == 11
