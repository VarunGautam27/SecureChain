import json

from securechain.gate import evaluate_gate
from securechain.riskignore import accept_risk, is_accepted, load_riskignore


def test_accept_writes_entry_with_all_fields(tmp_path):
    ignore_file = tmp_path / ".riskignore.json"

    accept_risk(
        ignore_file=ignore_file,
        package="xml2js",
        version="0.4.19",
        reason="Accepted pending upstream upgrade",
        accepted_by="ayush",
        accepted_date="2026-07-09",
    )

    store = json.loads(ignore_file.read_text())
    assert len(store["exceptions"]) == 1
    entry = store["exceptions"][0]
    assert entry == {
        "package": "xml2js",
        "version": "0.4.19",
        "reason": "Accepted pending upstream upgrade",
        "date": "2026-07-09",
        "accepted_by": "ayush",
    }


def test_accept_upserts_existing_entry_for_same_package_version(tmp_path):
    ignore_file = tmp_path / ".riskignore.json"
    accept_risk(ignore_file, "xml2js", "0.4.19", "first reason", "ayush", "2026-01-01")
    accept_risk(ignore_file, "xml2js", "0.4.19", "updated reason", "ayush", "2026-07-09")

    store = load_riskignore(ignore_file)
    assert len(store["exceptions"]) == 1
    assert store["exceptions"][0]["reason"] == "updated reason"


def _fake_report(package, version, severity):
    return {
        "dependencies": [
            {"package": package, "version": version, "severity": severity}
        ]
    }


def test_check_passes_when_dependency_is_accepted(tmp_path):
    ignore_file = tmp_path / ".riskignore.json"
    accept_risk(ignore_file, "xml2js", "0.4.19", "accepted", "ayush", "2026-07-09")

    report = _fake_report("xml2js", "0.4.19", "Critical")
    result = evaluate_gate(report, max_severity="safe", ignore_file=str(ignore_file))

    assert result.exit_code == 0
    assert result.warnings


def test_check_fails_when_dependency_is_not_accepted(tmp_path):
    ignore_file = tmp_path / ".riskignore.json"
    ignore_file.write_text(json.dumps({"exceptions": []}))

    report = _fake_report("xml2js", "0.4.19", "Critical")
    result = evaluate_gate(report, max_severity="safe", ignore_file=str(ignore_file))

    assert result.exit_code != 0
    assert result.failures


def test_exception_is_version_specific_not_covering_upgraded_vulnerable_version(tmp_path):
    ignore_file = tmp_path / ".riskignore.json"
    accept_risk(ignore_file, "xml2js", "0.4.19", "accepted old version", "ayush", "2026-07-09")

    # Package upgraded to a *different* still-vulnerable version - old exception must not apply.
    report = _fake_report("xml2js", "0.4.20", "Critical")
    result = evaluate_gate(report, max_severity="safe", ignore_file=str(ignore_file))

    assert result.exit_code != 0
    store = load_riskignore(ignore_file)
    assert is_accepted(store, "xml2js", "0.4.20") is None
