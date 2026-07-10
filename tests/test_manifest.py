import json

import pytest

from securechain.manifest import ManifestError, parse_manifest


def test_parses_valid_manifest_extracts_name_version_pairs(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({
        "name": "demo",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.21",
            "express": "^4.18.2",
            "minimist": "~1.2.0",
        },
    }))

    deps = parse_manifest(manifest)
    by_name = {d.name: d.version for d in deps}

    assert by_name == {"lodash": "4.17.21", "express": "4.18.2", "minimist": "1.2.0"}


def test_malformed_json_raises_clear_error(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{ this is not valid json ")

    with pytest.raises(ManifestError):
        parse_manifest(manifest)


def test_missing_file_raises_clear_error(tmp_path):
    with pytest.raises(ManifestError):
        parse_manifest(tmp_path / "does-not-exist.json")


def test_empty_manifest_file_raises_clear_error(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("")

    with pytest.raises(ManifestError):
        parse_manifest(manifest)


def test_zero_dependencies_returns_empty_list_without_error(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"name": "demo", "version": "1.0.0"}))

    deps = parse_manifest(manifest)

    assert deps == []
