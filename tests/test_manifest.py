import json

import pytest

from securechain.manifest import ManifestError, detect_ecosystem, find_lockfile, parse_lockfile, parse_manifest


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
    assert all(d.ecosystem == "npm" for d in deps)


def test_package_json_detected_as_npm_ecosystem(tmp_path):
    assert detect_ecosystem(tmp_path / "package.json") == "npm"


def test_requirements_txt_detected_as_pypi_ecosystem(tmp_path):
    assert detect_ecosystem(tmp_path / "requirements.txt") == "pypi"


def test_parses_requirements_txt_extracts_name_version_pairs(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "# a comment\n"
        "requests==2.31.0\n"
        "\n"
        "flask>=2.0.0\n"
        "django==4.1.0  ; python_version >= '3.8'\n"
        "-e git+https://example.com/some/editable/package\n"
        "just-a-bare-name-with-no-version\n"
    )

    deps = parse_manifest(manifest)
    by_name = {d.name: d.version for d in deps}

    assert by_name == {"requests": "2.31.0", "flask": "2.0.0", "django": "4.1.0"}
    assert all(d.ecosystem == "pypi" for d in deps)


def test_requirements_txt_skips_comments_and_blank_lines(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("# just a comment\n\n   \n")

    deps = parse_manifest(manifest)

    assert deps == []


def _write_lockfile(path, packages: dict):
    path.write_text(json.dumps({"name": "test", "lockfileVersion": 3, "packages": packages}))


def test_find_lockfile_returns_none_when_no_lockfile_present(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    assert find_lockfile(manifest) is None


def test_find_lockfile_finds_a_sibling_package_lock(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    assert find_lockfile(manifest) == tmp_path / "package-lock.json"


def test_find_lockfile_is_npm_only_not_requirements_txt(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("")
    (tmp_path / "package-lock.json").write_text("{}")
    assert find_lockfile(manifest) is None


def test_parse_lockfile_separates_direct_from_transitive(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile, {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/axios": {"version": "1.6.0"},
        "node_modules/follow-redirects": {"version": "1.15.4"},  # a real transitive dep of axios
    })

    deps = parse_lockfile(lockfile, direct_names={"axios"})
    by_name = {d.name: d for d in deps}

    assert by_name["axios"].is_direct is True
    assert by_name["follow-redirects"].is_direct is False


def test_parse_lockfile_handles_scoped_package_names(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile, {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/@babel/core": {"version": "7.24.0"},
    })

    deps = parse_lockfile(lockfile, direct_names=set())

    assert len(deps) == 1
    assert deps[0].name == "@babel/core"
    assert deps[0].is_direct is False


def test_parse_lockfile_skips_dev_and_optional_only_entries(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile, {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/jest": {"version": "29.0.0", "dev": True},
        "node_modules/fsevents": {"version": "2.3.3", "optional": True},
        "node_modules/lodash": {"version": "4.17.21"},
    })

    deps = parse_lockfile(lockfile, direct_names={"lodash"})

    assert {d.name for d in deps} == {"lodash"}


def test_parse_lockfile_degrades_gracefully_on_malformed_file(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{ not valid json")

    assert parse_lockfile(lockfile, direct_names=set()) == []


def test_parse_lockfile_degrades_gracefully_when_no_packages_key(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({"name": "demo", "lockfileVersion": 1}))

    assert parse_lockfile(lockfile, direct_names=set()) == []


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
