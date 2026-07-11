from securechain.behavioral import CachedBehavioralClient, compute_behavioral_features, normalize_pypi_metadata


class _FakeBehavioralClient(CachedBehavioralClient):
    def __init__(self, metadata: dict, downloads: int):
        self._metadata = metadata
        self._downloads = downloads

    def fetch_metadata(self, package: str, ecosystem: str = "npm"):
        return self._metadata

    def fetch_downloads(self, package: str, ecosystem: str = "npm"):
        return self._downloads


def test_release_frequency_deviation_higher_for_spiky_history():
    even_map = {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.0.1": "2020-02-01T00:00:00.000Z",
        "1.0.2": "2020-03-02T00:00:00.000Z",
        "1.0.3": "2020-04-01T00:00:00.000Z",
        "1.0.4": "2020-05-01T00:00:00.000Z",
    }
    spiky_map = {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.0.1": "2020-01-31T00:00:00.000Z",
        "1.0.2": "2020-03-01T00:00:00.000Z",
        "1.0.3": "2023-06-01T00:00:00.000Z",
        "1.0.4": "2023-06-05T00:00:00.000Z",
    }

    even_client = _FakeBehavioralClient({"time": even_map, "maintainers": [{"name": "a"}]}, downloads=1000)
    spiky_client = _FakeBehavioralClient({"time": spiky_map, "maintainers": [{"name": "a"}]}, downloads=1000)

    even_features = compute_behavioral_features("pkg", even_client)
    spiky_features = compute_behavioral_features("pkg", spiky_client)

    assert spiky_features.release_frequency_deviation > even_features.release_frequency_deviation


def test_maintainer_count_extracted_from_registry_metadata():
    client = _FakeBehavioralClient(
        {
            "time": {"created": "2020-01-01T00:00:00.000Z", "1.0.0": "2020-01-01T00:00:00.000Z"},
            "maintainers": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
        },
        downloads=500,
    )

    features = compute_behavioral_features("pkg", client)

    assert features.maintainer_count == 3


def test_version_jump_irregularity_detects_irregular_jump():
    regular_map = {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.0.1": "2020-02-01T00:00:00.000Z",
        "1.0.2": "2020-03-01T00:00:00.000Z",
        "1.0.3": "2020-04-01T00:00:00.000Z",
        "1.0.4": "2020-05-01T00:00:00.000Z",
    }
    irregular_map = {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.0.1": "2020-02-01T00:00:00.000Z",
        "9.0.0": "2020-03-01T00:00:00.000Z",  # deliberate irregular jump
        "1.0.3": "2020-04-01T00:00:00.000Z",
        "1.0.4": "2020-05-01T00:00:00.000Z",
    }

    regular_client = _FakeBehavioralClient({"time": regular_map, "maintainers": [{"name": "a"}]}, downloads=1000)
    irregular_client = _FakeBehavioralClient({"time": irregular_map, "maintainers": [{"name": "a"}]}, downloads=1000)

    regular_features = compute_behavioral_features("pkg", regular_client)
    irregular_features = compute_behavioral_features("pkg", irregular_client)

    assert irregular_features.version_jump_irregularity > regular_features.version_jump_irregularity


def test_download_age_ratio_calculation():
    from datetime import datetime, timedelta, timezone

    created = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat().replace("+00:00", "Z")
    client = _FakeBehavioralClient(
        {"time": {"created": created, "1.0.0": created}, "maintainers": [{"name": "a"}]},
        downloads=1000,
    )

    features = compute_behavioral_features("pkg", client)

    assert abs(features.download_age_ratio - 10.0) < 0.5


def test_failed_metadata_fetch_returns_failed_status():
    client = _FakeBehavioralClient(metadata=None, downloads=None)
    features = compute_behavioral_features("pkg", client)
    assert features.status == "lookup_failed"


def test_normalize_pypi_metadata_deduplicates_same_person_in_both_email_fields():
    raw = {
        "info": {
            "author_email": '"Ahmed R. TAHRI" <tahri.ahmed@proton.me>',
            "maintainer_email": '"Ahmed R. TAHRI" <tahri.ahmed@proton.me>',
        },
        "releases": {},
    }
    normalized = normalize_pypi_metadata(raw)
    assert len(normalized["maintainers"]) == 1


def test_normalize_pypi_metadata_counts_distinct_people_across_both_fields():
    raw = {
        "info": {
            "author_email": "Andrey Petrov <andrey@example.com>",
            "maintainer_email": "Seth Larson <seth@example.com>, Quentin Pradet <quentin@example.com>",
        },
        "releases": {},
    }
    normalized = normalize_pypi_metadata(raw)
    assert len(normalized["maintainers"]) == 3


def test_normalize_pypi_metadata_falls_back_to_unknown_when_nothing_parseable():
    raw = {"info": {"author_email": None, "maintainer_email": None}, "releases": {}}
    normalized = normalize_pypi_metadata(raw)
    assert normalized["maintainers"] == [{"name": "unknown"}]


def test_normalize_pypi_metadata_builds_time_map_from_releases():
    raw = {
        "info": {"author_email": "a@example.com", "maintainer_email": None},
        "releases": {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "1.1.0": [{"upload_time_iso_8601": "2021-06-01T00:00:00.000000Z"}],
            "2.0.0": [],  # a yanked/fileless release, should be skipped, not crash
        },
    }
    normalized = normalize_pypi_metadata(raw)
    assert normalized["time"]["1.0.0"] == "2020-01-01T00:00:00.000000Z"
    assert normalized["time"]["created"] == "2020-01-01T00:00:00.000000Z"
    assert normalized["time"]["modified"] == "2021-06-01T00:00:00.000000Z"
    assert "2.0.0" not in normalized["time"]
