from securechain.behavioral import CachedBehavioralClient, compute_behavioral_features


class _FakeBehavioralClient(CachedBehavioralClient):
    def __init__(self, metadata: dict, downloads: int):
        self._metadata = metadata
        self._downloads = downloads

    def fetch_metadata(self, package: str):
        return self._metadata

    def fetch_downloads(self, package: str):
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
