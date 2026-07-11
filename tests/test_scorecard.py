import requests

from securechain.scorecard import (
    CachedScorecardClient,
    ScorecardClient,
    extract_github_repo,
)
from tests.conftest import FakeResponse, FakeSession


def test_extract_github_repo_from_npm_style_metadata():
    metadata = {"repository": {"type": "git", "url": "git://github.com/lodash/lodash.git"}}
    assert extract_github_repo(metadata) == "lodash/lodash"


def test_extract_github_repo_from_normalized_pypi_style_metadata():
    metadata = {"repository": {"url": "https://github.com/psf/requests"}}
    assert extract_github_repo(metadata) == "psf/requests"


def test_extract_github_repo_returns_none_when_no_github_url_present():
    metadata = {"repository": {"url": "https://gitlab.com/someone/somewhere.git"}}
    assert extract_github_repo(metadata) is None


def test_extract_github_repo_returns_none_for_empty_metadata():
    assert extract_github_repo({}) is None


def test_scorecard_client_parses_score_and_top_checks():
    client = ScorecardClient()
    client.session = FakeSession(
        get_result=FakeResponse({
            "score": 8.2,
            "checks": [{"name": "Maintained", "score": 10}, {"name": "Code-Review", "score": 8}],
        })
    )

    result = client.lookup("psf/requests")

    assert result.status == "ok"
    assert result.score == 8.2
    assert result.checks == [{"name": "Maintained", "score": 10}, {"name": "Code-Review", "score": 8}]


def test_scorecard_client_maps_404_to_not_available():
    client = ScorecardClient()
    client.session = FakeSession(get_result=FakeResponse({}, status_code=404))
    result = client.lookup("someuser/never-scanned")
    assert result.status == "not_available"


def test_scorecard_client_degrades_gracefully_on_network_failure():
    client = ScorecardClient()
    client.session = FakeSession(get_result=requests.ConnectionError("simulated failure"))
    result = client.lookup("lodash/lodash")
    assert result.status == "lookup_failed"


def test_cached_client_returns_not_available_for_no_repo():
    client = CachedScorecardClient(cache_dir=None, offline=False)
    result = client.lookup(None)
    assert result.status == "not_available"


def test_cached_client_reads_cache_before_live_api(tmp_path):
    (tmp_path / "scorecard.json").write_text(
        '{"lodash/lodash": {"status": "ok", "score": 7.2, "checks": []}}'
    )
    client = CachedScorecardClient(cache_dir=tmp_path, offline=True)
    result = client.lookup("lodash/lodash")
    assert result.status == "ok"
    assert result.score == 7.2


def test_offline_mode_without_cache_entry_reports_lookup_failed(tmp_path):
    client = CachedScorecardClient(cache_dir=tmp_path, offline=True)
    result = client.lookup("someuser/somerepo")
    assert result.status == "lookup_failed"
