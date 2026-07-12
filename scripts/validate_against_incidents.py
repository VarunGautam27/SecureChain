"""One-off retrospective validation: does the anomaly detector, trained only
on synthetic data, flag real historical npm supply-chain incidents?

Reuses the exact feature-computation functions from securechain.behavioral and
the exact trained model from models/anomaly.joblib - no retraining, no changed
thresholds. The only difference from a live scan: the release history fed
into the feature functions is truncated to versions published on or before
each incident's own publish date, so features reflect what the registry would
have shown on the day that version went live, not what it shows today.

Honest limitations, not hidden:
  - npm's registry API only reports *current* maintainers, not who they were
    at the time, so maintainer_count here is an approximation.
  - Historical weekly downloads are real (npm's downloads API supports
    arbitrary past date ranges), so download_age_ratio is not an
    approximation, aside from using a 7-day window starting at the incident
    date rather than the exact week the tool would have queried live.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import requests

from securechain.behavioral import (
    BehavioralFeatures,
    NpmRegistryClient,
    _NON_VERSION_TIME_KEYS,
    _parse_release_times,
    _release_frequency_deviation,
    _version_jump_irregularity,
)
from securechain.ml.anomaly import load_anomaly_detector, predict_anomaly_flag

NPM_DOWNLOADS_RANGE_URL = "https://api.npmjs.org/downloads/point"
REQUEST_TIMEOUT_SECONDS = 10

# (package, malicious/compromised version) - real, documented npm incidents.
INCIDENTS = [
    ("event-stream", "3.3.6"),   # 2018 flatmap-stream crypto-wallet backdoor
    ("ua-parser-js", "0.7.29"),  # 2021 hijacked-maintainer-account compromise
    ("ua-parser-js", "1.0.0"),   # same 2021 incident, second compromised version
]


def historical_downloads(package: str, start: datetime) -> int:
    end = start + timedelta(days=7)
    url = f"{NPM_DOWNLOADS_RANGE_URL}/{start.date()}:{end.date()}/{package}"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return int(response.json().get("downloads", 0))
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return 0


def evaluate(package: str, malicious_version: str, model) -> None:
    metadata = NpmRegistryClient().fetch(package)
    if metadata is None:
        print(f"{package}@{malicious_version}: could not fetch registry metadata, skipping")
        return

    time_map = metadata.get("time", {})
    if malicious_version not in time_map:
        print(f"{package}@{malicious_version}: version not found in registry history, skipping")
        return

    incident_date = datetime.fromisoformat(time_map[malicious_version].replace("Z", "+00:00"))

    # Only what the registry would have shown on the day this version went live.
    truncated = {
        key: value
        for key, value in time_map.items()
        if key in _NON_VERSION_TIME_KEYS
        or datetime.fromisoformat(value.replace("Z", "+00:00")) <= incident_date
    }

    created_raw = time_map.get("created")
    created = datetime.fromisoformat(created_raw.replace("Z", "+00:00")) if created_raw else None
    age_days = max((incident_date - created).total_seconds() / 86400, 1.0) if created else 1.0

    maintainers = metadata.get("maintainers", [])
    maintainer_count = len(maintainers) if isinstance(maintainers, list) else 0
    weekly_downloads = historical_downloads(package, incident_date)

    features = BehavioralFeatures(
        release_frequency_deviation=_release_frequency_deviation(_parse_release_times(truncated)),
        maintainer_count=maintainer_count,
        version_jump_irregularity=_version_jump_irregularity(truncated),
        download_age_ratio=weekly_downloads / age_days,
        status="ok",
    )

    flagged = predict_anomaly_flag(model, features.as_vector())

    print(f"\n{package}@{malicious_version}  (published {incident_date.date()})")
    print(f"  release_frequency_deviation : {features.release_frequency_deviation:.3f}")
    print(f"  maintainer_count (current)  : {features.maintainer_count}")
    print(f"  version_jump_irregularity   : {features.version_jump_irregularity:.3f}")
    print(f"  download_age_ratio          : {features.download_age_ratio:.3f}")
    print(f"  ANOMALY FLAGGED             : {'YES' if flagged else 'no'}")


def main() -> None:
    model = load_anomaly_detector()
    for package, version in INCIDENTS:
        evaluate(package, version, model)


if __name__ == "__main__":
    main()
