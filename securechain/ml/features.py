"""Feature vector assembly shared by training and inference.

Keeping the feature name/order constants here guarantees the classifier
(5 features: CVSS + 4 behavioral), the anomaly detector (4 behavioral
features only), and SHAP's per-feature attribution all agree on ordering.
"""

from __future__ import annotations

from typing import Optional

from securechain.behavioral import BehavioralFeatures

CLASSIFIER_FEATURE_NAMES = [
    "cvss_score",
    "release_frequency_deviation",
    "maintainer_count",
    "version_jump_irregularity",
    "download_age_ratio",
]

ANOMALY_FEATURE_NAMES = [
    "release_frequency_deviation",
    "maintainer_count",
    "version_jump_irregularity",
    "download_age_ratio",
]

STATIC_SCAN_FEATURE_NAMES = [
    "category_count",
    "has_install_hook",
    "taint_chain_confirmed",
    "files_scanned",
]


def classifier_vector(cvss_score: Optional[float], behavioral: BehavioralFeatures) -> list[float]:
    return [cvss_score or 0.0, *behavioral.as_vector()]


def anomaly_vector(behavioral: BehavioralFeatures) -> list[float]:
    return behavioral.as_vector()


def static_scan_vector(
    category_count: int, has_install_hook: bool, taint_chain_confirmed: bool, files_scanned: int
) -> list[float]:
    return [float(category_count), float(has_install_hook), float(taint_chain_confirmed), float(files_scanned)]
