"""Synthetic training data generator.

No real labeled corpus of (CVSS + behavioral features) -> risk mappings exists
for this project, so both models are trained on a documented synthetic
dataset. This is a methodology limitation, called out in the README.

Sampling:
  cvss_score        - ~40% of samples have a CVE (uniform 0.1-10.0), the rest are 0 (no CVE).
  release_frequency_deviation - Gamma(shape=2.0, scale=0.5): a coefficient of
                                 variation (unitless, self-normalizing against a
                                 package's own typical release gap), so this
                                 stays on a comparable scale whether a package
                                 releases every few days or every few years.
  maintainer_count            - Poisson(lambda=2.5) + 1 (always >= 1).
  version_jump_irregularity   - Gamma(shape=2.0, scale=0.5): same coefficient-of-
                                 variation idea applied to consecutive weighted
                                 semver deltas.
  download_age_ratio          - Lognormal(mean=9.2, sigma=2.0) in ln-space (median ~10,000)
                                 - wide dynamic range so that both near-abandoned packages
                                 (ratio near 0) and very popular packages (tens of thousands
                                 of weekly downloads relative to their age) fall within the
                                 normal range; only genuine extremes at either tail are flagged.

Labeling rule (documented, deterministic):
  A sample is labeled "risky" (1) if cvss_score >= 4.0 OR at least 2 of the 4
  behavioral features are statistical outliers (|z-score| > 2 relative to the
  sampled behavioral distribution). This ties the supervised label to both a
  CVSS signal and a purely behavioral signal, mirroring the real engine's
  intent without requiring a numeric label from an external source.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from securechain.ml.features import ANOMALY_FEATURE_NAMES, CLASSIFIER_FEATURE_NAMES

RANDOM_STATE = 42


@dataclass
class SyntheticDataset:
    classifier_features: np.ndarray  # shape (n, 5): cvss + 4 behavioral
    classifier_labels: np.ndarray  # shape (n,)
    anomaly_features: np.ndarray  # shape (n, 4): behavioral only


def generate_synthetic_dataset(n_samples: int = 3000, random_state: int = RANDOM_STATE) -> SyntheticDataset:
    rng = np.random.default_rng(random_state)
    n = n_samples

    has_cve = rng.random(n) < 0.4
    cvss = np.where(has_cve, rng.uniform(0.1, 10.0, n), 0.0)

    release_freq_dev = rng.gamma(shape=2.0, scale=0.5, size=n)
    maintainer_count = rng.poisson(lam=2.5, size=n) + 1
    version_jump_irreg = rng.gamma(shape=2.0, scale=0.5, size=n)
    download_age_ratio = rng.lognormal(mean=9.2, sigma=2.0, size=n)

    behavioral = np.column_stack(
        [release_freq_dev, maintainer_count.astype(float), version_jump_irreg, download_age_ratio]
    )
    assert behavioral.shape[1] == len(ANOMALY_FEATURE_NAMES)

    z_scores = (behavioral - behavioral.mean(axis=0)) / (behavioral.std(axis=0) + 1e-9)
    outlier_count = (np.abs(z_scores) > 2).sum(axis=1)

    labels = ((cvss >= 4.0) | (outlier_count >= 2)).astype(int)

    classifier_features = np.column_stack([cvss, behavioral])
    assert classifier_features.shape[1] == len(CLASSIFIER_FEATURE_NAMES)

    return SyntheticDataset(
        classifier_features=classifier_features,
        classifier_labels=labels,
        anomaly_features=behavioral,
    )
