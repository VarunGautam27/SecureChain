import json

import numpy as np

from securechain.ml.classifier import predict_risk_score, train_classifier
from securechain.ml.training_data import generate_synthetic_dataset
from tests.conftest import BASELINE_METRICS_PATH

REGRESSION_TOLERANCE = 0.05  # 5 points, per the spec's regression-test threshold


def test_classifier_reports_precision_recall_f1_on_held_out_set():
    dataset = generate_synthetic_dataset()
    _, metrics = train_classifier(dataset)

    for key in ("precision", "recall", "f1"):
        assert key in metrics
        assert 0.0 <= metrics[key] <= 1.0


def test_risk_score_is_always_a_valid_probability():
    dataset = generate_synthetic_dataset(n_samples=200, random_state=7)
    model, _ = train_classifier(dataset)

    for feature_vector in dataset.classifier_features:
        score = predict_risk_score(model, list(feature_vector))
        assert not np.isnan(score)
        assert 0.0 <= score <= 1.0


def test_classifier_regression_against_saved_baseline():
    dataset = generate_synthetic_dataset()
    _, new_metrics = train_classifier(dataset)

    baseline = json.loads(BASELINE_METRICS_PATH.read_text())

    for key in ("precision", "recall", "f1"):
        assert new_metrics[key] >= baseline[key] - REGRESSION_TOLERANCE, (
            f"{key} regressed: {new_metrics[key]:.3f} vs baseline {baseline[key]:.3f}"
        )
