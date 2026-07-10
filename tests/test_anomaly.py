import numpy as np

from securechain.ml.anomaly import predict_anomaly_flag, train_anomaly_detector
from securechain.ml.training_data import generate_synthetic_dataset


def test_obvious_outlier_is_flagged():
    dataset = generate_synthetic_dataset()
    model = train_anomaly_detector(dataset)

    # Extreme values on all 4 behavioral features, far beyond anything in training.
    extreme_vector = [5000.0, 50.0, 5_000_000.0, 500_000.0]

    assert predict_anomaly_flag(model, extreme_vector) is True


def test_false_positive_rate_stays_under_threshold_on_typical_data():
    dataset = generate_synthetic_dataset(n_samples=3000, random_state=99)
    model = train_anomaly_detector(dataset)

    # Fresh i.i.d. draws from the same "typical package" distribution used for training,
    # i.e. a sample with no deliberately injected outliers.
    eval_dataset = generate_synthetic_dataset(n_samples=2000, random_state=123)

    flags = [predict_anomaly_flag(model, list(v)) for v in eval_dataset.anomaly_features]
    false_positive_rate = sum(flags) / len(flags)

    # Model contamination is configured at 0.05; allow modest sampling tolerance.
    assert false_positive_rate <= 0.07


def test_predict_anomaly_flag_returns_boolean():
    dataset = generate_synthetic_dataset()
    model = train_anomaly_detector(dataset)
    result = predict_anomaly_flag(model, [10.0, 3.0, 100.0, 5.0])
    assert isinstance(result, bool)
