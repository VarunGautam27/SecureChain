import numpy as np

from securechain.ml.anomaly import train_anomaly_detector
from securechain.ml.classifier import predict_risk_score, train_classifier
from securechain.ml.explain import explain_anomaly, explain_classifier
from securechain.ml.training_data import generate_synthetic_dataset

TOLERANCE = 1e-3


def test_classifier_shap_values_sum_to_model_output():
    dataset = generate_synthetic_dataset(n_samples=300, random_state=1)
    model, _ = train_classifier(dataset)
    feature_vector = list(dataset.classifier_features[0])

    explanation = explain_classifier(model, feature_vector)
    actual_output = predict_risk_score(model, feature_vector)

    assert abs(explanation.model_output - actual_output) < TOLERANCE


def test_anomaly_shap_values_sum_to_model_output():
    dataset = generate_synthetic_dataset(n_samples=300, random_state=2)
    model = train_anomaly_detector(dataset)
    feature_vector = list(dataset.anomaly_features[0])

    explanation = explain_anomaly(model, feature_vector, anomaly_flagged=False)
    actual_output = float(model.score_samples(np.array([feature_vector]))[0])

    assert abs(explanation.model_output - actual_output) < TOLERANCE


def test_classifier_top_feature_matches_max_abs_shap_value():
    dataset = generate_synthetic_dataset(n_samples=300, random_state=3)
    model, _ = train_classifier(dataset)
    feature_vector = list(dataset.classifier_features[5])

    explanation = explain_classifier(model, feature_vector)
    expected_top = max(explanation.attributions, key=lambda a: abs(a.shap_value))

    assert explanation.top_feature == expected_top.feature


def test_anomaly_top_feature_matches_max_abs_shap_value():
    dataset = generate_synthetic_dataset(n_samples=300, random_state=4)
    model = train_anomaly_detector(dataset)
    feature_vector = list(dataset.anomaly_features[5])

    explanation = explain_anomaly(model, feature_vector, anomaly_flagged=False)
    expected_top = max(explanation.attributions, key=lambda a: abs(a.shap_value))

    assert explanation.top_feature == expected_top.feature
