"""SHAP explainability wrappers for the classifier and anomaly detector.

Produces per-feature attributions for both models plus a short plain-sentence
explanation built from the top contributing feature(s). Explanations are
written as plain sentences (no em-dashes or hyphens used as separators).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import shap

from securechain.ml.features import ANOMALY_FEATURE_NAMES, CLASSIFIER_FEATURE_NAMES


@dataclass
class FeatureAttribution:
    feature: str
    value: float
    shap_value: float

    def to_dict(self) -> dict:
        return {"feature": self.feature, "value": self.value, "shap_value": self.shap_value}


@dataclass
class ExplanationResult:
    attributions: list[FeatureAttribution]
    base_value: float
    model_output: float
    top_feature: str
    explanation_text: str

    def to_dict(self) -> dict:
        return {
            "attributions": [a.to_dict() for a in self.attributions],
            "base_value": self.base_value,
            "model_output": self.model_output,
            "top_feature": self.top_feature,
            "explanation_text": self.explanation_text,
        }


def _extract_positive_class_shap(raw_shap_output, expected_value) -> tuple[np.ndarray, float]:
    """Normalizes SHAP's classifier output across SHAP versions to a single 1D vector
    (attributions for the positive/"risky" class for sample 0) plus its base value.
    """
    if isinstance(raw_shap_output, list):
        values = np.array(raw_shap_output[-1][0])
        base = expected_value[-1] if isinstance(expected_value, (list, np.ndarray)) else expected_value
        return values, float(base)

    arr = np.array(raw_shap_output)
    if arr.ndim == 3:
        values = arr[0, :, -1]
        base = expected_value[-1] if isinstance(expected_value, (list, np.ndarray)) else expected_value
        return values, float(base)
    if arr.ndim == 2:
        base = expected_value[0] if isinstance(expected_value, (list, np.ndarray)) else expected_value
        return arr[0], float(base)
    return arr, float(expected_value)


_PHRASES = {
    "cvss_score": {
        "risk": "a CVE with a CVSS score of {value:.1f}",
        "safe": "the absence of a significant CVE",
    },
    "release_frequency_deviation": {
        "risk": "an unusual release spike",
        "safe": "a steady release cadence",
    },
    "version_jump_irregularity": {
        "risk": "an irregular version jump between releases",
        "safe": "consistent version increments",
    },
    "download_age_ratio": {
        "risk": "an unusual download to age ratio",
        "safe": "a typical download to age ratio for its age",
    },
}


def _feature_phrase(feature: str, value: float, shap_value: float, invert: bool = False) -> str:
    is_risk_direction = (shap_value < 0) if invert else (shap_value > 0)
    if feature == "maintainer_count":
        if is_risk_direction:
            if value <= 1:
                return "a single maintainer"
            return f"a small maintainer pool of {int(value)} maintainers"
        return f"a healthy maintainer pool of {int(value)} maintainers"

    templates = _PHRASES[feature]
    template = templates["risk"] if is_risk_direction else templates["safe"]
    return template.format(value=value)


def _build_explanation_text(attributions: list[FeatureAttribution], flagged: bool, invert: bool = False) -> str:
    ranked = sorted(attributions, key=lambda a: abs(a.shap_value), reverse=True)
    top = ranked[:2]
    phrases = [_feature_phrase(a.feature, a.value, a.shap_value, invert=invert) for a in top]

    if not phrases:
        return "No significant risk factors identified."

    joined = " and ".join(phrases)
    if flagged:
        return f"Flagged due to {joined}."
    return f"Not flagged. Primary contributing factors were {joined}."


def explain_classifier(model, feature_vector: list[float]) -> ExplanationResult:
    explainer = shap.TreeExplainer(model)
    raw_values = explainer.shap_values(np.array([feature_vector]))
    values, base_value = _extract_positive_class_shap(raw_values, explainer.expected_value)

    attributions = [
        FeatureAttribution(feature=name, value=float(val), shap_value=float(sv))
        for name, val, sv in zip(CLASSIFIER_FEATURE_NAMES, feature_vector, values)
    ]
    model_output = base_value + float(np.sum(values))
    top = max(attributions, key=lambda a: abs(a.shap_value))
    predicted_risky = model_output >= 0.5
    text = _build_explanation_text(attributions, flagged=predicted_risky)

    return ExplanationResult(
        attributions=attributions,
        base_value=base_value,
        model_output=model_output,
        top_feature=top.feature,
        explanation_text=text,
    )


def explain_anomaly(model, feature_vector: list[float], anomaly_flagged: bool) -> ExplanationResult:
    background = np.zeros((1, len(feature_vector)))
    try:
        explainer = shap.TreeExplainer(model)
        raw_values = explainer.shap_values(np.array([feature_vector]))
        values = np.array(raw_values)
        if values.ndim == 2:
            values = values[0]
        base_value = explainer.expected_value
        if isinstance(base_value, (list, np.ndarray)):
            base_value = base_value[0]
        base_value = float(base_value)
    except Exception:
        explainer = shap.KernelExplainer(lambda x: model.score_samples(x), background)
        raw_values = explainer.shap_values(np.array([feature_vector]), silent=True)
        values = np.array(raw_values)
        if values.ndim == 2:
            values = values[0]
        base_value = float(explainer.expected_value[0] if isinstance(explainer.expected_value, (list, np.ndarray)) else explainer.expected_value)

    attributions = [
        FeatureAttribution(feature=name, value=float(val), shap_value=float(sv))
        for name, val, sv in zip(ANOMALY_FEATURE_NAMES, feature_vector, values)
    ]
    model_output = base_value + float(np.sum(values))
    top = max(attributions, key=lambda a: abs(a.shap_value))
    # Isolation Forest's score_samples output is higher for "more normal" points, so a
    # *negative* SHAP contribution is what pushes a dependency toward being anomalous -
    # the opposite convention from the classifier, where higher output means more risky.
    text = _build_explanation_text(attributions, flagged=anomaly_flagged, invert=True)

    return ExplanationResult(
        attributions=attributions,
        base_value=base_value,
        model_output=model_output,
        top_feature=top.feature,
        explanation_text=text,
    )
