"""Isolation Forest behavioral anomaly detector.

Trained only on the 4 behavioral features (release frequency deviation,
maintainer count, version jump irregularity, download/age ratio) so it can
flag statistically unusual dependencies independent of whether a CVE exists.

The 4 features live on very different natural scales (a 0-3ish coefficient of
variation next to a maintainer count of 1-10 next to a download/age ratio that
can run into the tens of thousands). Isolation Forest partitions by picking a
random split point within each feature's observed range, so leaving the raw
scales in place lets whichever feature has the widest range dominate the
isolation depth. A StandardScaler step in front of the forest normalizes that
away; the whole thing is saved and used as a single scikit-learn Pipeline.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from securechain.ml.training_data import SyntheticDataset

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "anomaly.joblib"

CONTAMINATION = 0.05


def train_anomaly_detector(dataset: SyntheticDataset, random_state: int = 42) -> Pipeline:
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=200,
            contamination=CONTAMINATION,
            random_state=random_state,
        )),
    ])
    model.fit(dataset.anomaly_features)
    return model


def save_anomaly_detector(model: Pipeline, path: Path = DEFAULT_MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load_anomaly_detector(path: Path = DEFAULT_MODEL_PATH) -> Pipeline:
    if not Path(path).exists():
        raise FileNotFoundError(
            f"Anomaly model not found at {path}. Run scripts/train_models.py first."
        )
    return joblib.load(path)


def predict_anomaly_flag(model: Pipeline, feature_vector: list[float]) -> bool:
    prediction = model.predict(np.array([feature_vector]))[0]
    return bool(prediction == -1)
