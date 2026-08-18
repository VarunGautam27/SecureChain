"""Random Forest classifier for the static-scan indicator feature space.

Same methodology as ml/classifier.py: trained on a documented synthetic
dataset (see ml/training_data.py's generate_static_scan_dataset), since no
real labeled corpus of malicious-vs-benign package indicator profiles
exists publicly. Outputs a risk score in [0, 1] (predicted probability of
the "malicious" class) over 4 features derived from the static scan:
category_count, has_install_hook, taint_chain_confirmed, files_scanned.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from securechain.ml.training_data import StaticScanDataset

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "static_classifier.joblib"


def train_static_classifier(
    dataset: StaticScanDataset, random_state: int = 42
) -> tuple[RandomForestClassifier, dict]:
    x_train, x_test, y_train, y_test = train_test_split(
        dataset.features,
        dataset.labels,
        test_size=0.2,
        random_state=random_state,
        stratify=dataset.labels,
    )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=6, random_state=random_state, class_weight="balanced"
    )
    model.fit(x_train, y_train)

    from sklearn.metrics import f1_score, precision_score, recall_score

    y_pred = model.predict(x_test)
    metrics = {
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }
    return model, metrics


def save_static_classifier(model: RandomForestClassifier, path: Path = DEFAULT_MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load_static_classifier(path: Path = DEFAULT_MODEL_PATH) -> RandomForestClassifier:
    if not Path(path).exists():
        raise FileNotFoundError(
            f"Static-scan classifier not found at {path}. Run scripts/train_models.py first."
        )
    return joblib.load(path)


def predict_static_risk(model: RandomForestClassifier, feature_vector: list[float]) -> float:
    proba = model.predict_proba(np.array([feature_vector]))[0]
    classes = list(model.classes_)
    risky_index = classes.index(1) if 1 in classes else int(np.argmax(classes))
    score = float(proba[risky_index])
    if np.isnan(score):
        return 0.0
    return min(max(score, 0.0), 1.0)
