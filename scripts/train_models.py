"""Regenerates the synthetic training dataset, trains both models, and saves them.

Run with: python scripts/train_models.py

Writes:
  models/classifier.joblib
  models/anomaly.joblib
  models/baseline_metrics.json   (precision/recall/F1 on the held-out split;
                                   test_classifier.py asserts future retrains
                                   don't regress more than 5 points against this file)
"""

from __future__ import annotations

import json
from pathlib import Path

from securechain.ml.anomaly import save_anomaly_detector, train_anomaly_detector
from securechain.ml.classifier import save_classifier, train_classifier
from securechain.ml.training_data import generate_synthetic_dataset

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
BASELINE_METRICS_PATH = MODELS_DIR / "baseline_metrics.json"


def main() -> None:
    dataset = generate_synthetic_dataset()

    classifier, metrics = train_classifier(dataset)
    save_classifier(classifier)
    print(f"Classifier trained: precision={metrics['precision']:.3f} "
          f"recall={metrics['recall']:.3f} f1={metrics['f1']:.3f}")

    anomaly_model = train_anomaly_detector(dataset)
    save_anomaly_detector(anomaly_model)
    print("Isolation Forest anomaly detector trained.")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(f"Baseline metrics written to {BASELINE_METRICS_PATH}")


if __name__ == "__main__":
    main()
