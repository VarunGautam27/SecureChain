from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests

from securechain.ml import classifier as classifier_module
from securechain.ml import anomaly as anomaly_module
from securechain.ml.classifier import DEFAULT_MODEL_PATH as CLASSIFIER_PATH
from securechain.ml.anomaly import DEFAULT_MODEL_PATH as ANOMALY_PATH
from securechain.ml.training_data import generate_synthetic_dataset

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo"
DEMO_FIXTURES_DIR = DEMO_DIR / "fixtures"
TEST_FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BASELINE_METRICS_PATH = REPO_ROOT / "models" / "baseline_metrics.json"


class FakeResponse:
    """Minimal stand-in for requests.Response used to mock HTTP calls in tests."""

    def __init__(self, json_data, status_code: int = 200):
        self._json_data = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


class FakeSession:
    """A fake requests.Session whose get/post are set per-test to a callable or exception."""

    def __init__(self, get_result=None, post_result=None):
        self._get_result = get_result
        self._post_result = post_result

    def get(self, *args, **kwargs):
        if isinstance(self._get_result, Exception):
            raise self._get_result
        return self._get_result

    def post(self, *args, **kwargs):
        if isinstance(self._post_result, Exception):
            raise self._post_result
        return self._post_result


@pytest.fixture(scope="session", autouse=True)
def ensure_models_trained():
    """Trains and saves the classifier/anomaly models once per test session if they
    aren't already present on disk (e.g. a fresh checkout that hasn't run
    scripts/train_models.py yet), so the full test suite is runnable standalone.
    """
    if CLASSIFIER_PATH.exists() and ANOMALY_PATH.exists() and BASELINE_METRICS_PATH.exists():
        return

    dataset = generate_synthetic_dataset()
    model, metrics = classifier_module.train_classifier(dataset)
    classifier_module.save_classifier(model)

    anomaly_model = anomaly_module.train_anomaly_detector(dataset)
    anomaly_module.save_anomaly_detector(anomaly_model)

    BASELINE_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")


@pytest.fixture
def demo_manifest_path() -> Path:
    """A private, test-owned copy of the original 15-dependency vulnerable
    manifest (tests/fixtures/manifest.json) - deliberately NOT demo/package.json,
    since that file is meant to be edited by hand as part of the README's manual
    exercise. Tests must stay stable regardless of what state the user has left
    demo/package.json in.
    """
    return TEST_FIXTURES_DIR / "manifest.json"


@pytest.fixture
def demo_cache_dir() -> Path:
    return DEMO_FIXTURES_DIR
