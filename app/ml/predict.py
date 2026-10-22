"""
Loads trained models once (module-level singletons) and predicts on
WHOLE BATCHES in a single call. This is the other half of the performance
fix: calling model.predict() inside a per-row Python loop is one of the
most common ways to accidentally turn a 2-second operation into minutes.
scikit-learn models are already vectorized internally — feed them the
whole matrix at once and let NumPy do the work.
"""
import os
import pickle
from typing import Tuple
import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

_iso_forest = None
_rf = None
_metrics = None


def _ensure_loaded():
    global _iso_forest, _rf, _metrics
    if _iso_forest is not None and _rf is not None:
        return

    iso_path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
    rf_path = os.path.join(MODEL_DIR, "random_forest.pkl")
    metrics_path = os.path.join(MODEL_DIR, "metrics.pkl")

    if not (os.path.exists(iso_path) and os.path.exists(rf_path)):
        from app.ml.train import train_models
        train_models()

    with open(iso_path, "rb") as f:
        _iso_forest = pickle.load(f)
    with open(rf_path, "rb") as f:
        _rf = pickle.load(f)
    if os.path.exists(metrics_path):
        with open(metrics_path, "rb") as f:
            _metrics = pickle.load(f)


def predict_batch(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    One call for the entire batch.
    Returns: (is_anomaly[bool array], predicted_class[int array], confidence[float array])
    """
    _ensure_loaded()

    iso_pred = _iso_forest.predict(X)  # -1 = anomaly, 1 = normal
    is_anomaly = iso_pred == -1

    rf_proba = _rf.predict_proba(X)
    predicted_class = np.argmax(rf_proba, axis=1)
    confidence = np.max(rf_proba, axis=1)

    return is_anomaly, predicted_class, confidence


def get_metrics() -> dict:
    _ensure_loaded()
    return _metrics or {}


def retrain() -> dict:
    global _iso_forest, _rf, _metrics
    from app.ml.train import train_models
    metrics = train_models()
    _iso_forest = None
    _rf = None
    _ensure_loaded()
    return metrics

if __name__ == "__main__":
    X = np.array([
        # Normal-looking event
        [10, 20, 0, 80, 0],
        # Suspicious-looking event
        [2, 95, 3, 180, 1],
    ], dtype=float)
    is_anomaly, predicted_class, confidence = predict_batch(X)
    print("Is anomaly:", is_anomaly)
    print("Predicted class:", predicted_class)
    print("Confidence:", confidence)