"""
Trains Isolation Forest (anomaly detection) + Random Forest (classification).

IMPORTANT HONESTY NOTE:
If REAL_DATASET_PATH is not set or the file doesn't exist, this falls back
to synthetic data with cleanly-separated classes. A model trained on that
will report 95-99% accuracy easily — that number reflects how artificially
separable the fake data is, NOT real detection skill. Don't quote it as
a real result. To get a metric worth putting on a resume, point
REAL_DATASET_PATH at a prepared extract of a real dataset (CICIDS2017,
UNSW-NB15, etc.) with the same 5 feature columns + a label column.
"""
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from app.ml.feature_engineering import EVENT_TYPE_VOCAB

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

# Set this env var to a CSV path to train on real data instead of synthetic.
REAL_DATASET_PATH = os.environ.get("REAL_DATASET_PATH", "")

LABELS = ["Normal", "brute_force", "ddos", "sql_injection", "port_scan"]


def _synthetic_dataset(n: int = 4000):
    rng = np.random.default_rng(42)
    rows = []
    per_class = n // len(LABELS)
    for label_idx, label in enumerate(LABELS):
        for _ in range(per_class):
            if label == "Normal":
                hour = rng.integers(8, 18)
                sev = rng.choice([20, 50])
                event_enc = rng.choice([0, 1, 2])
                length = rng.integers(40, 120)
                high_sev = 0
            else:
                hour = rng.integers(0, 24)
                sev = rng.choice([75, 95])
                event_enc = EVENT_TYPE_VOCAB.get(label, 3)
                length = rng.integers(60, 200)
                high_sev = 1
            rows.append([hour, sev, event_enc, length, high_sev, label_idx])
    arr = np.array(rows, dtype=float)
    return arr[:, :5], arr[:, 5].astype(int)


def _load_real_dataset(path: str):
    """Expects columns: hour, severity_score, event_encoded, log_length, is_high_severity, label"""
    df = pd.read_csv(path)
    X = df[["hour", "severity_score", "event_encoded", "log_length", "is_high_severity"]].values
    y = df["label"].values
    return X, y


def train_models() -> dict:
    if REAL_DATASET_PATH and os.path.exists(REAL_DATASET_PATH):
        X, y = _load_real_dataset(REAL_DATASET_PATH)
        data_source = "real"
    else:
        X, y = _synthetic_dataset()
        data_source = "synthetic"

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    iso_forest = IsolationForest(contamination=0.25, random_state=42)
    iso_forest.fit(X_train)

    rf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42)
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "data_source": data_source,
        "training_rows": int(len(X_train)),
    }

    with open(os.path.join(MODEL_DIR, "isolation_forest.pkl"), "wb") as f:
        pickle.dump(iso_forest, f)
    with open(os.path.join(MODEL_DIR, "random_forest.pkl"), "wb") as f:
        pickle.dump(rf, f)
    with open(os.path.join(MODEL_DIR, "metrics.pkl"), "wb") as f:
        pickle.dump(metrics, f)

    return metrics


if __name__ == "__main__":
    print(train_models())
