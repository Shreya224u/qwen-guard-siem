"""
Converts normalized log dicts into numeric feature vectors the ML models
can consume. Built as ONE vectorized array construction, not a per-row
loop that appends to a growing list — matters once batches are in the
thousands of rows.
"""
import numpy as np
from datetime import datetime
from typing import List, Dict, Any

SEVERITY_SCORE = {"critical": 95, "high": 75, "medium": 50, "low": 20}

# Fixed vocabulary — MUST stay identical between training and prediction,
# otherwise the same event_type could map to different numbers at each
# stage and the model's learned patterns become meaningless.
EVENT_TYPE_VOCAB = {
    "general": 0, "login": 1, "connection": 2,
    "brute_force": 3, "sql_injection": 4, "port_scan": 5,
    "ddos": 6, "malware": 7, "unauthorized_access": 8,
}


def encode_event_type(event_type: str) -> int:
    return EVENT_TYPE_VOCAB.get(event_type, 0)


def build_feature_matrix(rows: List[Dict[str, Any]]) -> np.ndarray:
    """
    Input: list of normalized log dicts (from normalization_service).
    Output: (N, 5) numpy array — [hour, severity_score, event_type_code,
    log_length, is_high_severity].
    """
    features = np.zeros((len(rows), 5), dtype=float)
    for i, row in enumerate(rows):
        ts = row.get("timestamp") or datetime.utcnow()
        hour = ts.hour if hasattr(ts, "hour") else 12
        severity = row.get("severity", "low")

        features[i, 0] = hour
        features[i, 1] = SEVERITY_SCORE.get(severity, 20)
        features[i, 2] = encode_event_type(row.get("event_type", "general"))
        features[i, 3] = len(row.get("raw_log", "") or "")
        features[i, 4] = 1.0 if severity in ("high", "critical") else 0.0
    return features
