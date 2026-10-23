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
    if not rows:
        return np.empty((0, 5), dtype=float)

    # Build each numeric column directly. This avoids Python's per-row,
    # per-feature writes for large uploads while preserving the model's
    # existing input values and column order.
    current_hour = datetime.utcnow().hour
    timestamps = (row.get("timestamp") for row in rows)
    features = np.empty((len(rows), 5), dtype=float)
    features[:, 0] = np.fromiter(
        (ts.hour if hasattr(ts, "hour") else current_hour if not ts else 12 for ts in timestamps),
        dtype=float,
        count=len(rows),
    )
    features[:, 1] = np.fromiter(
        (SEVERITY_SCORE.get(row.get("severity", "low"), 20) for row in rows),
        dtype=float,
        count=len(rows),
    )
    features[:, 2] = np.fromiter(
        (encode_event_type(row.get("event_type", "general")) for row in rows),
        dtype=float,
        count=len(rows),
    )
    features[:, 3] = np.fromiter(
        (len(row.get("raw_log", "") or "") for row in rows),
        dtype=float,
        count=len(rows),
    )
    features[:, 4] = np.fromiter(
        (1.0 if row.get("severity", "low") in ("high", "critical") else 0.0 for row in rows),
        dtype=float,
        count=len(rows),
    )
    return features
