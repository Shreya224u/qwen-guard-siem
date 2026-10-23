from app.services import ml_service


def test_evaluate_batch_excludes_rule_detected_logs_before_prediction(monkeypatch):
    rule_detected = {"event_type": "sql_injection", "ip_address": "192.0.2.1"}
    candidate = {"event_type": "general", "ip_address": "192.0.2.2"}
    feature_rows = []

    def build_features(rows):
        feature_rows.extend(rows)
        return rows

    monkeypatch.setattr(ml_service, "build_feature_matrix", build_features)
    monkeypatch.setattr(
        ml_service.ml_predict,
        "predict_batch",
        lambda features: ([True], [0], [0.8]),
    )
    monkeypatch.setattr(
        ml_service.mitre_mapping_service,
        "get_db_id_for_event_type",
        lambda event_type: None,
    )

    alerts = ml_service.evaluate_batch(
        [rule_detected, candidate],
        [10, 11],
        skip_ids={10},
    )

    assert feature_rows == [candidate]
    assert len(alerts) == 1
    assert alerts[0]["log_id"] == 11
