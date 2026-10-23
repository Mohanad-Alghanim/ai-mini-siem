"""Application logic turns model anomalies into durable alerts, never labels."""


def create_alert(connection, prediction_id, created_at_utc):
    """Insert at most one alert for an anomaly; retain existing alert history."""
    cursor = connection.execute(
        """INSERT INTO alerts (prediction_id, alert_type, created_at_utc)
           SELECT prediction_id, ?, ? FROM predictions
           WHERE prediction_id = ? AND anomaly_label = -1
           ON CONFLICT(prediction_id) DO NOTHING""",
        ("SSH behavioral anomaly", created_at_utc, prediction_id),
    )
    return cursor.rowcount
