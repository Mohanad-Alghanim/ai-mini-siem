"""Validate and infer locally, then atomically store an entire feature batch."""

from contextlib import closing
import hashlib
from io import BytesIO
from pathlib import Path
import tempfile

from mini_siem.alerts.management import create_alert
from mini_siem.ml.features import load_features
from mini_siem.ml.model import load_model, predict_records
from mini_siem.storage.sqlite import SCORE_CONVENTION, connect_database, utc_now


def ingest_features(database, csv_path, model_path, batch_id, *, trusted=False):
    """An explicit batch ID is bound to exact CSV bytes, not to a filename.

    Model identity is SHA-256 of the exact loaded artifact bytes. Source records
    are one-based CSV data-record positions (not physical lines or SourceIP).
    Identical rows at different positions remain separate observations.
    """
    if not trusted:
        raise ValueError("Only explicitly trusted local model artifacts may be loaded")
    if not isinstance(batch_id, str) or not batch_id.strip():
        raise ValueError("A nonblank batch_id is required")
    database_path = Path(database).resolve()
    if database_path in (Path(csv_path).resolve(), Path(model_path).resolve()):
        raise ValueError("Database path must differ from input and model paths")
    source_bytes = Path(csv_path).read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    # Validate an exact snapshot with the existing loader. The private temporary
    # file is removed before inference; originals are never opened for writing.
    with tempfile.TemporaryDirectory(prefix="mini-siem-features-") as folder:
        snapshot = Path(folder) / "features.csv"
        snapshot.write_bytes(source_bytes)
        frame = load_features(snapshot)
    model_bytes = Path(model_path).read_bytes()
    model_id = "sha256:" + hashlib.sha256(model_bytes).hexdigest()
    model = load_model(BytesIO(model_bytes), trusted=True)
    results = predict_records(model, frame)  # no fit or retraining
    processed_at = utc_now()
    inserted_predictions = inserted_alerts = 0
    with closing(connect_database(database)) as connection:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            batch = connection.execute("SELECT source_sha256, record_count FROM ingestion_batches WHERE batch_id = ?", (batch_id,)).fetchone()
            if batch is not None and (batch["source_sha256"] != source_hash or batch["record_count"] != len(results)):
                raise ValueError("Batch ID is already bound to different source content")
            connection.execute(
                """INSERT INTO ingestion_batches (batch_id, source_sha256, record_count, created_at_utc)
                   VALUES (?, ?, ?, ?) ON CONFLICT(batch_id) DO NOTHING""",
                (batch_id, source_hash, len(results), processed_at),
            )
            for record, row in enumerate(results.itertuples(index=False), start=1):
                cursor = connection.execute(
                    """INSERT INTO predictions
                       (batch_id, model_id, source_record, source_ip, anomaly_label,
                        anomaly_status, anomaly_score, score_convention, processed_at_utc)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(batch_id, model_id, source_record) DO NOTHING""",
                    (batch_id, model_id, record, row.SourceIP, int(row.AnomalyLabel),
                     row.AnomalyStatus, float(row.AnomalyScore), SCORE_CONVENTION, processed_at),
                )
                inserted_predictions += cursor.rowcount
                prediction_id = connection.execute(
                    "SELECT prediction_id FROM predictions WHERE batch_id = ? AND model_id = ? AND source_record = ?",
                    (batch_id, model_id, record),
                ).fetchone()[0]
                inserted_alerts += create_alert(connection, prediction_id, processed_at)
    return {"batch_id": batch_id, "model_id": model_id, "records": len(results),
            "Normal": int(results.AnomalyLabel.eq(1).sum()),
            "Anomaly": int(results.AnomalyLabel.eq(-1).sum()),
            "inserted_predictions": inserted_predictions, "inserted_alerts": inserted_alerts}
