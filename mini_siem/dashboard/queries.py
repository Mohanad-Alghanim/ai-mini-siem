"""Read-only, uncached snapshots of the existing TASK-004 database."""

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import math
import sqlite3

import pandas as pd

from mini_siem.storage.sqlite import SCORE_CONVENTION, verify_schema
from mini_siem.preprocessing.validation import valid_ip


class DashboardDataError(ValueError):
    """Safe user-facing error without SQL text, paths, or stored record values."""


MESSAGE = "Database unavailable or incompatible. Check the configured local database and its TASK-004 schema."
COLUMNS = {
    "ingestion_batches": {"batch_id", "source_sha256", "record_count", "created_at_utc"},
    "security_events": {"event_id", "batch_id", "source_record", "source_ip", "event_type", "occurred_at", "ingested_at_utc"},
    "predictions": {"prediction_id", "batch_id", "model_id", "source_record", "source_ip", "anomaly_label", "anomaly_status", "anomaly_score", "score_convention", "processed_at_utc"},
    "alerts": {"alert_id", "prediction_id", "alert_type", "created_at_utc"},
}


@contextmanager
def readonly_database(path):
    """Never create or migrate a database. Close the connection after each read."""
    connection = None
    try:
        resolved = Path(path).expanduser().resolve()
        connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        verify_schema(connection)
        for table, required in COLUMNS.items():
            # Names are fixed program constants, never query parameters.
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            if not required <= columns:
                raise ValueError("Missing schema columns")
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Database integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError("Broken relationships")
        # A malformed lookalike schema must not multiply alert join rows.
        for table, key in (("predictions", "prediction_id"), ("alerts", "alert_id"), ("alerts", "prediction_id")):
            if connection.execute(f"SELECT 1 FROM {table} GROUP BY {key} HAVING COUNT(*) > 1 LIMIT 1").fetchone():
                raise ValueError("Duplicate identifiers")
        if connection.execute("""SELECT 1 FROM alerts a LEFT JOIN predictions p
                                 ON p.prediction_id = a.prediction_id
                                 WHERE p.prediction_id IS NULL OR p.anomaly_label != -1 LIMIT 1""").fetchone():
            raise ValueError("Invalid alert relationship")
        yield connection
    except (OSError, ValueError, TypeError, sqlite3.Error, pd.errors.DatabaseError):
        raise DashboardDataError(MESSAGE) from None
    finally:
        if connection is not None:
            connection.close()


def where_filters(batch=None, model=None, status=None, source_ip=None):
    """All user values are bound parameters. SourceIP search is literal substring."""
    clauses, values = [], []
    for column, value in (("p.batch_id", batch), ("p.model_id", model), ("p.anomaly_status", status)):
        if value is not None:
            clauses.append(f"{column} = ?")
            values.append(value)
    if source_ip:
        clauses.append("instr(p.source_ip, ?) > 0")
        values.append(source_ip)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), values


def processing_dates(timestamps):
    """Only timezone-aware ISO timestamps support UTC processing-day counts."""
    days, skipped = [], 0
    for value in timestamps:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.utcoffset() is None:
                raise ValueError("Timestamp has no timezone")
            days.append(parsed.astimezone(timezone.utc).date().isoformat())
        except (ValueError, TypeError, OverflowError):
            skipped += 1
    counts = pd.Series(days, dtype="string").value_counts().sort_index()
    return pd.DataFrame({"Processing date (UTC)": counts.index, "Predictions": counts.values}), skipped


def read_snapshot(path, *, batch=None, model=None, status=None, source_ip=None):
    """Global KPIs/charts and filtered tables share a single read transaction."""
    with readonly_database(path) as connection:
        kpis = dict(zip(("Total Predictions", "Normal Predictions", "Anomaly Predictions"),
                        connection.execute("""SELECT COUNT(*),
                          COALESCE(SUM(anomaly_label = 1), 0),
                          COALESCE(SUM(anomaly_label = -1), 0) FROM predictions""").fetchone()))
        for label, table in (("Total Alerts", "alerts"), ("Total Batches", "ingestion_batches"), ("Raw Events Available", "security_events")):
            kpis[label] = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        options = pd.read_sql_query("SELECT DISTINCT batch_id, model_id FROM predictions ORDER BY batch_id, model_id", connection)
        where, values = where_filters(batch, model, status, source_ip)
        predictions = pd.read_sql_query("""SELECT p.prediction_id AS 'Prediction ID', p.source_ip AS SourceIP,
            p.anomaly_status AS AnomalyStatus, p.anomaly_score AS AnomalyScore,
            p.batch_id AS 'Batch ID', p.model_id AS 'Model ID',
            p.processed_at_utc AS 'Processing Timestamp (UTC)'
            FROM predictions p""" + where + " ORDER BY p.prediction_id DESC", connection, params=values)
        alert_where, alert_values = where_filters(batch, model, source_ip=source_ip)
        alerts = pd.read_sql_query("""SELECT a.alert_id AS 'Alert ID', p.source_ip AS SourceIP,
            a.alert_type AS 'Alert Type', p.anomaly_score AS 'Anomaly Score',
            p.model_id AS 'Model ID', p.batch_id AS 'Batch ID',
            p.processed_at_utc AS 'Processing Timestamp (UTC)', a.created_at_utc AS 'Alert Created (UTC)'
            FROM alerts a JOIN predictions p ON p.prediction_id = a.prediction_id""" + alert_where + " ORDER BY a.alert_id DESC", connection, params=alert_values)
        groups = pd.read_sql_query("""SELECT p.model_id AS 'Model ID', p.batch_id AS 'Batch ID', COUNT(*) AS Alerts
            FROM alerts a JOIN predictions p ON p.prediction_id = a.prediction_id
            GROUP BY p.model_id, p.batch_id ORDER BY p.model_id, p.batch_id""", connection)
        scores = pd.read_sql_query("SELECT model_id AS 'Model ID', anomaly_score AS AnomalyScore, anomaly_status AS AnomalyStatus FROM predictions", connection)
        for row in connection.execute("SELECT anomaly_label, anomaly_status, anomaly_score, score_convention, source_ip, model_id, batch_id FROM predictions"):
            label, status_value, score, convention, ip, model_id, batch_id = row
            if not isinstance(ip, str) or not valid_ip(ip) or not all(isinstance(value, str) and value.strip() for value in (model_id, batch_id)):
                raise ValueError("Invalid prediction identifiers")
            if label not in (-1, 1) or status_value != ("Anomaly" if label == -1 else "Normal"):
                raise ValueError("Invalid classification state")
            if not isinstance(score, (float, int)) or not math.isfinite(score) or (score < 0) != (label == -1) or convention != SCORE_CONVENTION:
                raise ValueError("Invalid score state")
        times = [row[0] for row in connection.execute("SELECT processed_at_utc FROM predictions")]
        conventions = [row[0] for row in connection.execute("SELECT DISTINCT score_convention FROM predictions ORDER BY score_convention")]
    dates, skipped = processing_dates(times)
    return {"kpis": kpis, "options": options, "predictions": predictions, "alerts": alerts,
            "alert_groups": groups, "scores": scores, "dates": dates,
            "skipped_timestamps": skipped, "score_conventions": conventions}
