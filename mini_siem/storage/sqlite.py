"""Small, transactional SQLite store. No raw event timestamps are inferred."""

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3


SCHEMA_VERSION = 1
SCORE_CONVENTION = "sklearn.decision_function: negative=Anomaly; zero_or_positive=Normal"
SCHEMA = (
    """CREATE TABLE ingestion_batches (
        batch_id TEXT PRIMARY KEY CHECK(length(trim(batch_id)) > 0),
        source_sha256 TEXT NOT NULL,
        record_count INTEGER NOT NULL CHECK(record_count > 0),
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE security_events (
        event_id INTEGER PRIMARY KEY,
        batch_id TEXT NOT NULL REFERENCES ingestion_batches(batch_id),
        source_record INTEGER NOT NULL CHECK(source_record > 0),
        source_ip TEXT,
        event_type TEXT,
        occurred_at TEXT,
        ingested_at_utc TEXT NOT NULL,
        UNIQUE(batch_id, source_record)
    )""",
    """CREATE TABLE predictions (
        prediction_id INTEGER PRIMARY KEY,
        batch_id TEXT NOT NULL REFERENCES ingestion_batches(batch_id),
        model_id TEXT NOT NULL,
        source_record INTEGER NOT NULL CHECK(source_record > 0),
        source_ip TEXT NOT NULL,
        anomaly_label INTEGER NOT NULL CHECK(anomaly_label IN (-1, 1)),
        anomaly_status TEXT NOT NULL,
        anomaly_score REAL NOT NULL,
        score_convention TEXT NOT NULL,
        processed_at_utc TEXT NOT NULL,
        CHECK((anomaly_label = -1 AND anomaly_status = 'Anomaly') OR
              (anomaly_label = 1 AND anomaly_status = 'Normal')),
        CHECK((anomaly_label = -1 AND anomaly_score < 0) OR
              (anomaly_label = 1 AND anomaly_score >= 0)),
        UNIQUE(batch_id, model_id, source_record)
    )""",
    """CREATE TABLE alerts (
        alert_id INTEGER PRIMARY KEY,
        prediction_id INTEGER NOT NULL UNIQUE REFERENCES predictions(prediction_id),
        alert_type TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TRIGGER alerts_require_anomaly BEFORE INSERT ON alerts
        WHEN NOT EXISTS (SELECT 1 FROM predictions
                         WHERE prediction_id = NEW.prediction_id AND anomaly_label = -1)
        BEGIN SELECT RAISE(ABORT, 'Alerts require an anomaly prediction'); END""",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def verify_schema(connection):
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    expected = {"ingestion_batches", "security_events", "predictions", "alerts"}
    if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION or not expected <= tables:
        raise ValueError("Unsupported database schema; initialize a fresh database")


def connect_database(path):
    """Open an existing initialized database; never silently create on ingestion."""
    path = Path(path).resolve()
    connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        verify_schema(connection)
    except (ValueError, sqlite3.Error):
        connection.close()
        raise
    return connection


def initialize_database(path):
    path = Path(path)
    if path.exists() and path.stat().st_size == 0:
        raise ValueError("Refusing to overwrite an existing empty file; choose a new database path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path, timeout=30)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
                verify_schema(connection)
                return
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if version != 0 or tables:
                raise ValueError("Refusing to initialize an unrelated or unsupported database")
            for statement in SCHEMA:
                connection.execute(statement)
            connection.execute("PRAGMA user_version = 1")


def stored_statistics(path):
    with closing(connect_database(path)) as connection:
        with connection:
            connection.execute("BEGIN")
            # Table names below are fixed program constants, never user input.
            counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                      for table in ("ingestion_batches", "security_events", "predictions", "alerts")}
            counts.update(Normal=connection.execute("SELECT COUNT(*) FROM predictions WHERE anomaly_label = 1").fetchone()[0],
                          Anomaly=connection.execute("SELECT COUNT(*) FROM predictions WHERE anomaly_label = -1").fetchone()[0])
            return counts
