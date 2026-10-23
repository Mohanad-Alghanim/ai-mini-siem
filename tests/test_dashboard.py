"""Temporary synthetic SQL records only; dashboard never creates demo data."""

from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3

import pytest
from streamlit.testing.v1 import AppTest

from mini_siem.dashboard.charts import alerts_by_source, prediction_distribution, processing_counts, score_distribution
from mini_siem.dashboard.queries import DashboardDataError, processing_dates, read_snapshot, readonly_database
from mini_siem.storage.sqlite import SCORE_CONVENTION, initialize_database


APP = Path(__file__).resolve().parents[1] / "mini_siem/dashboard/app.py"


@pytest.fixture
def database(tmp_path):
    path = tmp_path / "synthetic.db"
    initialize_database(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        for batch in ("batch-a", "batch-b"):
            connection.execute("INSERT INTO ingestion_batches VALUES (?, ?, ?, ?)", (batch, "synthetic-hash", 2, "2026-01-01T12:00:00+00:00"))
        for i, (batch, model, label, score, timestamp) in enumerate([
            ("batch-a", "model-a", 1, .2, "2026-01-01T12:00:00+00:00"),
            ("batch-a", "model-a", -1, -.1, "2026-01-01T13:00:00+00:00"),
            ("batch-b", "model-b", -1, -.2, "2026-01-02T12:00:00+00:00"),
            ("batch-b", "model-b", 1, .1, "2026-01-02T13:00:00+00:00"),
        ], 1):
            connection.execute("""INSERT INTO predictions
                (prediction_id,batch_id,model_id,source_record,source_ip,anomaly_label,anomaly_status,anomaly_score,score_convention,processed_at_utc)
                VALUES (?,?,?,?,?,?,?,?,?,?)""", (i, batch, model, i, f"192.0.2.{i}", label, "Anomaly" if label == -1 else "Normal", score, SCORE_CONVENTION, timestamp))
            if label == -1:
                connection.execute("INSERT INTO alerts (prediction_id,alert_type,created_at_utc) VALUES (?,?,?)", (i, "SSH behavioral anomaly", timestamp))
    return path


def test_kpis_and_alert_joins(database):
    snapshot = read_snapshot(database)
    assert snapshot["kpis"] == {"Total Predictions": 4, "Normal Predictions": 2, "Anomaly Predictions": 2, "Total Alerts": 2, "Total Batches": 2, "Raw Events Available": 0}
    assert snapshot["alerts"].SourceIP.tolist() == ["192.0.2.3", "192.0.2.2"]
    assert {"Alert ID", "SourceIP", "Alert Type", "Anomaly Score", "Model ID", "Batch ID", "Processing Timestamp (UTC)"} <= set(snapshot["alerts"])
    assert len(snapshot["alerts"]) == snapshot["alerts"]["Alert ID"].nunique()
    assert snapshot["alert_groups"].Alerts.sum() == 2
    assert snapshot["dates"].Predictions.tolist() == [2, 2]


@pytest.mark.parametrize("filters,predictions,alerts", [
    ({"batch": "batch-a"}, 2, 1),
    ({"model": "model-b"}, 2, 1),
    ({"status": "Anomaly"}, 2, 2),
    ({"status": "Normal"}, 2, 2),  # status is a prediction-table filter only
    ({"batch": "batch-a", "model": "model-b"}, 0, 0),
    ({"source_ip": "192.0.2.3"}, 1, 1),
    ({"source_ip": "%"}, 0, 0),
    ({"batch": "' OR 1=1 --"}, 0, 0),
])
def test_parameterized_filters(database, filters, predictions, alerts):
    result = read_snapshot(database, **filters)
    assert len(result["predictions"]) == predictions
    assert len(result["alerts"]) == alerts
    assert result["kpis"]["Total Predictions"] == 4  # overview always global


def test_empty_initialized_database(tmp_path):
    path = tmp_path / "empty.db"
    initialize_database(path)
    snapshot = read_snapshot(path)
    assert all(value == 0 for value in snapshot["kpis"].values())
    assert snapshot["alerts"].empty and snapshot["predictions"].empty
    assert snapshot["scores"].empty and snapshot["dates"].empty


@pytest.mark.parametrize("kind", ["missing", "directory", "malformed", "empty-file", "wrong-schema", "missing-column"])
def test_invalid_database_is_safe(tmp_path, kind):
    path = tmp_path / "private-database.db"
    if kind == "directory":
        path.mkdir()
    elif kind == "malformed":
        path.write_text("not sqlite; sensitive raw text")
    elif kind == "empty-file":
        path.touch()
    elif kind in ("wrong-schema", "missing-column"):
        with closing(sqlite3.connect(path)) as connection, connection:
            if kind == "wrong-schema":
                connection.execute("CREATE TABLE unrelated(id INTEGER)")
            else:
                for table in ("ingestion_batches", "security_events", "predictions", "alerts"):
                    connection.execute(f"CREATE TABLE {table}(id INTEGER)")
                connection.execute("PRAGMA user_version=1")
    before = path.read_bytes() if path.is_file() else None
    with pytest.raises(DashboardDataError) as error:
        read_snapshot(path)
    assert "private-database" not in str(error.value)
    assert "sensitive raw text" not in str(error.value)
    assert "SELECT" not in str(error.value)
    if kind == "missing":
        assert not path.exists()
    elif path.is_file():
        assert path.read_bytes() == before


def test_readonly_connection_rejects_writes(database):
    before = hashlib.sha256(database.read_bytes()).digest()
    with readonly_database(database) as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM predictions")
    read_snapshot(database, batch="batch-a")
    assert hashlib.sha256(database.read_bytes()).digest() == before


def test_orphan_alert_rejected(database):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER alerts_require_anomaly")
        connection.execute("INSERT INTO alerts (prediction_id,alert_type,created_at_utc) VALUES (999,'synthetic','2026-01-01T00:00:00+00:00')")
    with pytest.raises(DashboardDataError):
        read_snapshot(database)


def test_duplicate_prediction_ids_cannot_multiply_joins(database):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER alerts_require_anomaly")
        connection.execute("CREATE TABLE replacement AS SELECT * FROM predictions")
        connection.execute("INSERT INTO replacement SELECT * FROM predictions WHERE anomaly_label=-1")
        connection.execute("DROP TABLE predictions")
        connection.execute("ALTER TABLE replacement RENAME TO predictions")
    with pytest.raises(DashboardDataError):
        read_snapshot(database)


def test_bad_classification_state_rejected(database):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute("UPDATE predictions SET anomaly_status='unexpected' WHERE prediction_id=1")
    with pytest.raises(DashboardDataError):
        read_snapshot(database)


def test_timestamp_chart_never_infers_timezone():
    dates, skipped = processing_dates(["2026-01-02T00:30:00+02:00", "2026-01-01T12:00:00Z", "Jan 1 12:00:00", "2026-01-01T12:00:00", None])
    assert dates["Processing date (UTC)"].tolist() == ["2026-01-01"]
    assert dates.Predictions.tolist() == [2]
    assert skipped == 3


def test_invalid_processing_timestamp_is_skipped_not_fabricated(database):
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("UPDATE predictions SET processed_at_utc='no timestamp' WHERE prediction_id=1")
    snapshot = read_snapshot(database)
    assert snapshot["skipped_timestamps"] == 1
    assert snapshot["dates"].Predictions.sum() == 3


def test_chart_figures_use_database_values(database):
    data = read_snapshot(database)
    pie = prediction_distribution(data["kpis"])
    assert list(pie.data[0].values) == [2, 2]
    assert len(alerts_by_source(data["alert_groups"]).data) == 2
    assert len(score_distribution(data["scores"]).data) == 2
    assert sum(processing_counts(data["dates"]).data[0].y) == 4


def test_app_overview_navigation_and_filters(database, monkeypatch):
    monkeypatch.setenv("MINI_SIEM_DATABASE", str(database))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not app.exception
    assert {metric.label: metric.value for metric in app.metric}["Total Predictions"] == "4"
    app.sidebar.radio[0].set_value("Alerts").run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 2
    app.selectbox(key="alerts-batch").set_value("batch-a").run()
    assert len(app.dataframe[0].value) == 1
    app.sidebar.radio[0].set_value("Predictions").run()
    app.selectbox(key="predictions-status").set_value("Normal").run()
    assert not app.exception
    assert len(app.dataframe[0].value) == 2
    app.sidebar.radio[0].set_value("Data Sources / System Information").run()
    assert not app.exception


def test_app_refresh_rereads_database(database, monkeypatch):
    monkeypatch.setenv("MINI_SIEM_DATABASE", str(database))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("INSERT INTO security_events (batch_id,source_record,ingested_at_utc) VALUES ('batch-a',1,'2026-01-01T00:00:00+00:00')")
    app.sidebar.button[0].click().run()
    assert not app.exception
    assert {metric.label: metric.value for metric in app.metric}["Raw Events Available"] == "1"


def test_app_missing_database_has_safe_message(tmp_path, monkeypatch):
    path = tmp_path / "secret-name.db"
    monkeypatch.setenv("MINI_SIEM_DATABASE", str(path))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not app.exception
    assert app.error
    assert "secret-name" not in app.error[0].value
    assert not path.exists()


def test_app_empty_state(tmp_path, monkeypatch):
    path = tmp_path / "empty.db"
    initialize_database(path)
    monkeypatch.setenv("MINI_SIEM_DATABASE", str(path))
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not app.exception
    assert any("No predictions" in message.value for message in app.info)


@pytest.mark.parametrize("column,value", [("source_ip", "not an IP"), ("model_id", ""), ("batch_id", "")])
def test_malformed_identifiers_are_safe_errors(database, column, value):
    with closing(sqlite3.connect(database)) as connection, connection:
        # Column identifiers are fixed test constants; values remain parameters.
        connection.execute(f"UPDATE predictions SET {column}=? WHERE prediction_id=1", (value,))
    with pytest.raises(DashboardDataError):
        read_snapshot(database)
