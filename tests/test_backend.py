"""Synthetic local artifacts only; production ingestion never trains a model."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
import hashlib
import json
import sqlite3
from unittest.mock import patch

import pandas as pd
import pytest

from mini_siem.alerts.management import create_alert
from mini_siem.backend import main
from mini_siem.ingestion.ssh_backend import ingest_features
from mini_siem.ml.model import save_model, train_model
from mini_siem.storage.sqlite import (
    SCORE_CONVENTION, connect_database, initialize_database, stored_statistics,
)


@pytest.fixture
def inputs(tmp_path):
    rows = []
    for i in range(30):
        total, failed = (20 + i % 7, i % 3) if i < 29 else (2000, 1800)
        rows.append({"SourceIP": f"192.0.2.{i + 1}", "EventCount": total,
                     "UniqueEventTypes": 2 + i % 3, "FailedAuthCount": failed,
                     "InvalidUserCount": 0 if i < 29 else 900,
                     "FailedAuthRate": failed / total})
    frame = pd.DataFrame(rows)
    csv, model, database = tmp_path / "synthetic.csv", tmp_path / "synthetic.joblib", tmp_path / "siem.db"
    frame.to_csv(csv, index=False)
    save_model(train_model(frame), model)  # test fixture only, never an ingestion step
    initialize_database(database)
    return database, csv, model, frame


def ingest(inputs, batch_id="batch-1"):
    database, csv, model, _ = inputs
    return ingest_features(database, csv, model, batch_id, trusted=True)


def fetch_all(database, table):
    # Only fixed table constants are supplied by the tests.
    with closing(connect_database(database)) as connection:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table}")]


def test_initialize_repeatable_and_persistent(tmp_path):
    database = tmp_path / "nested/siem.db"
    initialize_database(database)
    initialize_database(database)
    assert stored_statistics(database) == {"ingestion_batches": 0, "security_events": 0, "predictions": 0, "alerts": 0, "Normal": 0, "Anomaly": 0}
    with closing(connect_database(database)) as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_ingestion_persistence_alerts_metadata_and_utc(inputs):
    database, csv, model, frame = inputs
    original_csv, original_model = csv.read_bytes(), model.read_bytes()
    result = ingest(inputs)
    statistics = stored_statistics(database)
    assert statistics["predictions"] == result["inserted_predictions"] == 30
    assert statistics["alerts"] == statistics["Anomaly"] == result["inserted_alerts"] > 0
    assert statistics["Normal"] > 0
    assert statistics["security_events"] == 0  # no fabricated raw events
    batch = fetch_all(database, "ingestion_batches")[0]
    assert batch["source_sha256"] == hashlib.sha256(original_csv).hexdigest()
    rows = fetch_all(database, "predictions")
    assert [row["source_ip"] for row in rows] == frame.SourceIP.tolist()
    assert [row["source_record"] for row in rows] == list(range(1, 31))
    assert {row["model_id"] for row in rows} == {"sha256:" + hashlib.sha256(original_model).hexdigest()}
    assert {row["score_convention"] for row in rows} == {SCORE_CONVENTION}
    for row in rows:
        assert datetime.fromisoformat(row["processed_at_utc"]).utcoffset().total_seconds() == 0
        assert (row["anomaly_label"] == -1) == (row["anomaly_score"] < 0)
    assert datetime.fromisoformat(batch["created_at_utc"]).utcoffset().total_seconds() == 0
    with closing(connect_database(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts JOIN predictions USING(prediction_id) WHERE anomaly_label != -1").fetchone()[0] == 0
    for alert in fetch_all(database, "alerts"):
        assert datetime.fromisoformat(alert["created_at_utc"]).utcoffset().total_seconds() == 0
    assert csv.read_bytes() == original_csv
    assert model.read_bytes() == original_model


def test_idempotency_preserves_historical_records(inputs):
    database, *_ = inputs
    first = ingest(inputs)
    before = {table: fetch_all(database, table) for table in ("ingestion_batches", "predictions", "alerts")}
    second = ingest(inputs)
    assert second["inserted_predictions"] == second["inserted_alerts"] == 0
    assert first["model_id"] == second["model_id"]
    assert before == {table: fetch_all(database, table) for table in before}


def test_changed_source_same_batch_rejected_without_writes(inputs):
    database, csv, _, frame = inputs
    ingest(inputs)
    before = stored_statistics(database)
    frame.loc[0, "EventCount"] = 99
    frame.to_csv(csv, index=False)
    with pytest.raises(ValueError, match="different source content"):
        ingest(inputs)
    assert stored_statistics(database) == before


def test_new_batch_retains_history_and_parameterizes_id(inputs):
    database, *_ = inputs
    ingest(inputs)
    alerts_before = fetch_all(database, "alerts")
    result = ingest(inputs, "batch'; DROP TABLE alerts; --")
    assert result["inserted_predictions"] == 30
    assert fetch_all(database, "alerts")[:len(alerts_before)] == alerts_before
    assert stored_statistics(database)["ingestion_batches"] == 2


def test_different_model_version_retains_prediction_and_alert_history(inputs):
    database, _, model, frame = inputs
    first = ingest(inputs)
    old_alerts = fetch_all(database, "alerts")
    save_model(train_model(frame, random_state=7), model)  # distinct synthetic fixture
    second = ingest(inputs)
    assert first["model_id"] != second["model_id"]
    assert second["inserted_predictions"] == 30
    assert stored_statistics(database)["ingestion_batches"] == 1
    assert stored_statistics(database)["predictions"] == 60
    assert fetch_all(database, "alerts")[:len(old_alerts)] == old_alerts


def test_normal_records_cannot_create_alerts(inputs):
    database, *_ = inputs
    ingest(inputs)
    with closing(connect_database(database)) as connection:
        normal_id = connection.execute("SELECT prediction_id FROM predictions WHERE anomaly_label = 1 LIMIT 1").fetchone()[0]
        with connection:
            assert create_alert(connection, normal_id, "2026-01-01T00:00:00+00:00") == 0
        with pytest.raises(sqlite3.IntegrityError), connection:
            connection.execute("INSERT INTO alerts (prediction_id, alert_type, created_at_utc) VALUES (?, ?, ?)", (normal_id, "forbidden", "2026-01-01T00:00:00+00:00"))


def test_failure_rolls_back_whole_batch_and_retry_succeeds(inputs):
    database, *_ = inputs
    # Inject an actual database failure after several predictions/alerts.
    with closing(connect_database(database)) as connection, connection:
        connection.execute("""CREATE TRIGGER fail_mid_batch BEFORE INSERT ON predictions
                              WHEN NEW.source_record = 30
                              BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        ingest(inputs)
    counts = stored_statistics(database)
    assert counts["ingestion_batches"] == counts["predictions"] == counts["alerts"] == 0
    with closing(connect_database(database)) as connection, connection:
        connection.execute("DROP TRIGGER fail_mid_batch")
    assert ingest(inputs)["inserted_predictions"] == 30


def test_alert_failure_rolls_back_predictions(inputs):
    database, *_ = inputs
    with patch("mini_siem.ingestion.ssh_backend.create_alert", side_effect=sqlite3.IntegrityError("synthetic alert failure")):
        with pytest.raises(sqlite3.IntegrityError):
            ingest(inputs)
    assert stored_statistics(database)["ingestion_batches"] == 0
    assert stored_statistics(database)["predictions"] == 0


def test_failed_second_batch_preserves_existing_history(inputs):
    database, *_ = inputs
    ingest(inputs)
    before = {table: fetch_all(database, table) for table in ("ingestion_batches", "predictions", "alerts")}
    with patch("mini_siem.ingestion.ssh_backend.create_alert", side_effect=RuntimeError("interrupted")):
        with pytest.raises(RuntimeError):
            ingest(inputs, "second")
    assert before == {table: fetch_all(database, table) for table in before}


def test_inference_never_fits(inputs):
    with patch("sklearn.ensemble.IsolationForest.fit", side_effect=AssertionError("must not retrain")), patch("sklearn.compose.ColumnTransformer.fit_transform", side_effect=AssertionError("must not refit")):
        assert ingest(inputs)["records"] == 30


@pytest.mark.parametrize("invalid", ["", "nonnumeric", -1, float("inf")])
def test_invalid_features_never_write(inputs, invalid):
    database, csv, _, frame = inputs
    frame = frame.astype(object)
    frame.loc[0, "EventCount"] = invalid
    frame.to_csv(csv, index=False)
    with pytest.raises(ValueError):
        ingest(inputs)
    assert stored_statistics(database)["ingestion_batches"] == 0


def test_missing_columns_never_write(inputs):
    database, csv, _, frame = inputs
    frame.drop(columns="FailedAuthRate").to_csv(csv, index=False)
    with pytest.raises(ValueError):
        ingest(inputs)
    assert stored_statistics(database)["predictions"] == 0


def test_untrusted_model_not_loaded(inputs):
    database, csv, model, _ = inputs
    with patch("mini_siem.ingestion.ssh_backend.load_model") as loader:
        with pytest.raises(ValueError, match="trusted"):
            ingest_features(database, csv, model, "batch")
        loader.assert_not_called()
    assert stored_statistics(database)["predictions"] == 0


def test_concurrent_retries_are_idempotent(inputs):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: ingest(inputs), range(2)))
    assert sum(result["inserted_predictions"] for result in results) == 30
    assert sum(result["inserted_alerts"] for result in results) == stored_statistics(inputs[0])["alerts"]


def test_duplicate_rows_keep_separate_source_record_identity(inputs):
    database, csv, _, frame = inputs
    frame.iloc[[29, 29]].to_csv(csv, index=False)
    result = ingest(inputs)
    assert result["inserted_predictions"] == result["inserted_alerts"] == 2
    assert len(fetch_all(database, "predictions")) == 2
    assert ingest(inputs)["inserted_predictions"] == 0


def test_cli_init_ingest_retry_stats(inputs, tmp_path, capsys):
    _, csv, model, _ = inputs
    database = tmp_path / "cli.db"
    assert main(["init", "--database", str(database)]) == 0
    capsys.readouterr()
    args = ["ingest", "--database", str(database), "--input", str(csv), "--model", str(model), "--batch-id", "cli", "--trust-model"]
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["inserted_predictions"] == 30
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["inserted_predictions"] == 0
    assert main(["stats", "--database", str(database)]) == 0
    assert json.loads(capsys.readouterr().out)["predictions"] == 30


def test_cli_missing_database_does_not_create_it(tmp_path):
    path = tmp_path / "missing.db"
    assert main(["stats", "--database", str(path)]) == 2
    assert not path.exists()


def test_unrelated_database_is_not_modified(tmp_path):
    database = tmp_path / "other.db"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE important (value TEXT)")
        connection.execute("INSERT INTO important VALUES (?)", ("keep",))
    with pytest.raises(ValueError):
        initialize_database(database)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT value FROM important").fetchone()[0] == "keep"


def test_reserved_events_have_no_fabricated_timestamp(inputs):
    database, *_ = inputs
    ingest(inputs)
    with closing(connect_database(database)) as connection, connection:
        connection.execute("INSERT INTO security_events (batch_id, source_record, source_ip, event_type, ingested_at_utc) VALUES (?, ?, ?, ?, ?)", ("batch-1", 1, "192.0.2.1", "synthetic", "2026-01-01T00:00:00+00:00"))
        assert connection.execute("SELECT occurred_at FROM security_events").fetchone()[0] is None


def test_all_normal_batch_creates_no_alerts(inputs):
    database, csv, _, frame = inputs
    frame.iloc[:1].to_csv(csv, index=False)
    result = ingest(inputs)
    assert result["Normal"] == result["inserted_predictions"] == 1
    assert result["Anomaly"] == result["inserted_alerts"] == 0
    assert stored_statistics(database)["alerts"] == 0


def test_empty_existing_file_is_preserved(tmp_path):
    path = tmp_path / "original.csv"
    path.write_bytes(b"")
    with pytest.raises(ValueError):
        initialize_database(path)
    assert path.read_bytes() == b""


def test_initialization_failure_rolls_back_schema(tmp_path):
    database = tmp_path / "broken.db"
    with patch("mini_siem.storage.sqlite.SCHEMA", ("CREATE TABLE partial (id INTEGER)", "invalid SQL")):
        with pytest.raises(sqlite3.Error):
            initialize_database(database)
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    # Initialization rolled back to an empty file; preserve it and recover
    # at a fresh path, as required by the existing-file protection.
    retry = tmp_path / "retry.db"
    initialize_database(retry)
    assert stored_statistics(retry)["predictions"] == 0


def test_blank_batch_id_is_rejected(inputs):
    database, *_ = inputs
    with pytest.raises(ValueError, match="batch_id"):
        ingest(inputs, " ")
    assert stored_statistics(database)["ingestion_batches"] == 0


def test_cli_ingest_requires_explicit_trust(inputs):
    database, csv, model, _ = inputs
    assert main(["ingest", "--database", str(database), "--input", str(csv), "--model", str(model), "--batch-id", "untrusted"]) == 2
    assert stored_statistics(database)["predictions"] == 0


def test_database_model_input_collisions_are_rejected(inputs):
    _, csv, model, _ = inputs
    before = csv.read_bytes()
    with pytest.raises(ValueError, match="differ"):
        ingest_features(csv, csv, model, "collision", trusted=True)
    assert csv.read_bytes() == before


def test_unrelated_version_one_database_is_rejected(tmp_path):
    database = tmp_path / "other-v1.db"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER)")
        connection.execute("PRAGMA user_version = 1")
    with pytest.raises(ValueError):
        initialize_database(database)
    with pytest.raises(ValueError):
        connect_database(database)
