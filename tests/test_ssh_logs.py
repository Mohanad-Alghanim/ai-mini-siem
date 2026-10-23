"""Synthetic fixtures only; no private historical logs or model artifacts."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import sqlite3
from unittest.mock import patch

import pandas as pd
import pytest

from mini_siem.dashboard.queries import read_snapshot
from mini_siem.ingestion.ssh_events import load_events, parse_message
from mini_siem.preprocessing.ssh_features import aggregate_features, analysis_report, compare_baseline, require_model_compatibility
from mini_siem.ssh_logs import main
from mini_siem.storage.sqlite import connect_database, initialize_database
from mini_siem.storage.ssh_events import persist_events, prepare_storage


@pytest.fixture
def source(tmp_path):
    messages = ["Failed password for invalid user test from 192.0.2.1 port 22 ssh2",
                "Accepted password for test from 192.0.2.1 port 22 ssh2",
                "Invalid user test", "Connection closed by 192.0.2.2 port 22",
                "authentication failure; rhost=2001:db8::1", "from 192.0.2.1 from 192.0.2.2"]
    rows = [{"LineId": str(i + 1), "Date": "Jun", "Day": "1", "Time": "12:01:00", "Component": "sshd", "Pid": "123", "Content": message, "EventId": "E1" if i == 0 else "E2", "EventTemplate": "synthetic template"} for i, message in enumerate(messages)]
    path = tmp_path / "events.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


@pytest.fixture
def storage(tmp_path):
    path = tmp_path / "siem.db"
    initialize_database(path)
    prepare_storage(path)
    return path


@pytest.mark.parametrize("message,ip,status", [
    ("Failed password for test from 192.0.2.1 port 22", "192.0.2.1", "supported_peer"),
    ("rhost=2001:0db8:0:0::1", "2001:db8::1", "supported_peer"),
    ("Connection closed by 192.0.2.2", "192.0.2.2", "supported_peer"),
    ("No remote peer", None, "no_ip_evidence"),
    ("peer [192.0.2.1] unexpected format", None, "unsupported_ip_context"),
    ("from 999.1.1.1", None, "invalid_peer"),
    ("from hostname", None, "invalid_peer"),
    ("from 192.0.2.1 from 192.0.2.2", None, "ambiguous_peer"),
    ("from 192.0.2.1 from 999.1.1.1", None, "invalid_peer"),
    ("from 192.0.2.1 rhost=192.0.2.1", "192.0.2.1", "supported_peer"),
])
def test_peer_extraction(message, ip, status):
    parsed = parse_message(message)
    assert parsed["SourceIP"] == ip
    assert parsed["ParseStatus"] == status


def test_authentication_indicators_and_overlap():
    parsed = parse_message("Failed password for invalid user test from 192.0.2.1")
    assert parsed["FailedAuth"] and parsed["InvalidUser"] and not parsed["AcceptedAuth"]
    assert parse_message("authentication failure")["FailedAuth"]
    assert parse_message("Accepted publickey for test from 192.0.2.1")["AcceptedAuth"]
    assert parse_message("Accepted password; authentication failure")["AuthAmbiguous"]
    assert not parse_message("Failed reverse mapping lookup")["FailedAuth"]


def test_load_aggregation_and_original_preservation(source):
    before = source.read_bytes()
    events, digest = load_events(source)
    assert len(events) == 6
    assert events[2]["SourceIP"] is None
    assert events[0]["Original"]["LineId"] == "1"
    features = aggregate_features(events).set_index("SourceIP")
    assert features.loc["192.0.2.1"].to_dict() == {"EventCount": 2, "UniqueEventTypes": 2, "FailedAuthCount": 1, "InvalidUserCount": 1, "FailedAuthRate": .5}
    assert features.loc["2001:db8::1", "FailedAuthRate"] == 1
    assert source.read_bytes() == before
    report = analysis_report(events, features.reset_index(), digest)
    assert report["events_with_source_ip"] == 4
    assert report["events_without_source_ip"] == 2
    assert report["ip_extraction_coverage"] == 4 / 6


def test_required_columns_and_malformed_csv_rejected(source):
    frame = pd.read_csv(source)
    frame.drop(columns="Content").to_csv(source, index=False)
    with pytest.raises(ValueError):
        load_events(source)
    source.write_text("LineId,Content\n1,extra,bad\n")
    with pytest.raises(ValueError):
        load_events(source)


@pytest.mark.parametrize("column,value", [("LineId", "not-number"), ("LineId", "0"), ("Content", "")])
def test_invalid_records_rejected(source, column, value):
    frame = pd.read_csv(source).astype(object)
    frame.loc[2, column] = value
    frame.to_csv(source, index=False)
    with pytest.raises(ValueError):
        load_events(source)


def test_template_fallback_and_partial_timestamps_remain_original(source):
    frame = pd.read_csv(source).astype(object)
    frame.loc[0, "EventId"] = ""
    frame.loc[0, "Time"] = ""
    frame.to_csv(source, index=False)
    events, _ = load_events(source)
    assert events[0]["EventType"] == "template:synthetic template"
    assert events[0]["Original"]["Time"] == ""


def test_persistence_all_rows_no_invented_times_and_idempotency(source, storage):
    events, digest = load_events(source)
    assert persist_events(storage, events, digest, "raw-1")["inserted_events"] == 6
    with closing(connect_database(storage)) as connection:
        before = [tuple(row) for row in connection.execute("SELECT * FROM security_events")]
        details = connection.execute("SELECT original_fields_json FROM ssh_event_details ORDER BY event_id").fetchall()
        assert all(row["occurred_at"] is None for row in connection.execute("SELECT * FROM security_events"))
        assert connection.execute("SELECT COUNT(*) FROM security_events WHERE source_ip IS NULL").fetchone()[0] == 2
        assert json.loads(details[0][0])["Content"] == events[0]["Original"]["Content"]
    assert persist_events(storage, events, digest, "raw-1")["inserted_events"] == 0
    with closing(connect_database(storage)) as connection:
        assert before == [tuple(row) for row in connection.execute("SELECT * FROM security_events")]
        assert connection.execute("SELECT COUNT(*) FROM predictions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert read_snapshot(storage)["kpis"]["Raw Events Available"] == 6


def test_storage_extension_explicit_only(source, tmp_path):
    database = tmp_path / "original.db"
    initialize_database(database)
    events, digest = load_events(source)
    with pytest.raises(ValueError, match="extension"):
        persist_events(database, events, digest, "raw")
    with closing(connect_database(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ingestion_batches").fetchone()[0] == 0
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='ssh_event_details'").fetchone()
    prepare_storage(database)
    prepare_storage(database)
    assert read_snapshot(database)["kpis"]["Raw Events Available"] == 0


def test_rollback_after_partial_insert_and_retry(source, storage):
    events, digest = load_events(source)
    with closing(connect_database(storage)) as connection, connection:
        connection.execute("""CREATE TRIGGER fail_details BEFORE INSERT ON ssh_event_details
            WHEN NEW.event_id=3 BEGIN SELECT RAISE(ABORT,'synthetic failure'); END""")
    with pytest.raises(sqlite3.IntegrityError):
        persist_events(storage, events, digest, "raw")
    with closing(connect_database(storage)) as connection, connection:
        for table in ("ingestion_batches", "security_events", "ssh_event_details"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        connection.execute("DROP TRIGGER fail_details")
    assert persist_events(storage, events, digest, "raw")["inserted_events"] == 6


def test_batch_source_conflict_preserves_history(source, storage):
    events, digest = load_events(source)
    persist_events(storage, events, digest, "raw")
    with pytest.raises(ValueError, match="different source"):
        persist_events(storage, events, "changed-hash", "raw")
    assert read_snapshot(storage)["kpis"]["Raw Events Available"] == 6


def test_concurrent_duplicate_prevention(source, storage):
    events, digest = load_events(source)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: persist_events(storage, events, digest, "raw"), range(2)))
    assert sum(result["inserted_events"] for result in results) == 6


def test_baseline_mismatch_and_compatibility_guard(source, tmp_path):
    events, digest = load_events(source)
    features = aggregate_features(events)
    baseline = features.copy()
    baseline.loc[0, "EventCount"] += 1
    baseline.loc[1, "SourceIP"] = "198.51.100.1"
    path = tmp_path / "baseline.csv"
    baseline.to_csv(path, index=False)
    comparison = compare_baseline(features, path)
    assert comparison["matching_source_ips"] == 2
    assert comparison["baseline_ips_without_generated_features"] == ["198.51.100.1"]
    assert comparison["generated_ips_not_in_baseline"]
    assert comparison["feature_differences"]
    report = analysis_report(events, features, digest, comparison)
    assert not report["model_compatibility"]["inference_allowed"]
    with pytest.raises(ValueError, match="compatibility"):
        require_model_compatibility(report)
    features.to_csv(path, index=False)
    exact = compare_baseline(features, path)
    assert exact["numerical_match"]
    with pytest.raises(ValueError):
        require_model_compatibility(analysis_report(events, features, digest, exact))


def test_no_ip_feature_export_is_empty_not_invented(source):
    events, _ = load_events(source)
    for event in events:
        event["SourceIP"] = None
    features = aggregate_features(events)
    assert features.empty
    assert list(features) == ["SourceIP", "EventCount", "UniqueEventTypes", "FailedAuthCount", "InvalidUserCount", "FailedAuthRate"]


def test_cli_export_compare_and_ingest_never_infers(source, storage, tmp_path):
    events, _ = load_events(source)
    baseline, output = tmp_path / "baseline.csv", tmp_path / "generated.csv"
    aggregate_features(events).to_csv(baseline, index=False)
    before = source.read_bytes()
    with patch("mini_siem.ml.model.predict_records", side_effect=AssertionError("Inference forbidden")), patch("mini_siem.ml.model.load_model", side_effect=AssertionError("Model loading forbidden")):
        assert main(["inspect", "--input", str(source), "--baseline", str(baseline), "--features", str(output), "--report-dir", str(tmp_path / "reports")]) == 0
        report = json.loads((tmp_path / "reports/summary.json").read_text())
        assert report["baseline_comparison"]["numerical_match"]
        assert not report["model_compatibility"]["inference_allowed"]
        assert main(["ingest", "--input", str(source), "--database", str(storage), "--batch-id", "raw"]) == 0
    assert source.read_bytes() == before


def test_cli_collision_and_invalid_input_do_not_write(source, storage, tmp_path):
    before = source.read_bytes()
    assert main(["inspect", "--input", str(source), "--features", str(source), "--report-dir", str(tmp_path / "reports")]) == 2
    assert source.read_bytes() == before
    frame = pd.read_csv(source).drop(columns="LineId")
    frame.to_csv(source, index=False)
    assert main(["ingest", "--input", str(source), "--database", str(storage), "--batch-id", "raw"]) == 2
    assert read_snapshot(storage)["kpis"]["Raw Events Available"] == 0


def test_prior_predictions_and_alerts_are_preserved(source, storage):
    from mini_siem.storage.sqlite import SCORE_CONVENTION
    with closing(connect_database(storage)) as connection, connection:
        connection.execute("INSERT INTO ingestion_batches VALUES (?,?,?,?)", ("old-feature-batch", "old-hash", 1, "2026-01-01T00:00:00+00:00"))
        connection.execute("""INSERT INTO predictions
            (batch_id,model_id,source_record,source_ip,anomaly_label,anomaly_status,anomaly_score,score_convention,processed_at_utc)
            VALUES (?,?,?,?,?,?,?,?,?)""", ("old-feature-batch", "old-model", 1, "192.0.2.100", -1, "Anomaly", -.2, SCORE_CONVENTION, "2026-01-01T00:00:00+00:00"))
        connection.execute("INSERT INTO alerts (prediction_id,alert_type,created_at_utc) VALUES (1,?,?)", ("SSH behavioral anomaly", "2026-01-01T00:00:00+00:00"))
        before = {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")] for table in ("predictions", "alerts")}
    events, digest = load_events(source)
    persist_events(storage, events, digest, "raw-batch")
    persist_events(storage, events, digest, "raw-batch")
    with closing(connect_database(storage)) as connection:
        assert before == {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")] for table in before}
    assert read_snapshot(storage)["kpis"]["Total Alerts"] == 1


def test_repeated_original_ids_are_retained_and_reported(source, storage):
    frame = pd.read_csv(source)
    frame.loc[1, "LineId"] = frame.loc[0, "LineId"]
    frame.to_csv(source, index=False)
    events, digest = load_events(source)
    assert analysis_report(events, aggregate_features(events), digest)["duplicate_original_line_ids"] == 1
    assert persist_events(storage, events, digest, "duplicate-original-ids")["inserted_events"] == 6


def test_timestamp_is_not_mistaken_for_ip_evidence():
    assert parse_message("Jan 1 12:00:00 unrelated message")["ParseStatus"] == "no_ip_evidence"


def test_duplicate_baseline_ips_are_not_arbitrarily_joined(source, tmp_path):
    events, _ = load_events(source)
    features = aggregate_features(events)
    baseline = pd.concat([features, features.iloc[:1]], ignore_index=True)
    path = tmp_path / "ambiguous.csv"
    baseline.to_csv(path, index=False)
    comparison = compare_baseline(features, path)
    assert comparison["ambiguous_baseline_rows"] == 2
    assert not comparison["numerical_match"]


def test_other_workflow_batch_is_not_repurposed(source, storage):
    events, digest = load_events(source)
    with closing(connect_database(storage)) as connection, connection:
        connection.execute("INSERT INTO ingestion_batches VALUES (?,?,?,?)", ("other", digest, len(events), "2026-01-01T00:00:00+00:00"))
    with pytest.raises(ValueError, match="complete historical"):
        persist_events(storage, events, digest, "other")
    assert read_snapshot(storage)["kpis"]["Raw Events Available"] == 0


def test_missing_event_reference_rejected(source):
    frame = pd.read_csv(source)
    frame.loc[0, ["EventId", "EventTemplate"]] = ""
    frame.to_csv(source, index=False)
    with pytest.raises(ValueError, match="EventId"):
        load_events(source)


def test_cli_prepare_storage_is_explicit_and_idempotent(tmp_path):
    database = tmp_path / "backend.db"
    assert main(["prepare-storage", "--database", str(database)]) == 2
    assert not database.exists()
    initialize_database(database)
    assert main(["prepare-storage", "--database", str(database)]) == 0
    assert main(["prepare-storage", "--database", str(database)]) == 0


def test_unsupported_groups_do_not_export_raw_content(source):
    events, digest = load_events(source)
    report = analysis_report(events, aggregate_features(events), digest)
    assert sum(group["records"] for group in report["unsupported_patterns"]) == 2
    serialized = json.dumps(report)
    assert events[0]["Original"]["Content"] not in serialized
    assert "synthetic template" not in serialized


@pytest.mark.parametrize("message,ip,status", [
    ("Received disconnect from 192.0.2.10: 11: Bye Bye [preauth]", "192.0.2.10", "supported_peer"),
    ("Received disconnect from 198.51.100.7: 11: disconnected by user", "198.51.100.7", "supported_peer"),
    ("Received disconnect from 192.0.2.10: 11: disconnected by user [preauth]", "192.0.2.10", "supported_peer"),
    ("Received disconnect FROM 192.0.2.10: 11: Bye Bye", "192.0.2.10", "supported_peer"),
    ("from 999.0.2.10: 11: Bye Bye", None, "invalid_peer"),
    ("from 192.0.2.999: 11: Bye Bye", None, "invalid_peer"),
    ("from 192.00.2.10: 11: Bye Bye", None, "invalid_peer"),
    ("from 192.0.2: 11: Bye Bye", None, "invalid_peer"),
    ("from 192.0.2.10:: 11: Bye Bye", None, "invalid_peer"),
    ("from 192.0.2.10:22 11: Bye Bye", None, "invalid_peer"),
    ("from 192.0.2.10:, 11: Bye Bye", None, "invalid_peer"),
    ("from example.invalid: 11: Bye Bye", None, "invalid_peer"),
    ("rhost=192.0.2.10:", None, "invalid_peer"),
    ("Connection closed by 192.0.2.10:", None, "invalid_peer"),
    ("peer 192.0.2.10: unexpected context", None, "no_ip_evidence"),
    ("Received disconnect from 2001:db8::1 11: Bye Bye", "2001:db8::1", "supported_peer"),
    ("Received disconnect from 2001:db8:: 11: Bye Bye", "2001:db8::", "supported_peer"),
    ("Received disconnect from :: 11: Bye Bye", "::", "supported_peer"),
    ("from 2001:db8::1: 11: Bye Bye", None, "invalid_peer"),
    ("from ::ffff:192.0.2.10: 11: Bye Bye", None, "invalid_peer"),
    ("from [2001:db8::1]: 11: Bye Bye", None, "invalid_peer"),
    ("from 192.0.2.10: from 192.0.2.11: 11: Bye Bye", None, "ambiguous_peer"),
    ("from 192.0.2.10: rhost=2001:db8::1", None, "ambiguous_peer"),
    ("from 192.0.2.10: from malformed:", None, "invalid_peer"),
    ("from 192.0.2.10: rhost=192.0.2.10", "192.0.2.10", "supported_peer"),
])
def test_ipv4_separator_regression(message, ip, status):
    parsed = parse_message(message)
    assert parsed["SourceIP"] == ip
    assert parsed["ParseStatus"] == status


def test_e24_e7_correction_preserves_events_idempotency_and_guard(source, storage):
    from mini_siem.ingestion.ssh_events import PARSER_VERSION
    frame = pd.read_csv(source)
    frame.loc[0, ["Content", "EventId"]] = ["Received disconnect from 192.0.2.10: 11: Bye Bye [preauth]", "E24"]
    frame.loc[1, ["Content", "EventId"]] = ["Received disconnect from 192.0.2.10: 11: disconnected by user", "E7"]
    frame.to_csv(source, index=False)
    before = source.read_bytes()
    events, digest = load_events(source)
    features = aggregate_features(events)
    row = features.set_index("SourceIP").loc["192.0.2.10"]
    assert row.EventCount == row.UniqueEventTypes == 2
    assert row.FailedAuthCount == row.InvalidUserCount == row.FailedAuthRate == 0
    report = analysis_report(events, features, digest)
    assert report["parser_version"] == PARSER_VERSION == "ssh-historical-v2"
    assert not report["model_compatibility"]["inference_allowed"]
    with pytest.raises(ValueError):
        require_model_compatibility(report)
    assert persist_events(storage, events, digest, "v2-events")["inserted_events"] == 6
    assert persist_events(storage, events, digest, "v2-events")["inserted_events"] == 0
    with closing(connect_database(storage)) as connection:
        raw = json.loads(connection.execute("SELECT original_fields_json FROM ssh_event_details ORDER BY event_id").fetchone()[0])
        assert raw["Content"] == frame.loc[0, "Content"]
        assert connection.execute("SELECT COUNT(*) FROM security_events WHERE occurred_at IS NOT NULL").fetchone()[0] == 0
    assert source.read_bytes() == before


def test_parser_version_conflict_preserves_v1_history(source, storage):
    events, digest = load_events(source)
    persist_events(storage, events, digest, "v1-history")
    with closing(connect_database(storage)) as connection, connection:
        # Represent an existing historical v1 batch; never rewrite it on retry.
        connection.execute("UPDATE ssh_event_details SET parser_version='ssh-historical-v1'")
        before = [tuple(row) for row in connection.execute("SELECT * FROM ssh_event_details")]
    with pytest.raises(ValueError, match="parser version conflict"):
        persist_events(storage, events, digest, "v1-history")
    with closing(connect_database(storage)) as connection:
        assert before == [tuple(row) for row in connection.execute("SELECT * FROM ssh_event_details")]
