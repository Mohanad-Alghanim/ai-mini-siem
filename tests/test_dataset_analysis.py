"""All data below are synthetic; no real security records are committed."""

from copy import deepcopy
import hashlib
import json

import pandas as pd
import pytest

from mini_siem.analysis import DATASETS, inspect, main, read_config
from mini_siem.ingestion.csv_loader import DatasetLoadError, load_csv
from mini_siem.preprocessing.relationships import check_predictions, event_ip_coverage, compare_datasets
from mini_siem.preprocessing.validation import analyze_events, validate_frame


def frame(values):
    return pd.DataFrame(values, dtype="string")


@pytest.fixture
def synthetic(tmp_path):
    """Generate four local fixtures; synthetic feature names are not real schemas."""
    ips = [f"192.0.2.{i + 1}" for i in range(30)]
    frames = {
        "events": frame({"SyntheticEventNumber": list(range(2000)), "SyntheticType": ["authentication"] * 2000,
                         "SyntheticMessage": [f"Failed password for demo from {ips[i % 30]} port 22 ssh2" for i in range(2000)]}),
        "baseline": frame({"SourceIP": ips, "SyntheticCount": [10] * 30}),
        "isolation": frame({"SourceIP": ips, "AnomalyLabel": [-1] * 30, "AnomalyStatus": ["flagged"] * 30, "AnomalyScore": [-0.1] * 30}),
        "risk": frame({"SourceIP": ips, "AnomalyLabel": [-1] * 30, "AnomalyStatus": ["flagged"] * 30, "AnomalyScore": [-0.1] * 30, "RiskLevel": ["review"] * 30}),
    }
    config = read_config()
    for name, data in frames.items():
        config["datasets"][name] = {"required": list(data), "columns": {column: {"type": "string"} for column in data}, "complete": True}
        if name != "events":
            config["datasets"][name]["columns"]["SourceIP"] = {"type": "ip"}
    config["datasets"]["events"].update(content_column="SyntheticMessage", event_column="SyntheticType")
    config["datasets"]["baseline"]["columns"]["SyntheticCount"] = {"type": "integer", "min": 0}
    for name in ("isolation", "risk"):
        config["datasets"][name]["columns"].update(AnomalyLabel={"type": "integer", "allowed": [-1, 1]}, AnomalyScore={"type": "number"})
    config["prediction_policy"] = {
        "label_status": {"-1": "flagged", "1": "normal"},
        "score_rule": {"direction": "lower", "threshold": 0, "anomaly_label": -1, "normal_label": 1},
        "risk_by_status": {"flagged": ["review"], "normal": ["low"]},
    }
    paths = {}
    for name, data in frames.items():
        paths[name] = tmp_path / DATASETS[name][0]
        data.to_csv(paths[name], index=False)
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(config))
    return frames, paths, config, schema_path


def test_full_cli_and_inputs_unchanged(synthetic, tmp_path):
    _, paths, _, schema = synthetic
    before = {name: hashlib.sha256(path.read_bytes()).digest() for name, path in paths.items()}
    output = tmp_path / "reports"
    args = ["--data-dir", str(tmp_path), "--schema", str(schema), "--output-dir", str(output)]
    assert main(args) == 0
    report = json.loads((output / "summary.json").read_text())
    assert report["datasets"]["events"]["quality"]["rows"] == 2000
    assert report["datasets"]["risk"]["prediction_checks"]["status_risk"]["compared"] == 30
    assert report["event_ip_evidence"]["coverage"]["baseline"]["shared_ips"] == 30
    text = (output / "analysis.md").read_text()
    assert "# SSH dataset inspection" in text
    assert "192.0.2.1" not in text
    assert "Failed password for demo" not in text
    assert main(args) == 0  # repeatable, no source mutation
    assert before == {name: hashlib.sha256(path.read_bytes()).digest() for name, path in paths.items()}


@pytest.mark.parametrize("contents", ["", "a,a\n1,2\n", "a,\n1,2\n", "a,b\n1\n", "a,b\n1,2,3\n", 'a,b\n"unclosed,2\n'])
def test_bad_csv_rejected(tmp_path, contents):
    path = tmp_path / "bad.csv"
    path.write_text(contents)
    with pytest.raises(DatasetLoadError):
        load_csv(path)


def test_loader_preserves_values_and_quoted_multiline(tmp_path):
    path = tmp_path / "input.csv"
    path.write_text('\ufeffSourceIP,Message\n001,"NA\nquoted"\n002,\n')
    data = load_csv(path)
    assert data.iloc[0].tolist() == ["001", "NA\nquoted"]
    assert data.iloc[1, 1] == ""


def test_quality_missing_duplicates_types_ranges():
    data = frame({"SourceIP": ["bad", "192.0.2.1", "192.0.2.1", ""], "Count": ["oops", "-1", "-1", "1.5"], "Score": ["nan", "inf", "-inf", "4"]})
    schema = {"required": ["Absent", "SourceIP"], "columns": {"Count": {"type": "integer", "min": 0}, "Score": {"type": "number", "max": 1}}}
    result = validate_frame(data, schema, 30)
    assert result["missing_columns"] == ["Absent"]
    assert result["duplicate_rows"] == 0
    assert validate_frame(frame({"X": ["same", "same"]}), {})["duplicate_rows"] == 1
    assert result["missing_values"]["SourceIP"] == 1
    assert result["column_checks"]["Count"]["invalid_type"] == 2
    assert result["column_checks"]["Count"]["out_of_range"] == 2
    assert result["column_checks"]["Score"]["invalid_type"] == 3
    assert result["column_checks"]["Score"]["out_of_range"] == 1
    assert result["source_ip"] == {"invalid": 1, "duplicate_keys": 1}
    assert not result["row_count_matches"]


def test_allowed_values():
    result = validate_frame(frame({"RiskLevel": ["low", "mystery", " "]}), {"columns": {"RiskLevel": {"allowed": ["low"]}}})
    assert result["column_checks"]["RiskLevel"]["invalid_allowed_value"] == 1
    assert result["missing_values"]["RiskLevel"] == 1


def test_event_indicators_and_no_timestamp_assumptions():
    data = frame({"Text": ["Accepted password", "Failed password for invalid user", "authentication failure", "Connection closed", "other"], "Type": ["A", "A", "B", "B", "C"], "Time": ["Jun 1 12:00:00"] * 5})
    result = analyze_events(data, {"content_column": "Text", "event_column": "Type"})
    assert result["event_types"]["distinct_types"] == 3
    assert result["authentication"]["indicator_counts"] == {"accepted": 1, "failed": 1, "invalid_user": 1, "authentication_failure": 1, "disconnect": 1}
    assert analyze_events(data, {})["authentication"]["status"] == "skipped"


def test_relations_missing_ips_duplicates_and_output_differences():
    a = frame({"SourceIP": ["192.0.2.1", "192.0.2.2", "192.0.2.2", "bad"], "AnomalyLabel": ["-1", "1", "1", "1"]})
    b = frame({"SourceIP": ["192.0.2.1", "192.0.2.3"], "AnomalyLabel": ["1", "-1"]})
    result = compare_datasets({"baseline": a, "risk": b}, {"baseline": {}, "risk": {}})[0]
    assert result["shared_ips"] == result["unambiguous_shared_ips"] == 1
    assert result["left_only_ips"] == result["right_only_ips"] == 1
    assert result["field_comparisons"]["AnomalyLabel"] == {"compared": 1, "different": 1}


def test_event_ip_extraction_is_conservative():
    events = frame({"Message": ["Failed from 192.0.2.1 port 22", "rhost=2001:db8::1", "from 999.1.1.1", "from 192.0.2.1 from 192.0.2.2", "no IP"]})
    baseline = frame({"SourceIP": ["192.0.2.1", "2001:db8::1", "192.0.2.3"]})
    result = event_ip_coverage({"events": events, "baseline": baseline}, {"events": {"content_column": "Message"}, "baseline": {}})
    assert result["events_with_ip_evidence"] == 2
    assert result["coverage"]["baseline"]["aggregate_ips_without_event_evidence"] == 1


def test_prediction_policy_checks(synthetic):
    _, _, config, _ = synthetic
    data = frame({"AnomalyLabel": ["-1", "1", "9"], "AnomalyStatus": ["normal", "flagged", "unknown"], "AnomalyScore": ["1", "-1", "inf"], "RiskLevel": ["review", "low", "anything"]})
    result = check_predictions(data, config["prediction_policy"])
    assert result["label_status"]["inconsistent"] == 2
    assert result["label_status"]["unmapped_labels"] == 1
    assert result["score_label"]["inconsistent"] == 2
    assert result["status_risk"]["inconsistent"] == 2
    assert result["status_risk"]["unmapped_statuses"] == 1
    assert all(check["status"] == "skipped" for check in check_predictions(data, {}).values())


def test_missing_inputs_reports_and_nonzero(tmp_path):
    assert main(["--data-dir", str(tmp_path), "--output-dir", str(tmp_path / "reports")]) == 1
    result = json.loads((tmp_path / "reports/summary.json").read_text())
    assert len(result["findings"]) == 4
    assert result["event_ip_evidence"]["status"] == "skipped"


def test_default_contract_is_explicitly_incomplete(synthetic):
    _, paths, _, _ = synthetic
    result = inspect(paths, read_config())
    assert all(not data["quality"]["schema_complete"] for data in result["datasets"].values())
    assert result["status"] == "findings"
    assert result["datasets"]["events"]["events"]["authentication"]["status"] == "skipped"


def test_path_overrides(synthetic, tmp_path):
    _, paths, _, schema = synthetic
    args = ["--schema", str(schema), "--output-dir", str(tmp_path / "out")]
    for name, path in paths.items():
        args.extend([f"--{name}", str(path)])
    assert main(args) == 0


def test_output_cannot_overwrite_input(synthetic, tmp_path):
    _, paths, _, schema = synthetic
    target = tmp_path / "summary.json"
    target.write_bytes(paths["events"].read_bytes())
    before = target.read_bytes()
    assert main(["--events", str(target), "--schema", str(schema), "--output-dir", str(tmp_path)]) == 2
    assert target.read_bytes() == before


@pytest.mark.parametrize("mutation", [
    lambda c: c["datasets"].pop("events"),
    lambda c: c["datasets"]["events"].update(complete="yes"),
    lambda c: c["datasets"]["events"].update(columns={"X": {"type": "timestamp"}}),
    lambda c: c["datasets"]["events"].update(columns={"X": {"type": "number", "min": 3, "max": 1}}),
    lambda c: c.update(prediction_policy={"score_rule": {"direction": "lower"}}),
    lambda c: c.update(prediction_policy={"risk_by_status": {"normal": "low"}}),
])
def test_invalid_config_rejected(synthetic, mutation):
    _, _, config, path = synthetic
    config = deepcopy(config)
    mutation(config)
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError):
        read_config(path)


def test_cli_bad_config_exit_two(tmp_path):
    schema = tmp_path / "bad.json"
    schema.write_text("not json")
    assert main(["--schema", str(schema)]) == 2


def test_empty_csv_is_reported_without_crashing(synthetic):
    _, paths, config, _ = synthetic
    paths["events"].write_text("SyntheticEventNumber,SyntheticType,SyntheticMessage\n")
    result = inspect(paths, config)
    assert result["datasets"]["events"]["quality"]["rows"] == 0
    assert result["event_ip_evidence"]["events_with_ip_evidence"] == 0
    assert result["status"] == "findings"


def test_ipv6_keys_are_canonicalized():
    frames = {"baseline": frame({"SourceIP": ["2001:db8::1"]}), "risk": frame({"SourceIP": ["2001:0db8:0:0:0:0:0:1"]})}
    result = compare_datasets(frames, {"baseline": {}, "risk": {}})[0]
    assert result["shared_ips"] == 1
    assert result["left_only_ips"] == result["right_only_ips"] == 0


def test_unreadable_csv_error_does_not_echo_content(tmp_path):
    path = tmp_path / "private.csv"
    path.write_bytes(b"Message\nprivate-record\xff\n")
    with pytest.raises(DatasetLoadError) as error:
        load_csv(path)
    assert "private-record" not in str(error.value)


def test_declared_selector_is_expected_column():
    result = validate_frame(frame({"Other": ["x"]}), {"content_column": "Message"})
    assert result["missing_columns"] == ["Message"]
