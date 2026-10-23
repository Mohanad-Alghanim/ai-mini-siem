"""Synthetic diagnostic evidence; no private dataset or model use."""

import hashlib
import json
from unittest.mock import patch

import pandas as pd
import pytest

from mini_siem.feature_compatibility import main, markdown
from mini_siem.ingestion.ssh_events import load_events
from mini_siem.preprocessing.compatibility import diagnose
from mini_siem.preprocessing.ssh_features import aggregate_features


@pytest.fixture
def inputs(tmp_path):
    messages = ["Failed password for invalid user test from 192.0.2.1 port 22",
                "Accepted password for test from 192.0.2.1 port 22",
                "Failed reverse mapping from 192.0.2.1", "peer [192.0.2.1] unsupported format",
                "from 192.0.2.1 from 192.0.2.2", "from bad-host",
                "authentication failure; rhost=192.0.2.2", "No IP here"]
    frame = pd.DataFrame([{"LineId": str(i+1), "Date": "Jun", "Day": "1", "Time": "12:00:00", "Component": "sshd", "Pid": "100", "Content": text, "EventId": "E1" if i < 3 else "E2", "EventTemplate": f"private template-{i % 2}"} for i, text in enumerate(messages)])
    events = tmp_path / "events.csv"
    frame.to_csv(events, index=False)
    parsed, _ = load_events(events)
    baseline = tmp_path / "baseline.csv"
    aggregate_features(parsed).to_csv(baseline, index=False)
    return events, baseline


def test_equal_numbers_still_block_inference(inputs):
    report = diagnose(*inputs)
    assert report["comparison"]["numerical_match"]
    assert report["parser_version"] == "ssh-historical-v2"
    assert report["compatibility"]["decision"] == "not_demonstrated"
    assert not report["compatibility"]["inference_allowed"]
    assert all(row["generated_rate_check"]["agrees_with_ratio"] for row in report["per_source_ip"])


def test_coverage_and_non_attributed_candidates(inputs):
    report = diagnose(*inputs)
    assert report["coverage"]["total_events"] == 8
    assert report["coverage"]["supported_events"] == 4
    assert report["coverage"]["unassigned_events"] == 4
    assert report["coverage"]["parse_status_counts"] == {"supported_peer": 4, "unsupported_ip_context": 1, "ambiguous_peer": 1, "invalid_peer": 1, "no_ip_evidence": 1}
    row = report["per_source_ip"][0]
    assert row["features"]["EventCount"]["generated"] == 3
    assert len(row["generated_evidence"]["unassigned_candidate_records"]) == 2


def test_per_feature_deltas_and_unresolved_causes(inputs):
    frame = pd.read_csv(inputs[1])
    frame.loc[0, ["EventCount", "UniqueEventTypes", "FailedAuthCount", "InvalidUserCount", "FailedAuthRate"]] = [4, 2, 2, 2, .5]
    frame.to_csv(inputs[1], index=False)
    report = diagnose(*inputs)
    row = report["per_source_ip"][0]
    assert all(row["features"][feature]["matches"] is False for feature in row["features"])
    assert row["features"]["EventCount"]["delta_generated_minus_baseline"] == -1
    assert all(item["cause"] == "unresolved" for item in row["features"].values())
    assert all(item["differing_ips"] == 1 for item in report["feature_summary"].values())
    assert row["hypotheses"]
    assert all(item["classification"] == "hypothesis_only" for item in row["hypotheses"])


def test_overlap_type_definitions_and_excluded_failed_word(inputs):
    row = diagnose(*inputs)["per_source_ip"][0]
    evidence = row["generated_evidence"]
    assert len(evidence["failure_records"]) == len(evidence["invalid_user_records"]) == 1
    assert len(evidence["failure_invalid_overlap_records"]) == 1
    assert evidence["failure_invalid_union_count"] == 1
    assert evidence["unique_nonblank_event_ids"] == 1
    assert evidence["unique_nonblank_templates"] == 2
    assert len(evidence["derived_event_type_groups"]) == 1
    assert len(evidence["broad_failed_word_excluded_records"]) == 1
    assert len(evidence["accepted_records"]) == 1


def test_baseline_rate_arithmetic_is_evidence_not_cause(inputs):
    frame = pd.read_csv(inputs[1])
    frame.loc[0, "FailedAuthRate"] = .9
    frame.to_csv(inputs[1], index=False)
    row = diagnose(*inputs)["per_source_ip"][0]
    assert not row["baseline_rate_check"]["agrees_with_ratio"]
    assert any("differs from baseline" in finding for finding in row["confirmed_findings"])
    assert row["features"]["FailedAuthRate"]["cause"] == "unresolved"


def test_zero_denominator_is_not_invented(inputs):
    frame = pd.read_csv(inputs[1])
    frame.loc[0, ["EventCount", "FailedAuthCount", "FailedAuthRate"]] = [0, 0, 0]
    frame.to_csv(inputs[1], index=False)
    assert diagnose(*inputs)["per_source_ip"][0]["baseline_rate_check"]["status"] == "zero_denominator"


def test_missing_unmatched_and_duplicate_ips(inputs):
    frame = pd.read_csv(inputs[1])
    frame.loc[1, "SourceIP"] = "198.51.100.1"
    frame = pd.concat([frame, frame.iloc[:1]])
    frame.to_csv(inputs[1], index=False)
    report = diagnose(*inputs)
    rows = {row["SourceIP"]: row for row in report["per_source_ip"]}
    assert rows["192.0.2.1"]["baseline_ambiguous"]
    assert rows["192.0.2.1"]["features"]["EventCount"]["baseline"] is None
    assert rows["192.0.2.2"]["presence"] == "generated_only"
    assert rows["198.51.100.1"]["presence"] == "baseline_only"


def test_reports_omit_raw_messages_and_templates(inputs):
    report = diagnose(*inputs)
    text = json.dumps(report) + markdown(report)
    assert "Failed password for invalid user test" not in text
    assert "private template" not in text
    assert "not_demonstrated" in text
    assert "Hypotheses" in text
    assert "Traceable evidence" in text


def test_cli_snapshots_unchanged_and_no_model_or_db_access(inputs, tmp_path, capsys):
    before = [hashlib.sha256(path.read_bytes()).digest() for path in inputs]
    args = ["--events", str(inputs[0]), "--baseline", str(inputs[1]), "--output-dir", str(tmp_path / "review")]
    with patch("mini_siem.ml.model.load_model", side_effect=AssertionError("Forbidden")), patch("mini_siem.ml.model.predict_records", side_effect=AssertionError("Forbidden")), patch("mini_siem.storage.sqlite.connect_database", side_effect=AssertionError("Forbidden")):
        assert main(args) == 0
    stdout = capsys.readouterr().out
    assert "192.0.2" not in stdout
    report = json.loads((tmp_path / "review/diagnostics.json").read_text())
    assert report["baseline_sha256"] == hashlib.sha256(inputs[1].read_bytes()).hexdigest()
    assert not report["compatibility"]["inference_allowed"]
    assert before == [hashlib.sha256(path.read_bytes()).digest() for path in inputs]
    assert main(args) == 2  # refuse overwrite


def test_invalid_inputs_produce_no_reports(inputs, tmp_path):
    pd.DataFrame({"wrong": [1]}).to_csv(inputs[1], index=False)
    output = tmp_path / "invalid"
    assert main(["--events", str(inputs[0]), "--baseline", str(inputs[1]), "--output-dir", str(output)]) == 2
    assert not output.exists()


def test_output_collision_does_not_overwrite_baseline(inputs):
    target = inputs[1].with_name("diagnostics.json")
    target.write_bytes(inputs[1].read_bytes())
    before = target.read_bytes()
    assert main(["--events", str(inputs[0]), "--baseline", str(target), "--output-dir", str(target.parent)]) == 2
    assert target.read_bytes() == before


def test_rate_gap_arithmetic_explains_math_without_producer_cause(inputs):
    frame = pd.read_csv(inputs[1])
    frame.loc[0, ["EventCount", "FailedAuthCount", "FailedAuthRate"]] = [4, 2, .5]
    frame.to_csv(inputs[1], index=False)
    evidence = diagnose(*inputs)["per_source_ip"][0]["rate_gap_explanation"]
    assert evidence["status"] == "arithmetic_explanation"
    assert evidence["numerator_effect_at_baseline_denominator"] == -.25
    assert abs(evidence["roundoff_residual"]) < 1e-12
    assert "remains unresolved" in evidence["interpretation"]


def test_invalid_and_unsupported_context_evidence(inputs):
    coverage = diagnose(*inputs)["coverage"]
    records = {row["source_record"]: row for row in coverage["unassigned_context_evidence"]}
    assert records[6]["peer_contexts"] == [{"context": "from", "token_category": "invalid_or_unsupported_token"}]
    assert records[5]["peer_contexts"] == [{"context": "from", "token_category": "valid_ipv4"}] * 2
    assert records[4]["literal_address_candidates"] == 1
    assert records[4]["peer_contexts"] == []


def test_no_assigned_ips_does_not_fabricate_feature_values(inputs):
    frame = pd.read_csv(inputs[0])
    frame.Content = "unsupported context only"
    frame.to_csv(inputs[0], index=False)
    report = diagnose(*inputs)
    assert report["coverage"]["supported_events"] == 0
    assert all(row["presence"] == "baseline_only" for row in report["per_source_ip"])
    assert all(row["features"]["EventCount"]["generated"] is None for row in report["per_source_ip"])
