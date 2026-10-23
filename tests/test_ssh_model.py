"""Synthetic-only tests for the educational SSH anomaly engine."""

import hashlib
import json
from unittest.mock import patch

import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from mini_siem.ml.__main__ import main
from mini_siem.ml.features import FEATURES, load_features, prepare_features
from mini_siem.ml.model import (
    load_model, predict_records, prediction_counts, save_model, train_model,
)


@pytest.fixture
def baseline():
    records = []
    for i in range(30):
        events = 20 + i % 7 if i < 29 else 2000
        failed = i % 3 if i < 29 else 1800
        records.append({"SourceIP": f"192.0.2.{i + 1}", "EventCount": events,
                        "UniqueEventTypes": 2 + i % 3, "FailedAuthCount": failed,
                        "InvalidUserCount": 0 if i < 29 else 900,
                        "FailedAuthRate": failed / events})
    return pd.DataFrame(records)


@pytest.fixture
def fitted(baseline):
    return train_model(baseline)


def test_load_features_and_no_input_mutation(baseline, tmp_path):
    path = tmp_path / "baseline.csv"
    baseline.to_csv(path, index=False)
    before = hashlib.sha256(path.read_bytes()).digest()
    loaded = load_features(path)
    identifiers, features = prepare_features(loaded)
    assert list(features) == list(FEATURES)
    assert identifiers.tolist() == baseline.SourceIP.tolist()
    assert all(pd.api.types.is_numeric_dtype(dtype) for dtype in features.dtypes)
    assert hashlib.sha256(path.read_bytes()).digest() == before


@pytest.mark.parametrize("column", ["SourceIP", *FEATURES])
def test_missing_required_column(baseline, column):
    with pytest.raises(ValueError, match="missing"):
        train_model(baseline.drop(columns=column))


@pytest.mark.parametrize("column,value", [
    ("EventCount", None), ("EventCount", ""), ("EventCount", " "),
    ("EventCount", "not-a-number"), ("EventCount", float("inf")),
    ("EventCount", float("nan")), ("EventCount", -1),
    ("EventCount", 0.5), ("EventCount", True),
    ("UniqueEventTypes", -1), ("FailedAuthCount", -1), ("InvalidUserCount", -1),
    ("FailedAuthRate", -0.01), ("FailedAuthRate", 1.01),
    ("FailedAuthRate", float("-inf")), ("FailedAuthRate", "NaN"),
    ("EventCount", 1e40), ("SourceIP", "invalid"), ("SourceIP", None),
])
def test_invalid_training_and_inference_values(baseline, fitted, column, value):
    bad = baseline.astype(object)
    bad.loc[0, column] = value
    with pytest.raises(ValueError):
        train_model(bad)
    with pytest.raises(ValueError):
        predict_records(fitted, bad)


def test_prediction_schema_scores_and_status(baseline, fitted):
    original = baseline.copy(deep=True)
    results = predict_records(fitted, baseline)
    assert list(results) == ["SourceIP", "AnomalyLabel", "AnomalyStatus", "AnomalyScore"]
    assert results.SourceIP.tolist() == baseline.SourceIP.tolist()
    assert set(results.AnomalyLabel) <= {-1, 1}
    assert results.AnomalyStatus.tolist() == ["Anomaly" if label == -1 else "Normal" for label in results.AnomalyLabel]
    assert (results.AnomalyScore.lt(0) == results.AnomalyLabel.eq(-1)).all()
    assert results.AnomalyScore.tolist() == fitted.decision_function(prepare_features(baseline)[1]).tolist()
    counts = prediction_counts(results)
    assert counts["records"] == counts["Normal"] + counts["Anomaly"] == 30
    assert counts["Anomaly"] > 0
    assert_frame_equal(baseline, original)


def test_persistence_round_trip(baseline, fitted, tmp_path):
    path = tmp_path / "models/ssh.joblib"
    save_model(fitted, path)
    restored = load_model(path, trusted=True)
    assert_frame_equal(predict_records(fitted, baseline), predict_records(restored, baseline))


def test_untrusted_artifact_not_deserialized(tmp_path):
    with patch("mini_siem.ml.model.joblib.load") as loader:
        with pytest.raises(ValueError, match="untrusted"):
            load_model(tmp_path / "unknown.joblib")
        loader.assert_not_called()


def test_fixed_seed_reproducibility(baseline, fitted):
    assert_frame_equal(predict_records(fitted, baseline), predict_records(train_model(baseline, random_state=42), baseline))


def test_no_feature_leakage(baseline, fitted):
    contaminated = baseline.copy()
    for column in ("AnomalyLabel", "AnomalyStatus", "AnomalyScore", "RiskScore", "RiskLevel"):
        contaminated[column] = [f"unused-{i}" for i in range(30)]
    contaminated.SourceIP = [f"198.51.100.{i + 1}" for i in range(30)]
    # Reversed input order must not change model feature order.
    contaminated = contaminated.loc[:, list(contaminated.columns)[::-1]]
    other = train_model(contaminated)
    assert list(other.feature_names_in_) == list(FEATURES)
    assert other.named_steps["forest"].n_features_in_ == 5
    expected = predict_records(fitted, baseline).drop(columns="SourceIP")
    assert_frame_equal(expected, predict_records(other, contaminated).drop(columns="SourceIP"))
    assert_frame_equal(expected, predict_records(fitted, contaminated).drop(columns="SourceIP"))


def test_inference_never_refits(baseline, fitted):
    with patch.object(fitted, "fit", side_effect=AssertionError("Inference refit")), patch.object(fitted.named_steps["features"], "fit_transform", side_effect=AssertionError("Preprocessing refit")):
        results = predict_records(fitted, baseline.iloc[:2])
    assert len(results) == 2


@pytest.mark.parametrize("value", [0, -0.1, 0.6, float("nan"), float("inf"), True])
def test_invalid_contamination(baseline, value):
    with pytest.raises(ValueError, match="contamination"):
        train_model(baseline, contamination=value)


def test_nondefault_contamination_and_seed(baseline):
    model = train_model(baseline, contamination=0.2, random_state=7)
    assert model.named_steps["forest"].contamination == 0.2
    assert model.named_steps["forest"].random_state == 7


def test_empty_and_single_record_inputs(baseline, fitted):
    with pytest.raises(ValueError):
        train_model(baseline.iloc[:0])
    with pytest.raises(ValueError):
        train_model(baseline.iloc[:1])
    with pytest.raises(ValueError):
        predict_records(fitted, baseline.iloc[:0])
    assert len(predict_records(fitted, baseline.iloc[:1])) == 1


def test_missing_inference_column(baseline, fitted):
    with pytest.raises(ValueError):
        predict_records(fitted, baseline.drop(columns="FailedAuthRate"))


def test_duplicate_headers_rejected(baseline):
    bad = baseline.copy()
    bad.columns = ["SourceIP"] * len(bad.columns)
    with pytest.raises(ValueError):
        prepare_features(bad)


def test_cli_train_reload_csv_json_and_input_preservation(baseline, tmp_path, capsys):
    source, model = tmp_path / "input.csv", tmp_path / "ssh.joblib"
    csv_out, json_out = tmp_path / "predictions.csv", tmp_path / "predictions.json"
    baseline.to_csv(source, index=False)
    original = source.read_bytes()
    assert main(["train", "--input", str(source), "--model", str(model), "--output", str(csv_out)]) == 0
    counts = json.loads(capsys.readouterr().out)
    assert counts["Normal"] + counts["Anomaly"] == 30
    model_bytes = model.read_bytes()
    assert main(["predict", "--input", str(source), "--model", str(model), "--trust-model", "--output", str(json_out)]) == 0
    a, b = pd.read_csv(csv_out), pd.read_json(json_out)
    assert_frame_equal(a, b, check_exact=False, atol=1e-14)
    assert source.read_bytes() == original
    assert model.read_bytes() == model_bytes
    assert main(["predict", "--input", str(source), "--model", str(model), "--output", str(tmp_path / "untrusted-output.json")]) == 2


def test_cli_rejects_input_output_collision(baseline, tmp_path):
    source = tmp_path / "input.csv"
    baseline.to_csv(source, index=False)
    original = source.read_bytes()
    assert main(["train", "--input", str(source), "--model", str(source)]) == 2
    assert main(["train", "--input", str(source), "--model", str(tmp_path / "model.joblib"), "--output", str(source)]) == 2
    assert source.read_bytes() == original


def test_cli_rejects_bad_export_extension_before_saving(baseline, tmp_path):
    source, model = tmp_path / "input.csv", tmp_path / "model.joblib"
    baseline.to_csv(source, index=False)
    assert main(["train", "--input", str(source), "--model", str(model), "--output", str(tmp_path / "bad.txt")]) == 2
    assert not model.exists()


def test_incompatible_artifact_rejected(fitted, tmp_path):
    import joblib
    path = tmp_path / "model.joblib"
    save_model(fitted, path)
    artifact = joblib.load(path)  # trusted synthetic artifact created in this test
    artifact["sklearn_version"] = "incompatible"
    joblib.dump(artifact, path)
    with pytest.raises(ValueError, match="version"):
        load_model(path, trusted=True)


def test_cli_will_not_overwrite_existing_outputs(baseline, tmp_path):
    source, model, output = tmp_path / "input.csv", tmp_path / "model.joblib", tmp_path / "existing.csv"
    baseline.to_csv(source, index=False)
    output.write_text("keep this file")
    assert main(["train", "--input", str(source), "--model", str(model), "--output", str(output)]) == 2
    assert output.read_text() == "keep this file"
    assert not model.exists()


def test_cli_symlink_collision_rejected(baseline, tmp_path):
    source, alias = tmp_path / "input.csv", tmp_path / "alias.joblib"
    baseline.to_csv(source, index=False)
    before = source.read_bytes()
    alias.symlink_to(source)
    assert main(["train", "--input", str(source), "--model", str(alias)]) == 2
    assert source.read_bytes() == before


def test_corrupt_local_artifact_is_reported_cleanly(baseline, tmp_path, capsys):
    source, artifact = tmp_path / "input.csv", tmp_path / "corrupt.joblib"
    baseline.to_csv(source, index=False)
    artifact.write_bytes(b"not a joblib artifact")
    assert main(["predict", "--input", str(source), "--model", str(artifact), "--trust-model", "--output", str(tmp_path / "out.csv")]) == 2
    assert "Model command failed" in capsys.readouterr().out
