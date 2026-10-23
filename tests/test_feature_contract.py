"""Synthetic-only contract checks; no model or database operations."""

from copy import deepcopy
import hashlib
import json
import shutil
from unittest.mock import patch

import pandas as pd
import pytest

from mini_siem.feature_contract import REFERENCE, ROOT, contract_digest, main, read_contract, readiness, validate_contract


@pytest.fixture
def contract():
    return read_contract(REFERENCE)


def test_reviewed_contract_matches_runtime_and_stays_blocked(contract):
    assert validate_contract(contract) == []
    report = readiness(contract)
    assert report["contract_valid"]
    assert report["input_inspection"] == {}
    assert not any(report[key] for key in ("training_allowed", "inference_allowed", "deployment_allowed"))
    assert report["legacy_feature_compatibility"] == "not_demonstrated"


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(parser_version="different"),
    lambda c: c.update(feature_semantics_version="different"),
    lambda c: c["feature_order"].reverse(),
    lambda c: c["features"][0].update(type="number"),
    lambda c: c["features"][2].update(formula="count all failed words"),
    lambda c: c["aggregation"].update(window="one hour"),
    lambda c: c["source_ip"].update(missing_or_ambiguous="fill missing"),
    lambda c: c["preprocessing"].update(scaling="fit on all records"),
    lambda c: c["task_008"].update(inference_allowed=True),
    lambda c: c.update(extra_field="ignore me"),
    lambda c: c["features"][0].update(min=False),
])
def test_contract_drift_fails_closed(contract, mutate):
    mutate(contract)
    assert validate_contract(contract)
    report = readiness(contract)
    assert not report["contract_valid"]
    assert not report["inference_allowed"]


def test_runtime_order_and_version_drift(contract):
    with patch("mini_siem.feature_contract.PARSER_VERSION", "unreviewed"):
        assert "Runtime parser/feature version drift" in validate_contract(contract)
    with patch("mini_siem.feature_contract.FEATURES", ("FailedAuthRate",)):
        assert "Runtime ordered schema drift" in validate_contract(contract)


def test_fingerprints_reject_changed_implementation_even_same_version(contract, tmp_path):
    for relative in contract["implementation"]["source_sha256"]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    assert validate_contract(contract, root=tmp_path) == []
    target = tmp_path / "mini_siem/ingestion/ssh_events.py"
    target.write_text(target.read_text() + "\n# accidental drift\n")
    assert any("Implementation fingerprint mismatch" in error for error in validate_contract(contract, root=tmp_path))


def test_missing_or_escaping_implementation_fails(contract, tmp_path):
    assert validate_contract(contract, root=tmp_path)
    target = tmp_path / "mini_siem/ingestion/csv_loader.py"
    target.parent.mkdir(parents=True)
    target.symlink_to(ROOT / "mini_siem/ingestion/csv_loader.py")
    assert any("csv_loader.py" in error for error in validate_contract(contract, root=tmp_path))


def test_canonical_digest_ignores_json_formatting(contract, tmp_path):
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract, sort_keys=True))
    assert contract_digest(read_contract(path)) == contract_digest(contract)
    assert validate_contract(read_contract(path)) == []


@pytest.mark.parametrize("text", ['{"key": 1, "key": 2}', '{"bad": NaN}', 'not json'])
def test_invalid_json_rejected(text, tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        read_contract(path)
    assert main(["--contract", str(path)]) == 2


def test_optional_synthetic_inputs_report_hashes_without_privacy_leak(contract, tmp_path, capsys):
    events = tmp_path / "private-events.csv"
    baseline = tmp_path / "private-baseline.csv"
    pd.DataFrame([{"LineId": "1", "Date": "Jun", "Day": "1", "Time": "12:00:00", "Component": "sshd", "Pid": "123", "Content": "Failed password for invalid user private-name from 192.0.2.1 port 22", "EventId": "E1", "EventTemplate": "private template"}]).to_csv(events, index=False)
    pd.DataFrame([{"SourceIP": "192.0.2.1", "EventCount": 1, "UniqueEventTypes": 1, "FailedAuthCount": 1, "InvalidUserCount": 1, "FailedAuthRate": 1}]).to_csv(baseline, index=False)
    before = {path: path.read_bytes() for path in (events, baseline)}
    with patch("sqlite3.connect", side_effect=AssertionError("No database access")), patch("mini_siem.ml.model.load_model", side_effect=AssertionError("No artifact loading")), patch("mini_siem.ml.model.train_model", side_effect=AssertionError("No training")), patch("mini_siem.ml.model.predict_records", side_effect=AssertionError("No inference")):
        assert main(["--events", str(events), "--baseline", str(baseline), "--output-dir", str(tmp_path / "reports")]) == 0
    report = json.loads((tmp_path / "reports/readiness.json").read_text())
    assert report["input_inspection"]["events"]["records"] == 1
    assert report["input_inspection"]["events"]["sha256"] == hashlib.sha256(before[events]).hexdigest()
    assert report["input_inspection"]["legacy_baseline"]["sha256"] == hashlib.sha256(before[baseline]).hexdigest()
    assert before == {path: path.read_bytes() for path in before}
    text = capsys.readouterr().out + (tmp_path / "reports/readiness.md").read_text()
    for secret in ("192.0.2.1", "private-name", "private template", "private-events.csv"):
        assert secret not in text
    assert not report["training_allowed"] and not report["inference_allowed"]


def test_invalid_contract_never_reads_optional_inputs(contract, tmp_path):
    contract["feature_order"].reverse()
    with patch("mini_siem.feature_contract.load_events", side_effect=AssertionError("Must fail closed")):
        report = readiness(contract, events_path=tmp_path / "missing.csv")
    assert not report["contract_valid"] and report["input_inspection"] == {}


def test_cli_invalid_contract_returns_one_and_blocked_report(contract, tmp_path, capsys):
    contract["feature_order"].reverse()
    path = tmp_path / "changed.json"
    path.write_text(json.dumps(contract))
    assert main(["--contract", str(path), "--output-dir", str(tmp_path / "review")]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["validation_errors"] and not report["inference_allowed"]


def test_reports_refuse_overwrite_or_input_collision(tmp_path):
    output = tmp_path / "report"
    assert main(["--output-dir", str(output)]) == 0
    before = (output / "readiness.json").read_bytes()
    assert main(["--output-dir", str(output)]) == 2
    assert (output / "readiness.json").read_bytes() == before
    target = tmp_path / "readiness.json"
    target.write_bytes(REFERENCE.read_bytes())
    assert main(["--contract", str(target), "--output-dir", str(tmp_path)]) == 2
    assert target.read_bytes() == REFERENCE.read_bytes()


def test_incompatible_contract_shape_is_not_authorized(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[]")
    assert main(["--contract", str(path)]) == 1
