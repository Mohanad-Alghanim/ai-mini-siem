"""Inspect a reviewed feature contract; never train, infer or open a database."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from mini_siem.ingestion.ssh_events import COLUMNS, PARSER_VERSION, load_events
from mini_siem.ml.features import FEATURES, load_features
from mini_siem.preprocessing.ssh_features import SEMANTICS, aggregate_features
from mini_siem.ssh_logs import check_output_paths


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "config/ssh_feature_contract.json"


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate contract keys")
        result[key] = value
    return result


def read_contract(path):
    def reject_constant(value):
        raise ValueError("Nonfinite JSON constant")
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates, parse_constant=reject_constant)


def contract_digest(contract):
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_contract(contract, *, root=ROOT):
    """Fail closed on any semantic/order/schema change or implementation drift.

    The reviewed checkout/reference is the trust root, not a signature. This is
    a TASK-008 diagnostic, not a guard added to existing training/inference APIs.
    """
    reference = read_contract(REFERENCE)
    errors = []
    if contract_digest(contract) != contract_digest(reference):
        return ["Contract differs from the reviewed specification; independent review/versioning required"]
    if contract["parser_version"] != PARSER_VERSION or contract["feature_semantics_version"] != SEMANTICS:
        errors.append("Runtime parser/feature version drift")
    if contract["feature_order"] != list(FEATURES) or contract["input"]["required_columns"] != list(COLUMNS):
        errors.append("Runtime ordered schema drift")
    root = Path(root).resolve()
    for relative, expected in contract["implementation"]["source_sha256"].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append(f"Implementation fingerprint mismatch: {relative}")
    return errors


def readiness(contract, *, events_path=None, baseline_path=None):
    errors = validate_contract(contract)
    provenance = {}
    if not errors and events_path is not None:
        events, digest = load_events(events_path)
        features = aggregate_features(events)
        provenance["events"] = {"sha256": digest, "records": len(events),
                                "supported_peer_events": sum(event["SourceIP"] is not None for event in events),
                                "generated_ip_records": len(features),
                                "note": "Inspection only; generated features are not exported or passed to a model"}
    if not errors and baseline_path is not None:
        content = Path(baseline_path).read_bytes()
        with tempfile.TemporaryDirectory(prefix="ssh-contract-baseline-") as folder:
            snapshot = Path(folder) / "baseline.csv"
            snapshot.write_bytes(content)
            frame = load_features(snapshot)
        provenance["legacy_baseline"] = {"sha256": hashlib.sha256(content).hexdigest(), "records": len(frame),
                                        "generation_provenance": "not_established_by_schema_validation"}
    return {"contract_id": contract.get("contract_id") if isinstance(contract, dict) else None,
            "contract_sha256": contract_digest(contract), "contract_valid": not errors, "validation_errors": errors,
            "input_inspection": provenance,
            "legacy_feature_compatibility": "not_demonstrated",
            "training_allowed": False, "inference_allowed": False, "deployment_allowed": False,
            "readiness": "blocked_pending_provenance_data_evaluation_and_review",
            "blockers": ["Legacy producer semantics and actual model training provenance are unverified",
                         "Thirty IP aggregates are insufficient to establish generalization",
                         "Version-enforcing model integration and adequate independent data/evaluation are a future design, not implemented authorization"],
            "limitations": ["Contract validity/fingerprints establish consistency checks, not scientific validity or model readiness",
                            "No independent provenance attestation, model artifact inspection, or private run manifest is created here",
                            "No training, prediction, SQLite access, alert changes or compatibility override"]}


def markdown(report):
    lines = ["# SSH feature-contract readiness", "", "**Training, inference and deployment remain blocked.**", "",
             f"Contract valid: {report['contract_valid']}", f"Contract digest: {report['contract_sha256']}", "",
             "## Validation errors", ""]
    lines += [f"- {error}" for error in report["validation_errors"]] or ["No contract/runtime consistency errors detected."]
    lines += ["", "## Local input inspection", "", "```json", json.dumps(report["input_inspection"], indent=2), "```", "", "## Blockers", ""]
    lines += [f"- {value}" for value in report["blockers"]]
    lines += ["", "## Limitations", ""] + [f"- {value}" for value in report["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=REFERENCE)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        outputs = [args.output_dir / "readiness.json", args.output_dir / "readiness.md"] if args.output_dir else []
        check_output_paths(outputs, [path for path in (args.contract, args.events, args.baseline) if path is not None])
        report = readiness(read_contract(args.contract), events_path=args.events, baseline_path=args.baseline)
        if outputs:
            serialized, rendered = json.dumps(report, indent=2, allow_nan=False) + "\n", markdown(report)
            args.output_dir.mkdir(parents=True, exist_ok=True)
            outputs[0].write_text(serialized, encoding="utf-8")
            outputs[1].write_text(rendered, encoding="utf-8")
        print(json.dumps(report))
        return 0 if report["contract_valid"] else 1
    except (OSError, ValueError, TypeError) as exc:
        print(f"Contract inspection failed ({type(exc).__name__}); check specification, local inputs and fresh output paths.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
