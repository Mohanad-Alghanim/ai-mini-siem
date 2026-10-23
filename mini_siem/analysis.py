"""Run read-only SSH CSV inspection: python -m mini_siem.analysis --help."""

import argparse
import json
import math
from pathlib import Path

from mini_siem.ingestion.csv_loader import DatasetLoadError, load_csv
from mini_siem.preprocessing.relationships import (
    check_predictions, compare_datasets, event_ip_coverage,
)
from mini_siem.preprocessing.validation import analyze_events, validate_frame


DATASETS = {
    "events": ("OpenSSH_2k.log_structured.csv", 2000),
    "baseline": ("ssh_baseline_features.csv", 30),
    "isolation": ("ssh_isolation_results.csv", 30),
    "risk": ("ssh_dynamic_risk_results.csv", 30),
}


def default_config():
    """Minimum named-field contract, not a claim about unseen real CSV headers."""
    config = {
        "datasets": {
            name: {"required": required, "columns": {}, "complete": False}
            for name, required in {
                "events": [], "baseline": ["SourceIP"],
                "isolation": ["SourceIP", "AnomalyLabel", "AnomalyScore"],
                "risk": ["SourceIP", "RiskLevel"],
            }.items()
        },
        "prediction_policy": {},
    }
    for name, schema in config["datasets"].items():
        if name != "events":
            schema["columns"]["SourceIP"] = {"type": "ip"}
    config["datasets"]["isolation"]["columns"].update(AnomalyLabel={"type": "integer"}, AnomalyScore={"type": "number"})
    return config


def read_config(path=None):
    config = default_config() if path is None else json.loads(Path(path).read_text())
    if not isinstance(config, dict) or set(config) - {"datasets", "prediction_policy"}:
        raise ValueError("Invalid configuration keys")
    schemas = config.get("datasets")
    if not isinstance(schemas, dict) or set(schemas) != set(DATASETS):
        raise ValueError("Configuration must declare all four dataset roles")
    for schema in schemas.values():
        if not isinstance(schema, dict) or set(schema) - {"required", "columns", "complete", "source_ip", "content_column", "event_column"}:
            raise ValueError("Invalid dataset schema")
        required = schema.get("required", [])
        if not isinstance(required, list) or not all(isinstance(v, str) for v in required):
            raise ValueError("required must be a list of column names")
        if not isinstance(schema.get("complete", False), bool):
            raise ValueError("complete must be boolean")
        for key in ("source_ip", "content_column", "event_column"):
            if key in schema and not isinstance(schema[key], str):
                raise ValueError("Column selectors must be strings")
        columns = schema.get("columns", {})
        if not isinstance(columns, dict):
            raise ValueError("columns must be an object")
        for column, rule in columns.items():
            if not isinstance(column, str) or not isinstance(rule, dict) or set(rule) - {"type", "min", "max", "allowed"}:
                raise ValueError("Invalid column rule")
            kind = rule.get("type", "string")
            if kind not in ("string", "number", "integer", "ip"):
                raise ValueError("Unsupported column type")
            for bound in ("min", "max"):
                if bound in rule and (kind not in ("number", "integer") or not isinstance(rule[bound], (int, float)) or not math.isfinite(rule[bound])):
                    raise ValueError("Bounds require finite numerical values and a numeric type")
            if rule.get("min", -math.inf) > rule.get("max", math.inf):
                raise ValueError("min exceeds max")
            if "allowed" in rule and (not isinstance(rule["allowed"], list) or not all(isinstance(v, (str, int, float)) for v in rule["allowed"])):
                raise ValueError("allowed must be a list of scalar values")
    policy = config.get("prediction_policy", {})
    if not isinstance(policy, dict) or set(policy) - {"label_status", "score_rule", "risk_by_status"}:
        raise ValueError("Invalid prediction policy")
    for key in ("label_status", "risk_by_status"):
        mapping = policy.get(key, {})
        if not isinstance(mapping, dict):
            raise ValueError("Prediction mappings must be objects")
        for value in mapping.values():
            if key == "label_status" and not isinstance(value, str):
                raise ValueError("Label statuses must be strings")
            if key == "risk_by_status" and (not isinstance(value, list) or not all(isinstance(v, str) for v in value)):
                raise ValueError("Allowed risk levels must be lists of strings")
    if "score_rule" in policy:
        rule = policy["score_rule"]
        if not isinstance(rule, dict) or set(rule) != {"direction", "threshold", "anomaly_label", "normal_label"}:
            raise ValueError("score_rule needs direction, threshold, anomaly_label, normal_label")
        if rule["direction"] not in ("lower", "higher") or not isinstance(rule["threshold"], (int, float)) or not math.isfinite(rule["threshold"]):
            raise ValueError("Invalid score threshold or direction")
        if not all(isinstance(rule[k], (str, int)) for k in ("anomaly_label", "normal_label")):
            raise ValueError("Score labels must be strings or integers")
    return config


def inspect(paths, config):
    """Return JSON-safe counts only. Missing/unreadable datasets do not stop peers."""
    frames, datasets = {}, {}
    for name, (_, expected_rows) in DATASETS.items():
        try:
            frame = load_csv(paths[name])
        except DatasetLoadError as exc:
            datasets[name] = {"status": "unavailable", "reason": str(exc)}
            continue
        frames[name] = frame
        schema = config["datasets"][name]
        quality = validate_frame(frame, schema, expected_rows)
        datasets[name] = {"status": "loaded", "quality": quality,
                          "events": analyze_events(frame, schema),
                          "prediction_checks": check_predictions(frame, config.get("prediction_policy", {}))}
    summary = {
        "report_version": 1,
        "limitations": [
            "Real-data validation is established only for the supplied local files; file names do not prove dataset provenance.",
            "Incomplete schemas leave unknown column/type/range expectations unverified. Unconfigured rules are not passing checks.",
            "Previous predictions and risks are unverified outputs, not ground truth. Score thresholds and risk rules require confirmed conventions.",
            "No timestamp year is inferred. No chronological or time-window checks are performed.",
            "Reports omit IP values and log messages. Review column names before sharing reports.",
        ],
        "datasets": datasets,
        "relationships": compare_datasets(frames, config["datasets"]),
        "event_ip_evidence": event_ip_coverage(frames, config["datasets"]),
    }
    summary["findings"] = collect_findings(summary)
    summary["status"] = "findings" if summary["findings"] else "no_findings_in_executed_checks"
    return summary


def collect_findings(summary):
    findings = []
    for name, dataset in summary["datasets"].items():
        if dataset["status"] != "loaded":
            findings.append(f"{name}: dataset unavailable")
            continue
        quality = dataset["quality"]
        if not quality["schema_complete"]:
            findings.append(f"{name}: complete expected schema not confirmed")
        if not quality["row_count_matches"]:
            findings.append(f"{name}: row count differs from supplied dataset description")
        if quality["missing_columns"]:
            findings.append(f"{name}: expected columns missing")
        if quality["duplicate_rows"] or any(quality["missing_values"].values()):
            findings.append(f"{name}: duplicate rows or missing values")
        if any(any(check.get(key, 0) for key in ("invalid_type", "out_of_range", "invalid_allowed_value")) for check in quality["column_checks"].values()):
            findings.append(f"{name}: invalid types, values, or ranges")
        if quality.get("source_ip", {}).get("invalid") or (name != "events" and quality.get("source_ip", {}).get("duplicate_keys")):
            findings.append(f"{name}: invalid or ambiguous IP keys")
        for check in dataset["prediction_checks"].values():
            if any(check.get(key, 0) for key in ("inconsistent", "unmapped_labels", "unmapped_statuses")):
                findings.append(f"{name}: prediction/risk convention review needed")
                break
    for item in summary["relationships"]:
        if item["status"] == "checked" and item["left"] != "events" and item["right"] != "events":
            if item["left_only_ips"] or item["right_only_ips"] or any(v["different"] for v in item["field_comparisons"].values()):
                findings.append(f"{item['left']}/{item['right']}: IP coverage or output differences require review")
    return findings


def markdown(summary):
    """Render readable Markdown; keep detailed structure in the JSON companion."""
    def safe(value):
        return str(value).replace("\n", " ").replace("\r", " ").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'")

    def details(value, depth=0):
        lines = []
        for key, item in value.items():
            label = safe(key.replace("_", " "))
            if isinstance(item, dict):
                lines.append("  " * depth + f"- {label}:")
                lines.extend(details(item, depth + 1))
            else:
                lines.append("  " * depth + f"- {label}: {safe(item)}")
        return lines

    lines = ["# SSH dataset inspection", "", f"Overall status: **{summary['status']}**", "", "## Findings", ""]
    lines += [f"- {finding}" for finding in summary["findings"]] or ["No findings in executed checks; consult skipped checks and limitations."]
    for name, dataset in summary["datasets"].items():
        lines += ["", f"## {name}", "", f"Status: {dataset['status']}"]
        if dataset["status"] != "loaded":
            lines += [dataset["reason"]]
            continue
        quality = dataset["quality"]
        lines += [f"Rows: {quality['rows']} (expected {quality['expected_rows']}). Duplicate rows: {quality['duplicate_rows']}.",
                  f"Complete schema confirmed: {quality['schema_complete']}. Missing expected columns: {safe(quality['missing_columns'])}.", "",
                  "| Column | Missing | Type/check | Invalid type | Out of range | Invalid category |",
                  "| --- | ---: | --- | ---: | ---: | ---: |"]
        for column, check in quality["column_checks"].items():
            lines.append(f"| {safe(column)} | {quality['missing_values'][column]} | {check.get('type', 'unconfigured')} | {check.get('invalid_type', '—')} | {check.get('out_of_range', '—')} | {check.get('invalid_allowed_value', '—')} |")
        lines += ["", "### Event and prediction checks", ""]
        lines += details({"source_ip": quality.get("source_ip", {"status": "unavailable"}), "events": dataset["events"], "prediction_checks": dataset["prediction_checks"]})
    lines += ["", "## Cross-dataset relationships", ""]
    for item in summary["relationships"]:
        lines += [f"### {item['left']} / {item['right']}", ""] + details(item) + [""]
    lines += ["## Event IP evidence", ""] + details(summary["event_ip_evidence"])
    lines += ["", "## Limitations", ""]
    lines += [f"- {note}" for note in summary["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    for name in DATASETS:
        parser.add_argument(f"--{name}", type=Path, help=f"Override {name} CSV path")
    parser.add_argument("--schema", type=Path, help="JSON schema and prediction policy; see docs/dataset-analysis.md")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    args = parser.parse_args(argv)
    paths = {name: getattr(args, name) or args.data_dir / filename for name, (filename, _) in DATASETS.items()}
    try:
        config = read_config(args.schema)
        outputs = [args.output_dir / "summary.json", args.output_dir / "analysis.md"]
        protected = {path.resolve() for path in paths.values()}
        if args.schema:
            protected.add(args.schema.resolve())
        if any(path.resolve() in protected for path in outputs):
            raise ValueError("Report output would overwrite an input")
        summary = inspect(paths, config)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        outputs[0].write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        outputs[1].write_text(markdown(summary), encoding="utf-8")
    except (OSError, ValueError, TypeError) as exc:
        print(f"Analysis failed ({type(exc).__name__}); check schema, input paths, and output permissions.")
        return 2
    print(f"Analysis completed: {summary['status']}. Reports: summary.json and analysis.md in the output directory.")
    return 1 if summary["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
