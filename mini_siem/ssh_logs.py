"""Historical SSH inspection/features/storage; deliberately no AI inference route."""

import argparse
import json
from pathlib import Path
import sqlite3

from mini_siem.ingestion.ssh_events import load_events
from mini_siem.preprocessing.ssh_features import aggregate_features, analysis_report, compare_baseline
from mini_siem.storage.ssh_events import persist_events, prepare_storage


def markdown_report(report):
    lines = ["# Historical SSH feature review", "", "**Existing-model inference blocked: feature semantics are not demonstrated compatible.**", "",
             f"Events: {report['events']}; with source IP: {report['events_with_source_ip']}; without source IP: {report['events_without_source_ip']}.",
             f"IP extraction coverage: {report['ip_extraction_coverage']:.2%}. Generated IP records: {report['generated_ip_records']}.",
             "", "## Parsing coverage", "", "| Outcome | Records |", "| --- | ---: |"]
    lines += [f"| {status} | {count} |" for status, count in report["parse_status_counts"].items()]
    lines += ["", "## Unsupported pattern groups", "", "```json", json.dumps(report["unsupported_patterns"], indent=2), "```"]
    lines += ["", "## Authentication indicators", ""]
    lines += [f"- {name}: {count}" for name, count in report["indicator_counts"].items()]
    lines += ["", "## Baseline comparison", ""]
    if report["baseline_comparison"] is None:
        lines += ["Not performed: no baseline supplied."]
    else:
        lines += ["Local comparison includes IP identifiers; keep this report private.", "", "```json", json.dumps(report["baseline_comparison"], indent=2), "```"]
    lines += ["", "## Limits", ""] + [f"- {value}" for value in report["limitations"]]
    return "\n".join(lines) + "\n"


def check_output_paths(outputs, inputs):
    resolved = [path.resolve() for path in outputs]
    if len(set(resolved)) != len(resolved) or set(resolved) & {path.resolve() for path in inputs}:
        raise ValueError("Output/input collision")
    if any(path.exists() or path.is_symlink() for path in outputs):
        raise ValueError("Output exists; choose fresh report/feature paths")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="Parse, aggregate, optionally compare and export; never infer")
    inspect.add_argument("--input", type=Path, required=True)
    inspect.add_argument("--baseline", type=Path)
    inspect.add_argument("--features", type=Path, help="Optional feature CSV export")
    inspect.add_argument("--report-dir", type=Path, required=True)
    prepare = commands.add_parser("prepare-storage", help="Explicitly install the optional additive event-details table")
    prepare.add_argument("--database", type=Path, required=True)
    ingest = commands.add_parser("ingest", help="Store all events; extension must already be installed")
    ingest.add_argument("--input", type=Path, required=True)
    ingest.add_argument("--database", type=Path, required=True)
    ingest.add_argument("--batch-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare-storage":
            prepare_storage(args.database)
            result = {"event_storage_prepared": True}
        else:
            if args.command == "ingest" and args.input.resolve() == args.database.resolve():
                raise ValueError("Input and database must differ")
            events, source_hash = load_events(args.input)
            if args.command == "ingest":
                result = persist_events(args.database, events, source_hash, args.batch_id)
            else:
                features = aggregate_features(events)
                comparison = compare_baseline(features, args.baseline) if args.baseline else None
                report = analysis_report(events, features, source_hash, comparison)
                outputs = [args.report_dir / "summary.json", args.report_dir / "analysis.md"]
                if args.features:
                    if args.features.suffix.lower() != ".csv":
                        raise ValueError("Features must be exported as CSV")
                    outputs.append(args.features)
                check_output_paths(outputs, [args.input] + ([args.baseline] if args.baseline else []))
                # Compute every representation before writing. No original CSV writes.
                summary = json.dumps(report, indent=2, allow_nan=False) + "\n"
                markdown = markdown_report(report)
                for output in outputs:
                    output.parent.mkdir(parents=True, exist_ok=True)
                outputs[0].write_text(summary, encoding="utf-8")
                outputs[1].write_text(markdown, encoding="utf-8")
                if args.features:
                    features.to_csv(args.features, index=False)
                result = {key: report[key] for key in ("events", "events_with_source_ip", "events_without_source_ip", "generated_ip_records", "model_compatibility")}
    except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
        print(f"Historical SSH command failed ({type(exc).__name__}); check input columns, paths, batch identity and explicit storage preparation.")
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
