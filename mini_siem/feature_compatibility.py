"""Read-only diagnostic command: python -m mini_siem.feature_compatibility --help."""

import argparse
import json
from pathlib import Path

from mini_siem.ml.features import FEATURES
from mini_siem.preprocessing.compatibility import diagnose
from mini_siem.ssh_logs import check_output_paths


def markdown(report):
    lines = ["# SSH feature compatibility investigation", "", "**Decision: NOT DEMONSTRATED. Existing-model inference remains blocked.**", "",
             report["compatibility"]["rationale"], "", "## Measured coverage", ""]
    coverage = report["coverage"]
    lines += [f"- Total events: {coverage['total_events']}", f"- Supported events: {coverage['supported_events']}", f"- Unassigned events: {coverage['unassigned_events']}"]
    lines += [f"- {name}: {count}" for name, count in coverage["parse_status_counts"].items()]
    comparison = report["comparison"]
    lines += [f"- Matching IPs: {comparison['matching_source_ips']}", f"- IPs with feature differences: {len(comparison['feature_differences'])}",
              f"- Numerical match: {comparison['numerical_match']}", "", "## Per-feature differences", "",
              "| Feature | Compared IPs | Differing IPs | Maximum absolute delta |", "| --- | ---: | ---: | ---: |"]
    lines += [f"| {name} | {values['compared_ips']} | {values['differing_ips']} | {values['maximum_absolute_delta']} |" for name, values in report["feature_summary"].items()]
    for section in ("confirmed_findings", "hypotheses", "unresolved", "recommendations", "limitations"):
        lines += ["", f"## {section.replace('_', ' ').title()}", ""]
        lines += [f"- {value}" for value in report[section]]
    lines += ["", "## IP coverage gaps", "", "```json", json.dumps({key: comparison[key] for key in ("baseline_ips_without_generated_features", "generated_ips_not_in_baseline", "ambiguous_baseline_rows")}, indent=2), "```"]
    for row in report["per_source_ip"]:
        lines += ["", f"## SourceIP {row['SourceIP']}", "", f"Presence: {row['presence']}", "",
                  "| Feature | Generated | Baseline | Delta (generated − baseline) | Match | Gap cause |",
                  "| --- | ---: | ---: | ---: | --- | --- |"]
        for feature in FEATURES:
            item = row["features"][feature]
            lines.append(f"| {feature} | {item['generated']} | {item['baseline']} | {item['delta_generated_minus_baseline']} | {item['matches']} | {item['cause']} |")
        for section in ("confirmed_findings", "hypotheses", "unresolved"):
            lines += ["", f"### {section.replace('_', ' ').title()}", ""]
            for value in row[section]:
                lines.append("- " + (value if isinstance(value, str) else json.dumps(value)))
        evidence = row["generated_evidence"]
        lines += ["", "### Traceable evidence", "",
                  f"- Assigned source records: {[ref['source_record'] for ref in evidence['event_records']]}",
                  f"- Failure source records: {[ref['source_record'] for ref in evidence['failure_records']]}",
                  f"- Invalid-user source records: {[ref['source_record'] for ref in evidence['invalid_user_records']]}",
                  f"- Failure/invalid overlap records: {[ref['source_record'] for ref in evidence['failure_invalid_overlap_records']]}",
                  f"- Distinct templates: {evidence['unique_nonblank_templates']}; distinct nonblank EventIds: {evidence['unique_nonblank_event_ids']}",
                  f"- Unassigned address-candidate records (not attributed as peers): {[ref['source_record'] for ref in evidence['unassigned_candidate_records']]}",
                  "- Baseline rate arithmetic: " + json.dumps(row["baseline_rate_check"]),
                  "- Generated rate arithmetic: " + json.dumps(row["generated_rate_check"]),
                  "- Evidence-backed rate decomposition: " + json.dumps(row["rate_gap_explanation"])]
    lines += ["", "Complete event-reference groups, hashed template/type groups, overlaps and excluded broad-word records are in diagnostics.json. No raw messages or template text are exported."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        outputs = [args.output_dir / "diagnostics.json", args.output_dir / "analysis.md"]
        check_output_paths(outputs, [args.events, args.baseline])
        report = diagnose(args.events, args.baseline)
        serialized = json.dumps(report, indent=2, allow_nan=False) + "\n"
        rendered = markdown(report)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        outputs[0].write_text(serialized, encoding="utf-8")
        outputs[1].write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, TypeError) as exc:
        print(f"Compatibility investigation failed ({type(exc).__name__}); check input schemas and fresh output paths.")
        return 2
    print(json.dumps({"total_events": report["coverage"]["total_events"],
                      "supported_events": report["coverage"]["supported_events"],
                      "matching_source_ips": report["comparison"]["matching_source_ips"],
                      "differing_source_ips": len(report["comparison"]["feature_differences"]),
                      "numerical_match": report["comparison"]["numerical_match"],
                      "compatibility": report["compatibility"]}))
    return 0  # completion, never a compatibility approval


if __name__ == "__main__":
    raise SystemExit(main())
