"""Versioned IP aggregation and cautious baseline comparison, never inference."""

from collections import Counter
from ipaddress import ip_address

import pandas as pd

from mini_siem.ml.features import FEATURES, load_features, prepare_features
from mini_siem.ingestion.ssh_events import PARSER_VERSION


SEMANTICS = "ssh-observed-peer-features-v1"


def aggregate_features(events):
    groups = {}
    for event in events:
        if event["SourceIP"] is not None:
            groups.setdefault(event["SourceIP"], []).append(event)
    rows = []
    for ip, records in sorted(groups.items()):
        failed = sum(record["FailedAuth"] for record in records)
        rows.append({"SourceIP": ip, "EventCount": len(records),
                     "UniqueEventTypes": len({record["EventType"] for record in records}),
                     "FailedAuthCount": failed,
                     "InvalidUserCount": sum(record["InvalidUser"] for record in records),
                     "FailedAuthRate": failed / len(records)})
    return pd.DataFrame(rows, columns=["SourceIP", *FEATURES])


def compare_baseline(generated, baseline_path):
    baseline = load_features(baseline_path)
    ids, numeric = prepare_features(baseline)
    baseline = numeric.copy()
    baseline.index = ids.map(lambda value: str(ip_address(value)))
    generated = generated.copy().set_index("SourceIP")
    duplicates = int(baseline.index.duplicated(keep=False).sum())
    # Duplicate baseline keys have no unambiguous feature vector.
    unique = baseline.loc[~baseline.index.duplicated(keep=False)]
    shared = sorted(set(generated.index) & set(baseline.index))
    differences = []
    for ip in sorted(set(generated.index) & set(unique.index)):
        changes = {}
        for feature in FEATURES:
            a, b = float(generated.loc[ip, feature]), float(unique.loc[ip, feature])
            # Rates only: tolerate CSV floating point roundoff, not semantic gaps.
            same = abs(a - b) <= 1e-12 if feature == "FailedAuthRate" else a == b
            if not same:
                changes[feature] = {"generated": a, "baseline": b}
        if changes:
            differences.append({"SourceIP": ip, "differences": changes})
    return {"baseline_records": len(baseline), "expected_baseline_records": 30,
            "expected_baseline_row_count_matches": len(baseline) == 30, "matching_source_ips": len(shared), "baseline_ips_without_generated_features": sorted(set(baseline.index) - set(generated.index)),
            "generated_ips_not_in_baseline": sorted(set(generated.index) - set(baseline.index)),
            "ambiguous_baseline_rows": duplicates, "feature_differences": differences,
            "numerical_match": not duplicates and not differences and set(generated.index) == set(baseline.index)}


def analysis_report(events, features, source_hash, comparison=None):
    statuses = Counter(event["ParseStatus"] for event in events)
    supported = statuses["supported_peer"]
    unsupported = Counter((event["ParseStatus"], event["Original"]["EventId"] or "[template-only]")
                          for event in events if event["ParseStatus"] != "supported_peer")
    return {"parser_version": PARSER_VERSION, "feature_semantics": SEMANTICS,
            "source_sha256": source_hash, "events": len(events), "expected_events": 2000,
            "expected_row_count_matches": len(events) == 2000,
            "events_with_source_ip": supported, "events_without_source_ip": len(events) - supported,
            "ip_extraction_coverage": supported / len(events) if events else 0,
            "parse_status_counts": dict(statuses), "generated_ip_records": len(features),
            "indicator_counts": {key: sum(event[key] for event in events) for key in ("FailedAuth", "InvalidUser", "AcceptedAuth", "AuthAmbiguous")},
            "duplicate_original_line_ids": len(events) - len({event["Original"]["LineId"] for event in events}),
            "unsupported_patterns": [{"parse_status": status, "original_event_id": event_id, "records": count}
                                     for (status, event_id), count in sorted(unsupported.items())],
            "baseline_comparison": comparison,
            "model_compatibility": {"inference_allowed": False, "status": "not_demonstrated",
                                    "reason": "Original training feature definitions/window are unverified. Numeric agreement alone does not establish semantic compatibility."},
            "limitations": ["No timestamp year or aggregation window inferred; features describe the supplied file only.",
                            "Missing/ambiguous/unsupported IP records remain in event storage but do not contribute to IP-level features.",
                            "Textual indicators are observable hints, not verified attacks or authentication outcomes.",
                            "Prior coverage findings (1145/2000 events and 27/30 baseline IPs) are external findings to investigate, not targets or results of this run."]}


def require_model_compatibility(report):
    """No automatic inference route is offered until independent semantic review."""
    raise ValueError("Generated feature compatibility is not demonstrated; export for review, do not invoke the existing model")
