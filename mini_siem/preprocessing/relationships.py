"""Compare IP-level records and optional, explicitly configured prediction rules."""

from itertools import combinations
import re

import pandas as pd

from .validation import canonical_ip, present


FIELDS = ("AnomalyLabel", "AnomalyStatus", "AnomalyScore", "RiskLevel")


def ip_records(frame, schema):
    column = schema.get("source_ip", "SourceIP")
    if column not in frame:
        return None
    keys = frame[column].map(canonical_ip)
    valid = keys.notna()
    # Ambiguous keys cannot safely be joined; report them rather than choosing a row.
    unique = valid & ~keys.duplicated(keep=False)
    result = frame.loc[unique].copy()
    result.index = keys[unique]
    return result


def compare_datasets(frames, schemas):
    result = []
    for left, right in combinations(frames, 2):
        a = ip_records(frames[left], schemas[left])
        b = ip_records(frames[right], schemas[right])
        item = {"left": left, "right": right}
        if a is None or b is None:
            item.update(status="skipped", reason="SourceIP column unavailable; no event-to-IP mapping inferred")
        else:
            left_col = schemas[left].get("source_ip", "SourceIP")
            right_col = schemas[right].get("source_ip", "SourceIP")
            keys_a = set(frames[left][left_col].map(canonical_ip).dropna())
            keys_b = set(frames[right][right_col].map(canonical_ip).dropna())
            shared = a.index.intersection(b.index)
            mismatches = {}
            for field in FIELDS:
                if field in a and field in b:
                    av, bv = a.loc[shared, field], b.loc[shared, field]
                    mask = present(av) & present(bv)
                    if field in ("AnomalyLabel", "AnomalyScore"):
                        av, bv = pd.to_numeric(av, errors="coerce"), pd.to_numeric(bv, errors="coerce")
                        mask &= av.notna() & bv.notna()
                    mismatches[field] = {"compared": int(mask.sum()), "different": int((av[mask] != bv[mask]).sum())}
            item.update(status="checked", shared_ips=len(keys_a & keys_b), left_only_ips=len(keys_a - keys_b), right_only_ips=len(keys_b - keys_a), unambiguous_shared_ips=len(shared), field_comparisons=mismatches,
                        note="Differences are review candidates; separate prediction/risk stages may intentionally differ. Duplicate IP keys excluded from field comparison.")
        result.append(item)
    return result


def event_ip_coverage(frames, schemas):
    """Use explicit SourceIP, or SSH 'from IP'/'rhost=IP' message evidence only."""
    if "events" not in frames:
        return {"status": "skipped", "reason": "Events dataset unavailable"}
    frame, schema = frames["events"], schemas["events"]
    column = schema.get("source_ip", "SourceIP")
    if column in frame:
        keys = frame[column].map(canonical_ip)
        method = "SourceIP column"
    elif schema.get("content_column") in frame:
        pattern = re.compile(r"(?:\bfrom\s+|\brhost=)([0-9a-fA-F:.]+)(?=\s|$)")
        def extract(value):
            matches = [canonical_ip(match) for match in pattern.findall(str(value))]
            matches = {match for match in matches if match is not None}
            return next(iter(matches)) if len(matches) == 1 else None
        keys = frame[schema["content_column"]].map(extract)
        method = "Unambiguous valid SSH from/rhost message IP; incomplete evidence"
    else:
        return {"status": "skipped", "reason": "No SourceIP or configured content column; no IPs inferred"}
    event_keys = set(keys.dropna())
    coverage = {}
    for name, other in frames.items():
        if name == "events":
            continue
        source = schemas[name].get("source_ip", "SourceIP")
        if source in other:
            other_keys = set(other[source].map(canonical_ip).dropna())
            coverage[name] = {"shared_ips": len(event_keys & other_keys), "aggregate_ips_without_event_evidence": len(other_keys - event_keys), "event_ips_not_in_aggregate": len(event_keys - other_keys)}
    return {"status": "checked", "method": method, "events_with_ip_evidence": int(keys.notna().sum()), "events_without_ip_evidence": int(keys.isna().sum()), "coverage": coverage,
            "note": "Missing evidence is not proof of a bad aggregation; no event count semantics or timestamp year assumed."}


def check_predictions(frame, policy):
    """Check only supplied conventions; never treat predictions as ground truth."""
    result = {}
    label_status = policy.get("label_status")
    if label_status and {"AnomalyLabel", "AnomalyStatus"} <= set(frame):
        expected = frame.AnomalyLabel.map(label_status)
        mask = expected.notna() & present(frame.AnomalyStatus)
        result["label_status"] = {"status": "checked", "compared": int(mask.sum()), "inconsistent": int((frame.AnomalyStatus[mask] != expected[mask]).sum()), "unmapped_labels": int((present(frame.AnomalyLabel) & expected.isna()).sum())}
    else:
        result["label_status"] = {"status": "skipped", "reason": "Needs label_status policy and both columns"}
    score_rule = policy.get("score_rule")
    if score_rule and {"AnomalyLabel", "AnomalyScore"} <= set(frame):
        scores = pd.to_numeric(frame.AnomalyScore, errors="coerce")
        finite = scores.notna() & scores.abs().ne(float("inf"))
        mask = finite & present(frame.AnomalyLabel)
        anomalous = scores.le(score_rule["threshold"]) if score_rule["direction"] == "lower" else scores.ge(score_rule["threshold"])
        expected = anomalous.map({True: str(score_rule["anomaly_label"]), False: str(score_rule["normal_label"])})
        result["score_label"] = {"status": "checked", "compared": int(mask.sum()), "inconsistent": int((frame.AnomalyLabel[mask] != expected[mask]).sum())}
    else:
        result["score_label"] = {"status": "skipped", "reason": "Needs explicit score direction/threshold/labels and columns; score convention unknown"}
    risk_map = policy.get("risk_by_status")
    if risk_map and {"RiskLevel", "AnomalyStatus"} <= set(frame):
        mask = present(frame.RiskLevel) & frame.AnomalyStatus.isin(risk_map)
        inconsistent = sum(str(row.RiskLevel) not in risk_map[str(row.AnomalyStatus)] for row in frame.loc[mask].itertuples())
        result["status_risk"] = {"status": "checked", "compared": int(mask.sum()), "inconsistent": int(inconsistent), "unmapped_statuses": int((present(frame.AnomalyStatus) & ~frame.AnomalyStatus.isin(risk_map)).sum())}
    else:
        result["status_risk"] = {"status": "skipped", "reason": "Needs risk_by_status policy and both columns; risk is not implied by anomaly status"}
    return result
