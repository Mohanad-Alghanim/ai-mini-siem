"""Evidence-led feature diagnostics, with no model or database operations."""

from collections import Counter, defaultdict
import hashlib
from ipaddress import ip_address
import re
from pathlib import Path
import tempfile

from mini_siem.ingestion.ssh_events import PARSER_VERSION, PEER, load_events
from mini_siem.ml.features import FEATURES, load_features, prepare_features
from mini_siem.preprocessing.ssh_features import SEMANTICS, aggregate_features, compare_baseline


DIAGNOSTIC_VERSION = "ssh-feature-diagnostics-v1"


def reference(event):
    """Local provenance without raw content, usernames, dates or templates."""
    return {"source_record": event["SourceRecord"], "LineId": event["Original"]["LineId"],
            "EventId": event["Original"]["EventId"] or None}


def fingerprint(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def candidate_addresses(event):
    """Literal address tokens for review, NEVER additional SourceIP assignments."""
    addresses = set()
    for token in re.split(r"[\s=\[\](),;]+", event["Original"]["Content"]):
        try:
            addresses.add(str(ip_address(token)))
        except ValueError:
            pass
    return addresses


def peer_context_evidence(event):
    observations = []
    for match in PEER.finditer(event["Original"]["Content"]):
        token = match.group("token")
        try:
            kind = "valid_ipv" + str(ip_address(token).version)
        except ValueError:
            kind = "invalid_or_unsupported_token"
            if re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}:", token):
                try:
                    ip_address(token[:-1])
                    kind = "strict_ipv4_with_separator"
                except ValueError:
                    pass
        observations.append({"context": match.group("context").strip().lower(), "token_category": kind})
    return {**reference(event), "parse_status": event["ParseStatus"], "peer_contexts": observations,
            "literal_address_candidates": len(candidate_addresses(event)),
            "note": "Diagnostic token categories do not change parser decisions or assign peers."}


def rate_gap_explanation(generated, baseline):
    checks = [rate_check(values) for values in (generated, baseline)]
    if not all(check.get("agrees_with_ratio") for check in checks):
        return {"status": "unresolved", "reason": "Both sides need nonzero denominators and rates agreeing with failure/event ratios."}
    gf, ge = generated["FailedAuthCount"], generated["EventCount"]
    bf, be = baseline["FailedAuthCount"], baseline["EventCount"]
    numerator = (gf - bf) / be
    denominator = gf / ge - gf / be
    delta = generated["FailedAuthRate"] - baseline["FailedAuthRate"]
    return {"status": "arithmetic_explanation", "numerator_effect_at_baseline_denominator": numerator,
            "denominator_effect_at_generated_numerator": denominator,
            "reported_rate_delta": delta, "roundoff_residual": delta - numerator - denominator,
            "interpretation": "Observed rate difference decomposes into changed failure/event counts. Why the baseline counts differ remains unresolved."}


def evidence_for_ip(records, unassigned):
    failures = [event for event in records if event["FailedAuth"]]
    invalid = [event for event in records if event["InvalidUser"]]
    accepted = [event for event in records if event["AcceptedAuth"]]
    overlap = [event for event in records if event["FailedAuth"] and event["InvalidUser"]]
    event_groups = defaultdict(list)
    template_groups = defaultdict(list)
    for event in records:
        event_groups[event["EventType"]].append(reference(event))
        if event["Original"]["EventTemplate"].strip():
            template_groups[fingerprint(event["Original"]["EventTemplate"])].append(reference(event))
    broad_failed = [event for event in records if re.search(r"\bfailed\b", event["Original"]["Content"], re.IGNORECASE) and not event["FailedAuth"]]
    all_flags = [(event["FailedAuth"], event["InvalidUser"], event["AcceptedAuth"]) for event in records]
    return {
        "event_records": [reference(event) for event in records],
        "failure_records": [reference(event) for event in failures],
        "invalid_user_records": [reference(event) for event in invalid],
        "accepted_records": [reference(event) for event in accepted],
        "failure_invalid_overlap_records": [reference(event) for event in overlap],
        "failure_invalid_union_count": len(failures) + len(invalid) - len(overlap),
        "failure_accepted_overlap_records": [reference(event) for event in records if event["AuthAmbiguous"]],
        "no_supported_auth_indicator_count": sum(not any(flags) for flags in all_flags),
        "derived_event_type_groups": [{"type_fingerprint": fingerprint(kind), "records": refs} for kind, refs in sorted(event_groups.items())],
        "template_groups": [{"template_fingerprint": key, "records": refs} for key, refs in sorted(template_groups.items())],
        "unique_nonblank_event_ids": len({event["Original"]["EventId"] for event in records if event["Original"]["EventId"].strip()}),
        "unique_nonblank_templates": len(template_groups),
        "template_fallback_records": [reference(event) for event in records if not event["Original"]["EventId"].strip()],
        "repeated_content_excess": len(records) - len({event["Original"]["Content"] for event in records}),
        "broad_failed_word_excluded_records": [reference(event) for event in broad_failed],
        "unassigned_candidate_records": [reference(event) for event in unassigned],
        "candidate_warning": "Address occurrence is not peer attribution. These unassigned records are NOT included in generated features.",
    }


def rate_check(values):
    if values is None:
        return {"status": "unavailable"}
    count, failed, rate = (values[name] for name in ("EventCount", "FailedAuthCount", "FailedAuthRate"))
    if count == 0:
        return {"status": "zero_denominator", "reported_rate": rate,
                "note": "Zero-event rate convention is not known; no ratio is fabricated."}
    expected = failed / count
    return {"status": "checked", "failed_count_div_event_count": expected,
            "reported_rate": rate, "agrees_with_ratio": abs(expected - rate) <= 1e-12,
            "note": "An arithmetic mismatch does not identify the original producer's intended denominator or rounding."}


def hypothesis_probes(baseline, generated, evidence):
    """Coincidences are explicitly hypotheses, never inferred producer rules."""
    if baseline is None or generated is None:
        return []
    probes = []
    for name, alternative, feature in (
        ("Distinct nonblank templates rather than current derived event types", evidence["unique_nonblank_templates"], "UniqueEventTypes"),
        ("Distinct nonblank EventId values only", evidence["unique_nonblank_event_ids"], "UniqueEventTypes"),
        ("Failure/invalid-user union rather than failure indicator", evidence["failure_invalid_union_count"], "FailedAuthCount"),
        ("Failure indicator plus excluded broad failed-word records", len(evidence["failure_records"]) + len(evidence["broad_failed_word_excluded_records"]), "FailedAuthCount"),
        ("Event count plus unassigned address-candidate records", generated["EventCount"] + len(evidence["unassigned_candidate_records"]), "EventCount"),
    ):
        if baseline[feature] != generated[feature] and alternative == baseline[feature]:
            probes.append({"classification": "hypothesis_only", "feature": feature, "description": name,
                           "candidate_value": alternative, "warning": "Numeric coincidence only; no evidence that the baseline producer used this rule. Features are unchanged."})
    return probes


def diagnose(raw_path, baseline_path):
    events, source_hash = load_events(raw_path)
    features = aggregate_features(events)
    baseline_bytes = Path(baseline_path).read_bytes()
    with tempfile.TemporaryDirectory(prefix="ssh-baseline-diagnostic-") as directory:
        snapshot = Path(directory) / "baseline.csv"
        snapshot.write_bytes(baseline_bytes)
        comparison = compare_baseline(features, snapshot)
        baseline = load_features(snapshot)
    ids, numbers = prepare_features(baseline)
    baseline_groups = defaultdict(list)
    for ip, (_, row) in zip(ids, numbers.iterrows()):
        baseline_groups[str(ip_address(ip))].append({feature: float(row[feature]) for feature in FEATURES})
    generated = {row.SourceIP: {feature: float(getattr(row, feature)) for feature in FEATURES} for row in features.itertuples(index=False)}
    assigned, candidates = defaultdict(list), defaultdict(list)
    coverage_groups = defaultdict(list)
    for event in events:
        coverage_groups[(event["ParseStatus"], event["Original"]["EventId"] or "[template-only]")].append(reference(event))
        if event["SourceIP"] is not None:
            assigned[event["SourceIP"]].append(event)
        else:
            for address in candidate_addresses(event):
                candidates[address].append(event)
    rows = []
    summary = {feature: {"compared_ips": 0, "differing_ips": 0, "maximum_absolute_delta": 0.0} for feature in FEATURES}
    for ip in sorted(set(generated) | set(baseline_groups)):
        ambiguous = len(baseline_groups.get(ip, [])) > 1
        base = baseline_groups[ip][0] if len(baseline_groups.get(ip, [])) == 1 else None
        current = generated.get(ip)
        evidence = evidence_for_ip(assigned[ip], candidates[ip])
        differences = {}
        for feature in FEATURES:
            a, b = (current[feature] if current else None), (base[feature] if base else None)
            delta = a - b if a is not None and b is not None else None
            match = (abs(delta) <= 1e-12 if feature == "FailedAuthRate" else delta == 0) if delta is not None else None
            differences[feature] = {"generated": a, "baseline": b, "delta_generated_minus_baseline": delta,
                                    "matches": match, "cause": "unresolved" if match is False else "not_applicable"}
            if delta is not None:
                summary[feature]["compared_ips"] += 1
                if not match:
                    summary[feature]["differing_ips"] += 1
                    summary[feature]["maximum_absolute_delta"] = max(summary[feature]["maximum_absolute_delta"], abs(delta))
        confirmed = ["Generated values are traceable to the listed parser-v2 records and current aggregation rules."] if current else ["No supported peer events were assigned to this baseline IP."]
        if rate_check(base).get("agrees_with_ratio") is False:
            confirmed.append("Baseline FailedAuthRate differs from baseline FailedAuthCount/EventCount at tolerance 1e-12; the producer denominator/rounding remains unknown.")
        rows.append({"SourceIP": ip, "baseline_ambiguous": ambiguous,
                     "presence": "both" if current and base else "ambiguous_baseline" if ambiguous else "generated_only" if current else "baseline_only",
                     "features": differences, "generated_evidence": evidence,
                     "baseline_rate_check": rate_check(base), "generated_rate_check": rate_check(current),
                     "rate_gap_explanation": rate_gap_explanation(current, base),
                     "confirmed_findings": confirmed,
                     "hypotheses": hypothesis_probes(base, current, evidence),
                     "unresolved": ["Baseline record membership, parsing, counting, deduplication and window definitions are not independently known."]})
    return {
        "diagnostic_version": DIAGNOSTIC_VERSION, "parser_version": PARSER_VERSION, "feature_semantics": SEMANTICS,
        "source_sha256": source_hash, "baseline_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
        "coverage": {"total_events": len(events), "supported_events": sum(event["SourceIP"] is not None for event in events),
                     "unassigned_events": sum(event["SourceIP"] is None for event in events),
                     "parse_status_counts": dict(Counter(event["ParseStatus"] for event in events)),
                     "unassigned_context_evidence": [peer_context_evidence(event) for event in events if event["SourceIP"] is None],
                     "groups": [{"parse_status": status, "EventId": kind, "count": len(refs), "records": refs} for (status, kind), refs in sorted(coverage_groups.items())]},
        "comparison": comparison, "feature_summary": summary, "per_source_ip": rows,
        "confirmed_findings": ["The supplied files' numerical differences and generated event membership are directly measured in this report.",
                               "Generated authentication counters are independent per-record indicators; failure/invalid overlaps count in both counters.",
                               "Generated event types prefer EventId and fall back to EventTemplate; diagnostic alternatives do not change the features."],
        "hypotheses": ["Different peer parsing, event membership, failure rules, event-type definitions, deduplication or aggregation windows could explain baseline gaps; original producer evidence is required."],
        "unresolved": ["Original baseline producer code, exact input membership/window and model training provenance are unavailable to this diagnostic.",
                       "No observed numerical coincidence proves a baseline generation rule or causes a mismatch to be marked explained."],
        "compatibility": {"decision": "not_demonstrated", "inference_allowed": False,
                          "rationale": "Baseline semantics/provenance are unverified. Equal IP sets or numerical agreement are insufficient for safe model reuse."},
        "recommendations": ["Recover baseline generation code/configuration, source hashes, row membership, counting rules, and training provenance; review every feature's semantics before reusing the existing model.",
                            "If compatibility cannot be demonstrated, propose a separately versioned feature/model pipeline with consistent training/inference definitions, sufficient representative data and independent evaluation. Do not train or replace it in this task."],
        "limitations": ["Historical file only; no timestamp year or time window inferred.", "Text indicators and previous model labels are not verified attack ground truth; no accuracy metrics are calculated.",
                        "Reports contain private IP-level provenance; they omit raw message content and template text. Keep them local."]}
