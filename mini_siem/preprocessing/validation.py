"""Aggregate data quality checks; never repair or mutate input datasets."""

from ipaddress import ip_address
import math

import pandas as pd


def present(series):
    """Return a mask for nonblank cells without treating literal NA as null."""
    return series.notna() & series.fillna("").astype(str).str.strip().ne("")


def valid_ip(value):
    try:
        ip_address(str(value))
        return True
    except ValueError:
        return False


def canonical_ip(value):
    try:
        return str(ip_address(str(value)))
    except ValueError:
        return None


def validate_frame(frame, schema, expected_rows=None):
    """Validate only declared types/ranges; unconfigured columns are profiled."""
    required = set(schema.get("required", [])) | set(schema.get("columns", {}))
    required |= {schema[key] for key in ("source_ip", "content_column", "event_column") if key in schema}
    result = {
        "rows": len(frame),
        "expected_rows": expected_rows,
        "row_count_matches": expected_rows is None or len(frame) == expected_rows,
        "columns": list(frame.columns),
        "missing_columns": sorted(set(required) - set(frame.columns)),
        "duplicate_rows": int(frame.duplicated().sum()),
        "missing_values": {},
        "column_checks": {},
        "schema_complete": schema.get("complete", False),
    }
    for column in frame:
        series = frame[column]
        mask = present(series)
        values = series[mask]
        result["missing_values"][column] = int((~mask).sum())
        rule = schema.get("columns", {}).get(column)
        if not rule:
            result["column_checks"][column] = {"status": "unconfigured", "distinct_nonblank": int(values.nunique())}
            continue
        kind = rule.get("type", "string")
        check = {"status": "checked", "type": kind, "invalid_type": 0, "out_of_range": 0, "invalid_allowed_value": 0}
        if kind in ("number", "integer"):
            numbers = pd.to_numeric(values, errors="coerce")
            finite = numbers.map(lambda value: pd.notna(value) and math.isfinite(float(value)))
            valid = finite.copy()
            if kind == "integer":
                valid &= numbers.fillna(0).mod(1).eq(0)
            check["invalid_type"] = int((~valid).sum())
            outside = pd.Series(False, index=values.index)
            if "min" in rule:
                outside |= numbers.lt(rule["min"])
            if "max" in rule:
                outside |= numbers.gt(rule["max"])
            check["out_of_range"] = int((outside & valid).sum())
        elif kind == "ip":
            check["invalid_type"] = int((~values.map(valid_ip)).sum())
        if "allowed" in rule:
            check["invalid_allowed_value"] = int((~values.isin([str(v) for v in rule["allowed"]])).sum())
        result["column_checks"][column] = check
    source = schema.get("source_ip", "SourceIP")
    if source in frame:
        values = frame.loc[present(frame[source]), source]
        result["source_ip"] = {"invalid": int((~values.map(valid_ip)).sum()), "duplicate_keys": int(values.map(canonical_ip).dropna().duplicated().sum())}
    return result


def analyze_events(frame, schema):
    """Count textual indicators, not verified outcomes or distinct incidents."""
    result = {"event_types": {"status": "skipped", "reason": "No configured event column present"},
              "authentication": {"status": "skipped", "reason": "No configured content column present"}}
    event_column = schema.get("event_column")
    if event_column in frame:
        counts = frame.loc[present(frame[event_column]), event_column].value_counts()
        # Avoid exporting event values, which can contain identifying information.
        result["event_types"] = {"status": "checked", "distinct_types": len(counts), "type_frequencies": sorted([int(v) for v in counts], reverse=True)}
    content_column = schema.get("content_column")
    if content_column in frame:
        content = frame[content_column].fillna("")
        patterns = {"accepted": r"\bAccepted\b", "failed": r"\bFailed\b", "invalid_user": r"\bInvalid user\b", "authentication_failure": r"\bauthentication failure\b", "disconnect": r"\b(?:disconnected|disconnecting|connection closed)\b"}
        result["authentication"] = {"status": "checked", "indicator_counts": {name: int(content.str.contains(pattern, case=False, regex=True).sum()) for name, pattern in patterns.items()}, "note": "Text indicators may overlap; they are not verified authentication outcomes."}
    return result
