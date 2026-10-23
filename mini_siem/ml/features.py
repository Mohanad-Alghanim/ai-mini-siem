"""Load and validate the five behavioral inputs without modifying source data."""

import pandas as pd

from mini_siem.ingestion.csv_loader import load_csv
from mini_siem.preprocessing.validation import validate_frame


FEATURES = (
    "EventCount", "UniqueEventTypes", "FailedAuthCount", "InvalidUserCount",
    "FailedAuthRate",
)
REQUIRED = ("SourceIP", *FEATURES)


def prepare_features(frame):
    """Return identifiers and a numeric feature frame in a fixed order.

    Extra columns, including previous predictions, are deliberately excluded.
    Counts must be integral and nonnegative; the rate must be in [0, 1].
    """
    if not isinstance(frame, pd.DataFrame) or not frame.columns.is_unique:
        raise ValueError("Input must be a DataFrame with unique column names")
    if frame.empty:
        raise ValueError("At least one feature record is required")
    missing = set(REQUIRED) - set(frame)
    if missing:
        raise ValueError("Required SourceIP or behavioral feature columns are missing")
    # String normalization makes CSV and in-memory validation consistent and
    # rejects boolean objects as numerical counts rather than treating True as 1.
    source = frame.loc[:, list(REQUIRED)].astype("string")
    rules = {name: {"type": "integer", "min": 0} for name in FEATURES[:-1]}
    rules.update(SourceIP={"type": "ip"}, FailedAuthRate={"type": "number", "min": 0, "max": 1})
    quality = validate_frame(source, {"required": list(REQUIRED), "columns": rules})
    if any(quality["missing_values"].values()):
        raise ValueError("Identifiers and features must not contain missing or blank values")
    if any(check.get("invalid_type", 0) or check.get("out_of_range", 0) for check in quality["column_checks"].values()):
        raise ValueError("Invalid IP, nonfinite/nonnumeric value, fractional/negative count, or rate outside [0, 1]")
    features = source.loc[:, list(FEATURES)].apply(pd.to_numeric).astype("float64")
    # Isolation Forest internally uses float32, so reject finite values that
    # would overflow that representation rather than allowing an infinite input.
    if features.abs().gt(3.4028234663852886e38).any().any():
        raise ValueError("Feature values exceed the model's float32 input range")
    return source["SourceIP"].copy(), features


def load_features(path):
    """Load through the shared strict Pandas CSV loader, then validate."""
    frame = load_csv(path)
    prepare_features(frame)
    return frame
