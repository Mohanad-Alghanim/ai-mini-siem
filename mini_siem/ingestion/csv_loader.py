"""Read CSV files without changing their contents or coercing source values."""

import csv
from pathlib import Path

import pandas as pd


class DatasetLoadError(ValueError):
    """A dataset could not be safely parsed as a rectangular CSV."""


def load_csv(path: str | Path) -> pd.DataFrame:
    """Preserve strings, including literal 'NA'; blank cells become missing later.

    Check every record's width because pandas may otherwise silently infer an
    index from extra fields or pad short records. UTF-8 BOMs are supported.
    """
    try:
        with Path(path).open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            header = next(reader, None)
            if not header or any(not name.strip() for name in header):
                raise DatasetLoadError("CSV needs a nonempty header with named columns")
            if len(header) != len(set(header)):
                raise DatasetLoadError("CSV has duplicate column names")
            for row in reader:
                if len(row) != len(header):
                    raise DatasetLoadError("CSV has a record with an incorrect field count")
        return pd.read_csv(path, dtype="string", keep_default_na=False, encoding="utf-8-sig")
    except (OSError, UnicodeError, csv.Error, pd.errors.ParserError) as exc:
        # Do not include exception text: parsers can echo sensitive log records.
        raise DatasetLoadError(f"CSV could not be read ({type(exc).__name__})") from None
