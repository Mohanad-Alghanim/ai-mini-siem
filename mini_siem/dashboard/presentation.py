"""Small display-only transformations; never update stored data or model outputs."""

from datetime import date, datetime, timezone
import math
import re

import pandas as pd

RISK_LEVELS = ('High', 'Medium', 'Low')
RISK_NOTE = ('Risk Level is an uncalibrated display priority: High = score < -0.1; '
             'Medium = -0.1 <= score < 0; Low = score >= 0. '
             'It is not attack probability or confirmed severity; score scales may differ between models.')
ALERT_NAME = 'Unusual SSH Authentication Behavior'


def format_timestamp(value):
    """Convert only a full timezone-aware value to UTC; never infer missing parts."""
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and re.match(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', value):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        else:
            return 'Unknown'
        if parsed.utcoffset() is None:
            return 'Unknown'
        return parsed.astimezone(timezone.utc).replace(tzinfo=None).isoformat(sep=' ', timespec='seconds')
    except (ValueError, TypeError, OverflowError):
        return 'Unknown'


def risk_level(score):
    """Presentation bins only, independent of model fitting and stored scores."""
    if isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score):
        raise ValueError('Invalid score for risk display')
    return 'High' if score < -0.1 else 'Medium' if score < 0 else 'Low'


def prediction_table(records):
    result = pd.DataFrame(index=records.index)
    result['Source IP'] = records['SourceIP']
    result['Classification'] = records['AnomalyStatus']
    result['Risk Level'] = records['AnomalyScore'].map(risk_level)
    result['Timestamp (UTC)'] = records['Processing Timestamp (UTC)'].map(format_timestamp)
    return result


def alert_table(records):
    result = pd.DataFrame(index=records.index)
    result['Alert Name'] = ALERT_NAME
    result['Source IP'] = records['SourceIP']
    result['Risk Level'] = records['Anomaly Score'].map(risk_level)
    result['Timestamp (UTC)'] = records['Alert Created (UTC)'].map(format_timestamp)
    result['Description'] = 'The stored SSH model marked this behavior as unusual. Not a confirmed attack.'
    return result


def event_table(records):
    """SQLite IDs stay in the query result, not in the analyst-facing view."""
    result = pd.DataFrame(index=records.index)
    result['Event Type'] = records['Event Type'].map(lambda value: value if isinstance(value, str) and value.strip() else 'Unknown')
    result['Source IP'] = records['SourceIP'].map(lambda value: value if isinstance(value, str) and value.strip() else 'Unknown')
    result['Event Status'] = records['Event Status'].map(lambda value: value.replace('_', ' ') if isinstance(value, str) and value.strip() else 'Unknown')
    result['Event Timestamp (UTC)'] = records['Original Event Timestamp'].map(format_timestamp)
    result['Ingested (UTC)'] = records['Ingested (UTC)'].map(format_timestamp)
    return result


def filter_table(records, *, source_ip='', text='', text_column=None, risk=None,
                 status=None, status_column='Classification', dates=(), timestamp='Timestamp (UTC)'):
    """Combine literal in-memory filters over the small read-only display frame.

    Timestamp strings here were already validated/converted by format_timestamp.
    Unknown times are retained without a date filter and excluded with one.
    """
    mask = pd.Series(True, index=records.index)
    if source_ip:
        mask &= records['Source IP'].str.contains(source_ip, case=False, regex=False, na=False)
    if text and text_column:
        mask &= records[text_column].str.contains(text, case=False, regex=False, na=False)
    if risk:
        mask &= records['Risk Level'].eq(risk)
    if status:
        mask &= records[status_column].eq(status)
    if isinstance(dates, date):
        dates = (dates,)
    if dates:
        if len(dates) > 2 or dates[0] > dates[-1]:
            raise ValueError('Invalid date range')
        def within_range(value):
            try:
                actual = datetime.strptime(value, '%Y-%m-%d %H:%M:%S').date()
            except (ValueError, TypeError):
                return False
            return dates[0] <= actual <= dates[-1]
        mask &= records[timestamp].map(within_range)
    return records.loc[mask].copy()
