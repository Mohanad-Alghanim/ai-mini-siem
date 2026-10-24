"""Read-only operational event metadata and sanitized offline SSH review."""

from collections import Counter
import re

import pandas as pd

from mini_siem.dashboard.queries import DashboardDataError, readonly_database
from mini_siem.evidence_review import CLASSES, VERSION
from mini_siem.feature_contract import read_contract as read_json


def historical_events(database, batch=None, source_ip=None):
    clauses, values = [], []
    if batch:
        clauses.append('batch_id = ?'); values.append(batch)
    if source_ip:
        clauses.append('instr(COALESCE(source_ip,\'\'), ?) > 0'); values.append(source_ip)
    where = ' WHERE '+' AND '.join(clauses) if clauses else ''
    with readonly_database(database) as connection:
        return pd.read_sql_query("""SELECT event_id AS 'Event ID',batch_id AS 'Batch ID',
            source_record AS 'Source Record',source_ip AS SourceIP,event_type AS 'Event Type',
            occurred_at AS 'Original Event Timestamp',ingested_at_utc AS 'Ingested (UTC)'
            FROM security_events"""+where+' ORDER BY event_id',connection,params=values)


def lab_review(path):
    """Display only selected sanitized fields, never arbitrary report strings.

    This checks report consistency, not the root-private original capture. The
    authorized analyst generates the report using evidence_review beforehand.
    """
    try:
        report = read_json(path)
        if report['review_version'] != VERSION or any(report[k] is not False for k in ('training_allowed','inference_allowed','event_labels_assigned')):
            raise ValueError('Incompatible review')
        rows = report['event_evidence']
        if not isinstance(rows,list) or any(set(row) != {'event_ref','category'} or not re.fullmatch('[0-9a-f]{64}',row['event_ref']) or row['category'] not in CLASSES for row in rows):
            raise ValueError('Invalid event references')
        counts = Counter(row['category'] for row in rows)
        if len({r['event_ref'] for r in rows}) != len(rows) or report['evidence_counts'] != {c:counts[c] for c in CLASSES}:
            raise ValueError('Inconsistent evidence counts')
        quality = report['quality']
        total = quality['total_records']
        numeric = [total,quality['supported_records'],quality['unsupported_records'],quality['records_with_source']]
        if any(type(n) is not int or n<0 for n in numeric) or total != len(rows) or quality['supported_records']+quality['unsupported_records'] != total or quality['records_with_source']>total:
            raise ValueError('Inconsistent record coverage')
        if report['correlation_summary']['verified_assignments'] != 0 or any(r['correlation_confidence']!='unresolved' for r in report['experiment_correlations']):
            raise ValueError('Unsupported verified correlation')
        return {'counts':{'Records':total,'Adapter supported':quality['supported_records'],
                          'Adapter unsupported':quality['unsupported_records'],'With source IP':quality['records_with_source']},
                'events':pd.DataFrame(rows,columns=['event_ref','category']),
                'classifications':pd.DataFrame([{'Evidence category':c,'Records':counts[c]} for c in CLASSES]),
                'experiments':len(report['experiment_correlations'])}
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        raise DashboardDataError('SSH review unavailable or incompatible. Select an authorized sanitized V2 review; private captures and credentials are not read by this screen.') from None
