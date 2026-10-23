"""Strict metadata validation and optional private CSV inspection."""

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import tempfile

from mini_siem.feature_contract import read_contract as read_json
from mini_siem.ingestion.csv_loader import load_csv
from mini_siem.preprocessing.validation import validate_frame


SCHEMA_PATH = Path(__file__).resolve().parents[2] / 'config/dataset_inventory.schema.json'


def validate_schema(value, schema=None, path='$'):
    """Validate the subset used by our fixed public JSON Schema, without dependencies."""
    schema = read_json(SCHEMA_PATH) if schema is None else schema
    types = schema.get('type', [])
    types = [types] if isinstance(types, str) else types
    kind = 'null' if value is None else 'boolean' if isinstance(value, bool) else 'integer' if isinstance(value, int) else 'number' if isinstance(value, float) else 'string' if isinstance(value, str) else 'array' if isinstance(value, list) else 'object' if isinstance(value, dict) else 'invalid'
    if kind not in types and not (kind == 'integer' and 'number' in types):
        return [f'{path}: incorrect type']
    errors = []
    if 'enum' in schema and value not in schema['enum']:
        errors.append(f'{path}: unknown category/version')
    if kind == 'object':
        if set(schema.get('required', [])) - set(value):
            errors.append(f'{path}: missing required fields')
        if schema.get('additionalProperties') is False and set(value) - set(schema['properties']):
            errors.append(f'{path}: unknown fields')
        for key in schema['properties'].keys() & value.keys():
            errors += validate_schema(value[key], schema['properties'][key], f'{path}.{key}')
    elif kind == 'array':
        if schema.get('uniqueItems') and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            errors.append(f'{path}: duplicated identifiers/items')
        for item in value:
            errors += validate_schema(item, schema['items'], path+'[]')
    elif kind == 'string':
        if len(value.strip()) < schema.get('minLength', 0) or ('pattern' in schema and not re.fullmatch(schema['pattern'], value)):
            errors.append(f'{path}: malformed value')
    elif kind in ('number', 'integer'):
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite or value < schema.get('minimum', -math.inf) or value <= schema.get('exclusiveMinimum', -math.inf):
            errors.append(f'{path}: invalid numerical range')
    return sorted(set(errors))


def utc_timestamp(value):
    """Only full timezone-aware ISO timestamps; never infer years/timezones."""
    if not isinstance(value, str) or not re.match(r'^\d{4}-\d{2}-\d{2}T', value):
        raise ValueError('Timestamp needs full date and timezone')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('Timezone missing')
    return parsed.astimezone(timezone.utc)


def metadata_errors(manifest):
    errors = validate_schema(manifest)
    if errors:
        return errors
    rules = manifest['schema']['column_rules']
    if len({rule['field'] for rule in rules}) != len(rules):
        errors.append('schema: duplicated column rule identifiers')
    for rule in rules:
        if rule['type'] not in ('integer','number') and (rule['min'] is not None or rule['max'] is not None):
            errors.append('schema: bounds require a numeric column type')
        if rule['min'] is not None and rule['max'] is not None and rule['min'] > rule['max']:
            errors.append('schema: numerical bounds reversed')
    labels = manifest['labels']
    if labels['available'] and (labels['source'] == 'none' or labels['reliability'] == 'not_available'):
        errors.append('labels: available labels need a declared source and reliability')
    if manifest['quality_review']['status'] == 'independently_reviewed' and not manifest['quality_review']['evidence_sha256']:
        errors.append('quality_review: independent review requires evidence')
    if labels['reliability'] == 'independently_verified' and (not labels['available'] or labels['source'] not in ('independent_review','controlled_experiment_record') or not labels['evidence_sha256']):
        errors.append('labels: independent verification needs available non-model labels and evidence')
    if not labels['available'] and (labels['source'] not in ('none','unknown') or labels['reliability'] != 'not_available'):
        errors.append('labels: contradictory availability/source/reliability')
    timestamps = manifest['timestamps']
    if timestamps['confidence'] == 'independently_verified' and (not timestamps['fields'] or not timestamps['evidence_sha256']):
        errors.append('timestamps: trusted fields require evidence')
    observation = manifest['observation']
    for field in ('start','end'):
        if observation[field] is not None:
            try:
                utc_timestamp(observation[field])
            except (ValueError, TypeError, OverflowError):
                errors.append('observation: malformed or timezone-ambiguous boundary')
    if observation['confidence'] == 'independently_verified':
        if any(observation[field] is None for field in ('start','end','duration_seconds','evidence_sha256')):
            errors.append('observation: verified duration needs boundaries, duration and evidence')
    if observation['start'] is not None and observation['end'] is not None:
        try:
            duration = (utc_timestamp(observation['end']) - utc_timestamp(observation['start'])).total_seconds()
            if duration <= 0 or (observation['duration_seconds'] is not None and abs(duration - observation['duration_seconds']) > 1e-6):
                errors.append('observation: boundaries/duration inconsistent')
        except (ValueError, TypeError, OverflowError):
            pass
    membership = manifest['event_membership']
    if membership['complete'] and (not membership['identity_namespace'] or not membership['event_identity_sha256'] or not membership['evidence_sha256']):
        errors.append('event_membership: complete membership needs namespace, hashes and evidence')
    if membership['complete'] and manifest['record_unit'] == 'raw_event' and manifest['file']['record_count'] != len(membership['event_identity_sha256']):
        errors.append('event_membership: raw-event count must equal complete identity count')
    return errors


def inspect_csv(path, manifest):
    """Hash and inspect an exact private snapshot. Never change original bytes."""
    if manifest['file']['format'] != 'csv':
        raise ValueError('Only CSV file inspection is implemented; other sources are metadata-only')
    content = Path(path).read_bytes()
    with tempfile.TemporaryDirectory(prefix='siem-inventory-') as directory:
        snapshot = Path(directory) / 'data.csv'
        snapshot.write_bytes(content)
        frame = load_csv(snapshot)
    findings = []
    actual_hash = hashlib.sha256(content).hexdigest()
    if manifest['file']['sha256'] is not None and manifest['file']['sha256'] != actual_hash:
        findings.append('file hash mismatch')
    if manifest['file']['record_count'] is not None and manifest['file']['record_count'] != len(frame):
        findings.append('record count mismatch')
    rules = manifest['schema']['column_rules']
    required = set(manifest['schema']['required_columns']) | set(manifest['timestamps']['fields']) | {rule['field'] for rule in rules}
    required |= {name for name in (manifest['schema']['record_id_field'], manifest['schema']['label_field']) if name is not None}
    missing_columns = sorted(required - set(frame))
    if missing_columns:
        findings.append('declared fields missing from CSV')
    blank_counts = {name: int(frame[name].str.strip().eq('').sum()) for name in frame}
    if any(blank_counts.get(rule['field'],0) for rule in rules if not rule['nullable']):
        findings.append('missing nonnullable field values')
    declared = {rule['field']: {key: rule[key] for key in ('type','min','max') if rule[key] is not None} for rule in rules}
    checks = validate_frame(frame, {'columns':declared})['column_checks']
    checks = {name: check for name,check in checks.items() if name in declared}
    if any(check.get('invalid_type',0) or check.get('out_of_range',0) for check in checks.values()):
        findings.append('malformed values or numerical ranges in declared columns')
    id_field = manifest['schema']['record_id_field']
    duplicate_ids = None
    if id_field in frame:
        ids = frame[id_field].str.strip()
        duplicate_ids = int(ids[ids.ne('')].duplicated().sum())
        if duplicate_ids:
            findings.append('duplicated record identifiers')
        if ids.eq('').any():
            findings.append('blank record identifiers')
    else:
        findings.append('record identifier diagnostics unavailable')
    timestamp_checks = {}
    for field in manifest['timestamps']['fields']:
        if field in frame:
            valid = 0
            outside = 0
            for value in frame[field]:
                try:
                    moment = utc_timestamp(value)
                    valid += 1
                    if manifest['observation']['start'] and manifest['observation']['end']:
                        start, end = (utc_timestamp(manifest['observation'][key]) for key in ('start','end'))
                        outside += not (start <= moment < end)
                except (ValueError, TypeError, OverflowError):
                    pass
            timestamp_checks[field] = {'full_aware_values': valid, 'invalid_or_partial_values': len(frame)-valid, 'outside_declared_half_open_interval': outside}
            if (valid != len(frame) and manifest['timestamps']['confidence'] == 'independently_verified') or (outside and manifest['observation']['confidence'] == 'independently_verified'):
                findings.append('timestamp values incomplete, malformed or outside observation')
    label_field = manifest['schema']['label_field']
    nonblank_labels = int(frame[label_field].str.strip().ne('').sum()) if label_field in frame else 0
    return {'sha256': actual_hash, 'record_count': len(frame), 'missing_columns': missing_columns,
            'blank_value_counts': blank_counts, 'declared_column_checks': checks, 'duplicate_record_ids': duplicate_ids,
            'duplicate_csv_rows': int(frame.duplicated().sum()),
            'timestamp_checks': timestamp_checks, 'nonblank_label_records': nonblank_labels,
            'findings': sorted(set(findings)),
            'note': 'Label values/reliability and acquisition identities are not independently certified by file parsing'}


def readiness(manifest, file_path=None):
    errors = metadata_errors(manifest)
    if errors:
        return {'metadata_valid': False, 'errors': errors, 'planning_ready': False, 'training_allowed': False, 'inference_allowed': False}
    inspection = inspect_csv(file_path, manifest) if file_path is not None else None
    gaps = []
    def known(value):
        return isinstance(value, str) and value.strip().lower() not in ('', 'unknown', 'unverified', 'unspecified', 'pending', 'n/a', 'none')
    for key in ('acquisition_method','collection_environment'):
        if not known(manifest[key]):
            gaps.append(f'{key} unavailable')
    if not known(manifest['schema']['id']) or not known(manifest['schema']['parser_version']):
        gaps.append('schema/parser provenance missing')
    if manifest['file']['sha256'] is None or manifest['file']['record_count'] in (None, 0):
        gaps.append('nonempty file hash/count provenance missing')
    provenance = manifest['provenance']
    if not all(provenance[key] for key in ('acquisition_id','collection_group','dependence_groups','lineage_root_sha256','evidence_sha256')) or not all(known(provenance[key]) for key in ('acquisition_id','collection_group')) or not all(known(value) for value in provenance['dependence_groups']):
        gaps.append('collection/acquisition/dependence/lineage evidence incomplete')
    membership = manifest['event_membership']
    if not membership['complete'] or not known(membership['identity_namespace']):
        gaps.append('complete global event membership unavailable')
    if not known(manifest['aggregation']['scope']) or not known(manifest['aggregation']['exposure']) or (manifest['record_unit'] == 'aggregate' and not known(manifest['aggregation']['window'])):
        gaps.append('aggregation/scope/window/exposure metadata incomplete')
    review = manifest['quality_review']
    if review['status'] != 'independently_reviewed' or review['unresolved_findings']:
        gaps.append('independent quality review incomplete or findings unresolved')
    if manifest['record_unit'] == 'unknown' or manifest['privacy'] == 'unknown':
        gaps.append('record unit/privacy classification unknown')
    if inspection and inspection['findings']:
        gaps += inspection['findings']
    labels = manifest['labels']
    return {'metadata_valid': True, 'errors': [], 'inspection': inspection, 'planning_ready': not gaps,
            'planning_blockers': gaps, 'ground_truth_declared_verified': labels['available'] and labels['reliability'] == 'independently_verified',
            'timestamp_confidence': manifest['timestamps']['confidence'],
            'limitations': ['Readiness relies on honest independently reviewed provenance/evidence references; hashes do not authenticate metadata',
                            'Without file inspection, hash/count declarations are not checked against bytes',
                            'Prior AI predictions are never independent attack ground truth',
                            'A single dataset or 30 IP aggregates cannot establish independent evaluation/generalization'],
            'training_allowed': False, 'inference_allowed': False}


def blank_inventory(dataset_id, version, source_type, file_format='csv'):
    """Create metadata scaffolding only; all acquisition facts stay unknown."""
    value = {
        'inventory_schema_version': 1, 'dataset_id': dataset_id, 'dataset_version': version,
        'source_type': source_type, 'acquisition_method': None, 'collection_environment': None,
        'record_unit': 'unknown', 'file': {'format': file_format, 'sha256': None, 'record_count': None},
        'schema': {'id': None, 'parser_version': None, 'record_id_field': None, 'required_columns': [], 'label_field': None, 'column_rules': []},
        'timestamps': {'fields': [], 'confidence': 'unknown', 'evidence_sha256': None},
        'observation': {'start': None, 'end': None, 'duration_seconds': None, 'confidence': 'unknown', 'evidence_sha256': None},
        'aggregation': {'scope': None, 'window': None, 'exposure': None},
        'labels': {'available': False, 'source': 'unknown', 'reliability': 'not_available', 'evidence_sha256': None},
        'privacy': 'unknown',
        'provenance': {'acquisition_id': None, 'collection_group': None, 'dependence_groups': [], 'lineage_root_sha256': [], 'evidence_sha256': None},
        'event_membership': {'complete': False, 'identity_namespace': None, 'event_identity_sha256': [], 'evidence_sha256': None},
        'quality_notes': [], 'quality_review': {'status': 'pending', 'evidence_sha256': None, 'unresolved_findings': []}}
    if metadata_errors(value):
        raise ValueError('Invalid draft inventory identity/category')
    return value
