"""Separately versioned Docker-timestamped native sshd adapter, never historical CSV."""

from collections import Counter
import csv
import hashlib
from io import StringIO
from ipaddress import ip_address
import json
import re

from mini_siem.evaluation.inventory import blank_inventory, metadata_errors, utc_timestamp


ADAPTER_VERSION='docker-sshd-native-v1'
PREFIX=re.compile(r'^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) (?P<message>.*)$')
SUPPORTED=re.compile(r'^(?:Server listening on |Connection from |Accepted publickey for |Failed publickey for |Received disconnect from |Disconnected from |Starting session: |Close session: |Connection closed by |User child is on pid |Received signal |Connection reset by |maximum authentication attempts exceeded |Disconnecting authenticating user )')
COLUMNS=('event_ref','engine_recorded_at','event_occurred_at','source_ip','source_status','format_status','original_message','original_line','collection_id','lab_environment_id','server_container_id','referenced_test_runs','event_label')


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def source_address(message):
    tokens=re.findall(r'\bfrom\s+(\S+)',message)
    disconnected=re.match(r'^Disconnected from (?:authenticating )?user \S+ (\S+) port \d+',message)
    if disconnected:
        tokens=[disconnected.group(1)]
    addresses=set()
    for token in tokens:
        try:
            try:address=ip_address(token)
            except ValueError:
                if not re.fullmatch(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}:',token):raise
                address=ip_address(token[:-1])
            addresses.add(str(address))
        except ValueError:
            return '', 'invalid_source_token'
    if len(addresses)>1:return '', 'ambiguous_source'
    if addresses:return next(iter(addresses)), 'observed_source'
    return '', 'no_supported_source'


def normalize(content, provenance):
    """Preserve raw export separately; log timestamps are engine times, not event times."""
    required=('collection_id','environment_id','server_container_id','daemon_id','test_run_ids')
    if any(key not in provenance for key in required) or not all(isinstance(provenance[key],str) and provenance[key] for key in required[:-1]) or not isinstance(provenance['test_run_ids'],list):
        raise ValueError('Actual collection provenance is required')
    text=content.decode('utf-8')
    records=[]
    # split only LF; no stripping of message whitespace or CR characters.
    lines=text.split('\n')
    if lines[-1]=='':lines.pop()
    if not lines:raise ValueError('Empty telemetry export')
    for line in lines:
        match=PREFIX.fullmatch(line)
        if not match:raise ValueError('Not Docker-timestamped native sshd format')
        timestamp,message=match.group('time'),match.group('message')
        utc_timestamp(timestamp)  # syntax/zone validation only; original precision retained
        supported=bool(SUPPORTED.match(message))
        ip,status=source_address(message) if supported else ('','unsupported_message')
        identity={'namespace':ADAPTER_VERSION,'daemon_id':provenance['daemon_id'],
                  'container_id':provenance['server_container_id'],'engine_recorded_at':timestamp,'message':message}
        records.append(dict(zip(COLUMNS,(sha256(canonical(identity)),timestamp,'',ip,status,
                       'supported_native_message' if supported else 'unsupported_native_message',message,line,
                       provenance['collection_id'],provenance['environment_id'],provenance['server_container_id'],
                       json.dumps(provenance['test_run_ids']),''))))
    return records


def csv_bytes(records):
    stream=StringIO(newline='')
    writer=csv.DictWriter(stream,fieldnames=COLUMNS,lineterminator='\n')
    writer.writeheader();writer.writerows(records)
    return stream.getvalue().encode('utf-8')


def quality_summary(records):
    ids=[row['event_ref'] for row in records]
    return {'adapter_version':ADAPTER_VERSION,'records':len(records),
            'format_counts':dict(Counter(row['format_status'] for row in records)),
            'source_counts':dict(Counter(row['source_status'] for row in records)),
            'duplicate_event_identities':len(ids)-len(set(ids)),
            'event_labels_assigned':0,'engine_timestamps_are_event_times':False,
            'quality_review':'pending','training_allowed':False,'inference_allowed':False}


def inventory_for_collection(records, normalized, raw, collection_manifest):
    p=collection_manifest['provenance']
    result=blank_inventory(p['collection_id'],'1','ssh_authentication')
    result.update(acquisition_method='docker logs --timestamps from verified local isolated sshd',
                  collection_environment=p['environment_id'],record_unit='raw_event',privacy='sensitive')
    result['file'].update(sha256=sha256(normalized),record_count=len(records))
    result['schema'].update(id='mini-siem-native-ssh-csv-v1',parser_version=ADAPTER_VERSION,record_id_field='event_ref',
                            required_columns=list(COLUMNS),label_field=None,
                            column_rules=[{'field':'source_ip','type':'ip','nullable':True,'min':None,'max':None}])
    result['timestamps'].update(fields=['engine_recorded_at'],confidence='unknown',evidence_sha256=sha256(canonical(collection_manifest)))
    result['aggregation'].update(scope='all records in one Docker log export; not historical IP features',window=None,exposure=None)
    runs=p['test_run_ids']
    result['labels'].update(available=bool(runs),source='controlled_experiment_record' if runs else 'none',
                            reliability='unverified' if runs else 'not_available',
                            evidence_sha256=sha256(canonical(collection_manifest['experiments'])) if runs else None)
    result['provenance'].update(acquisition_id='container:'+p['server_container_id'],collection_group='lab:'+p['environment_id'],
                                dependence_groups=['docker-daemon:'+p['daemon_id'],'lab:'+p['environment_id']],
                                lineage_root_sha256=[sha256(raw)],evidence_sha256=sha256(canonical(collection_manifest)))
    unique=sorted({row['event_ref'] for row in records})
    result['event_membership'].update(complete=len(unique)==len(records),identity_namespace=ADAPTER_VERSION,
                                      event_identity_sha256=unique,evidence_sha256=sha256(canonical(collection_manifest)))
    result['quality_notes']=['Raw evidence retained; engine record time is not original sshd event time',
                             'Scenario references are collection-level intent, not per-event labels',
                             'Clock accuracy, exposure and independent quality/label review are not established',
                             'Repeated exports from this server/environment/daemon are dependent, not independent test data']
    if len(unique)!=len(records):result['quality_review']['unresolved_findings']=['duplicate engine-time/message identities; no invented disambiguation']
    if any(row['format_status']=='unsupported_native_message' for row in records):
        result['quality_review']['unresolved_findings'].append('unsupported native messages require review')
    if metadata_errors(result):raise ValueError('Collection inventory inconsistent')
    return result
