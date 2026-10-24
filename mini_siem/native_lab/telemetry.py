"""kali-sshd-native-v1: preserve native -E log lines; never infer event times."""

import csv
from datetime import datetime, timezone
import io
import ipaddress
import json
import re

from mini_siem.evaluation.inventory import blank_inventory, metadata_errors
from mini_siem.native_lab.safety import digest

VERSION = 'kali-sshd-native-v1'
COLUMNS = ('event_ref','original_message','source_ip','source_status','format_status',
           'event_occurred_at','event_label','collection_id','server_identity','experiment_references')
SUPPORTED = re.compile(r'^(Server listening on |Connection from |Accepted publickey |Failed publickey |Received disconnect |Disconnected from |Starting session:|Close session:|Connection closed by |Connection reset by |User child is |Received signal |maximum authentication attempts exceeded |Disconnecting authenticating user )')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def normalize(raw, provenance):
    if not raw or len(raw) > 5*1024*1024:
        raise ValueError('Empty or oversized native log snapshot')
    text = raw.decode('utf-8')
    if not text.endswith('\n') or '\x00' in text:
        raise ValueError('Incomplete or incompatible native log snapshot')
    if not all(provenance.get(key) for key in ('collection_id','server_identity','environment_id')):
        raise ValueError('Missing collection/process provenance')
    lines = text.split('\n')[:-1]
    # Recognizable native messages establish the adapter, but unknown lines are
    # preserved. A CSV or wholly unrelated file is not silently reinterpreted.
    if not any(SUPPORTED.match(line) for line in lines):
        raise ValueError('Not a supported native OpenSSH log export')
    records = []
    for index, line in enumerate(lines):
        supported = bool(SUPPORTED.match(line))
        tokens = re.findall(r'\bfrom ([^\s]+)', line) if supported else []
        disconnected = re.fullmatch(r'Disconnected from (?:authenticating )?user [A-Za-z0-9_-]+ ([^\s]+) port [0-9]+(?:.*)?', line) if supported else None
        if disconnected and len(tokens) == 1:
            tokens = [disconnected.group(1)]
        peer, status = '', 'missing_source'
        if len(tokens) > 1:
            status = 'ambiguous_source'
        elif tokens:
            try:
                token = tokens[0]
                try:
                    peer = str(ipaddress.ip_address(token))
                except ValueError:
                    if token.endswith(':') and '.' in token:
                        peer = str(ipaddress.IPv4Address(token[:-1]))
                    else:
                        raise
                status = 'observed_source'
            except ValueError:
                status = 'invalid_source'
        record = dict.fromkeys(COLUMNS, '')
        record.update(event_ref=digest(canonical([VERSION, provenance['server_identity'], index, line])),
                      original_message=line, source_ip=peer, source_status=status,
                      format_status='supported_native' if supported else 'unsupported_native',
                      collection_id=provenance['collection_id'], server_identity=provenance['server_identity'],
                      experiment_references=json.dumps(provenance.get('experiment_ids', [])))
        records.append(record)
    return records


def csv_bytes(records):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=COLUMNS, lineterminator='\n')
    writer.writeheader(); writer.writerows(records)
    return output.getvalue().encode()


def summary(records):
    return {'records': len(records), 'supported_records': sum(r['format_status']=='supported_native' for r in records),
            'unsupported_records': sum(r['format_status']=='unsupported_native' for r in records),
            'records_with_source': sum(bool(r['source_ip']) for r in records),
            'event_labels_assigned': False, 'training_allowed': False, 'inference_allowed': False}


def inventory(records, normalized, raw, collection):
    p = collection['provenance']
    value = blank_inventory('native-ssh-'+p['collection_id'], '1', 'ssh_authentication')
    value.update(acquisition_method='snapshot of dedicated native OpenSSH -E log',
                 collection_environment='Kali local loopback lab '+p['environment_id'], record_unit='raw_event', privacy='restricted')
    value['file'].update(sha256=digest(normalized), record_count=len(records))
    value['schema'].update(id=VERSION, parser_version=VERSION, record_id_field='event_ref', required_columns=list(COLUMNS))
    value['labels'].update(source='none')
    value['aggregation'].update(scope='available process-lifetime log prefix; not an exposure estimate')
    evidence = digest(canonical(collection))
    value['provenance'].update(acquisition_id=p['server_identity'], collection_group=p['environment_id'],
        dependence_groups=['host:'+p['host_boot_id'], 'lab:'+p['environment_id']],
        lineage_root_sha256=[digest(raw)], evidence_sha256=evidence)
    value['event_membership'].update(complete=True, identity_namespace=VERSION,
        event_identity_sha256=[r['event_ref'] for r in records], evidence_sha256=evidence)
    value['quality_notes'] = ['Native -E messages have no independently verified event timestamp; collection times are separate',
        'Scenario intent is not an event label; source is loopback, not independent external hosts',
        'Repeated captures of one process overlap; groups remain dependent; no training or inference authorization']
    value['quality_review']['unresolved_findings'] = ['clock, completeness, event correlation and independent review pending']
    if metadata_errors(value):
        raise ValueError('Invalid inventory draft')
    return value
