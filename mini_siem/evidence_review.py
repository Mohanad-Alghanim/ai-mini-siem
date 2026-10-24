"""Read-only native SSH evidence review; no privileged operations or event labels."""

import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
import tempfile
import uuid

from mini_siem.evaluation.inventory import utc_timestamp
from mini_siem.feature_contract import read_contract as read_json
from mini_siem.kali_ssh_lab import inspect_collection
from mini_siem.native_lab.control import validate_experiment
from mini_siem.native_lab.safety import digest
from mini_siem.native_lab.telemetry import canonical, csv_bytes, inventory, normalize, summary

VERSION = 'ssh-evidence-review-v1'
CLASSES = ('authentication_success_evidence', 'authentication_failure_evidence',
           'session_open_evidence', 'session_close_evidence',
           'connection_or_transport_event', 'unsupported_or_ambiguous')
PEER = r'(?P<account>[A-Za-z0-9_-]+) from (?P<ip>[^\s]+) port (?P<port>[0-9]+)'
AUTH = re.compile(r'(?P<result>Accepted|Failed) publickey for '+PEER+r' ssh2(?:: (?:ED25519|RSA|ECDSA|ED25519-CERT|RSA-CERT|ECDSA-CERT) SHA256:[A-Za-z0-9+/=]+)?(?: \[preauth\])?')
SESSION = re.compile(r'(?P<action>Starting session: command for|Close session: user) '+PEER+r' id [0-9]+')
TRANSPORT = re.compile(r'(?:Server listening on 127\.0\.0\.1 port 2222\.|Connection from [^\s]+ port [0-9]+ on [^\s]+ port [0-9]+(?: rdomain [0-9]+)?|Received disconnect from [^\s]+ port [0-9]+:[^\r\n]*|Disconnected from (?:authenticating )?user [A-Za-z0-9_-]+ [^\s]+ port [0-9]+(?: \[preauth\])?|Received signal [0-9]+; terminating\.)')


def classify(message):
    """Explicit anchored server evidence only; unknown syntax stays ambiguous."""
    match = AUTH.fullmatch(message) or SESSION.fullmatch(message)
    if match:
        fields = match.groupdict()
        try:
            ipaddress.ip_address(fields['ip'])
            if not 1 <= int(fields['port']) <= 65535:
                raise ValueError('Invalid port')
        except ValueError:
            return {'category': CLASSES[-1]}
        if 'result' in fields:
            category = CLASSES[0] if fields['result'] == 'Accepted' else CLASSES[1]
        else:
            category = CLASSES[2] if fields['action'].startswith('Starting') else CLASSES[3]
        return {'category': category, 'account': fields['account'], 'ip': fields['ip']}
    return {'category': CLASSES[4] if TRANSPORT.fullmatch(message) else CLASSES[-1]}


def unsupported_reason(message):
    # Only fixed descriptions leave this function; never copy arbitrary tokens.
    if re.match(r'^(?:pam_|PAM[: (])', message):
        return ('pam_related_format', 'No PAM message rule in the native adapter; message alone does not establish lab authentication outcome', 'format_and_insufficient_evidence')
    if re.match(r'^(?:Accepted|Failed|Invalid user|error:|fatal:)', message):
        return ('authentication_or_diagnostic_format', 'Prefix is outside adapter rules or diagnostic syntax is unrecognized; no outcome inferred', 'format_and_insufficient_evidence')
    if re.match(r'^(?:Connection |Disconnected |Received |Starting |Close )', message):
        return ('connection_or_session_format', 'Native connection/session syntax is outside adapter prefix rules', 'format')
    return ('unrecognized_native_message', 'No current native adapter prefix rule; meaning cannot be established from the available implementation', 'insufficient_evidence')


def snapshot_collection(source, target):
    """Copy exact input bytes to private temporary storage before verification."""
    source = Path(source)
    for name in ('collection.json','raw-sshd.log','events.csv','inventory.json','quality.json'):
        path = source/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing or symlinked collection evidence')
        (target/name).write_bytes(path.read_bytes())
    collection = read_json(target/'collection.json')
    if not isinstance(collection.get('experiments'), dict):
        raise ValueError('Missing experiment index')
    if (source/'experiments').is_symlink():
        raise ValueError('Symlinked experiment directory')
    (target/'experiments').mkdir(mode=0o700)
    for name in collection['experiments']:
        if not re.fullmatch(r'experiment-[0-9a-f-]{36}\.json', name):
            raise ValueError('Invalid experiment reference')
        path = source/'experiments'/name
        if path.is_symlink() or not path.is_file() or (source/'experiments').is_symlink():
            raise ValueError('Missing or symlinked experiment evidence')
        (target/'experiments'/name).write_bytes(path.read_bytes())
    if (source/'experiments').exists():
        actual = {p.name for p in (source/'experiments').iterdir()}
        if actual != set(collection['experiments']):
            raise ValueError('Unindexed or missing experiment evidence')
    return collection


def verified_review(source):
    with tempfile.TemporaryDirectory(prefix='siem-evidence-') as temporary:
        root = Path(temporary)
        collection = snapshot_collection(source, root)
        checked = inspect_collection(root)  # Existing hash checks and native adapter.
        p = collection['provenance']
        if collection['version'] != 1 or any(collection[key] is not False for key in ('training_allowed','inference_allowed','event_labels_assigned')):
            raise ValueError('Unsupported collection state or label authorization')
        if p['server_identity'] != digest(canonical(p['process'])) or p['host_boot_id'] != p['process']['boot_id']:
            raise ValueError('Inconsistent process provenance')
        for value in (p['collection_id'], p['environment_id']):
            uuid.UUID(value)
        if utc_timestamp(collection['collection_finished_at']) < utc_timestamp(collection['collection_started_at']):
            raise ValueError('Invalid collection interval')
        raw = (root/'raw-sshd.log').read_bytes()
        records = normalize(raw, p)
        if read_json(root/'quality.json') != summary(records):
            raise ValueError('Quality summary does not match evidence')
        if read_json(root/'inventory.json') != inventory(records, csv_bytes(records), raw, collection):
            raise ValueError('Inventory draft is inconsistent with collection provenance')
        runs = []
        for name in sorted(collection['experiments']):
            run = read_json(root/'experiments'/name)
            validate_experiment(run, {'environment_id':p['environment_id'], 'account':p['account']}, p['process'])
            if name != 'experiment-'+str(uuid.UUID(run['experiment_id']))+'.json':
                raise ValueError('Experiment identity mismatch')
            runs.append(run)
        if len(set(p['experiment_ids'])) != len(p['experiment_ids']) or set(p['experiment_ids']) != {run['experiment_id'] for run in runs}:
            raise ValueError('Experiment index and provenance disagree')
        return build_report(records, runs, checked, collection)


def build_report(records, runs, checked, collection):
    evidence, unsupported = [], []
    for record in records:
        finding = classify(record['original_message'])
        evidence.append((record, finding))
        if record['format_status'] == 'unsupported_native':
            category, reason, gap = unsupported_reason(record['original_message'])
            unsupported.append({'event_ref':record['event_ref'], 'category':category,
                                'reason':reason, 'support_gap':gap})
    correlations = []
    account = collection['provenance']['account']
    for run in runs:
        target = CLASSES[0] if run['expected_result'] == 'authentication_success' else CLASSES[1]
        candidates = [r['event_ref'] for r, f in evidence if f['category'] == target and
                      f.get('account') == account and f.get('ip') == '127.0.0.1']
        correlations.append({'experiment_id':run['experiment_id'], 'scenario':run['scenario'],
            'expected_result':run['expected_result'], 'manifest_status':run['status'],
            'recorded_attempts':len(run['actions']),
            'client_exit_codes':[a['client_exit_code'] for a in run['actions']],
            'candidate_server_evidence_refs':candidates, 'correlation_confidence':'unresolved',
            'limitations':['Candidates match server account, loopback source and expected evidence type only',
                          'No trustworthy event timestamps or per-attempt connection identifiers; candidates may overlap experiments',
                          'Client exits and collection membership do not prove an event-to-experiment relationship']})
    counts = Counter(f['category'] for _, f in evidence)
    messages = Counter(r['original_message'] for r in records)
    candidates = {ref for item in correlations for ref in item['candidate_server_evidence_refs']}
    return {'review_version':VERSION, 'collection_manifest_sha256':digest(canonical(collection)),
        'integrity':'hashes, native normalization, provenance, inventory and manifest consistency verified; not independent authentication',
        'quality':dict(summary(records), total_records=len(records),
            source_ip_coverage={'with_source':sum(bool(r['source_ip']) for r in records), 'total':len(records)},
            unsupported_categories=dict(Counter(item['category'] for item in unsupported)),
            source_status_counts=dict(Counter(r['source_status'] for r in records)),
            supported_but_ambiguous_records=sum(r['format_status']=='supported_native' and f['category']==CLASSES[-1] for r,f in evidence),
            repeated_message_occurrences=sum(n-1 for n in messages.values()),
            duplicate_event_refs=len(records)-len({r['event_ref'] for r in records}),
            completeness='unverified; only available native process-log snapshot reviewed',
            original_event_timestamps='unavailable; collection and experiment times cannot substitute',
            label_reliability='no independently verified event or attack labels',
            provenance='process/account/environment and experiment consistency checked; external provenance not independently certified'),
        'evidence_counts':{category:counts[category] for category in CLASSES},
        'event_evidence':[{'event_ref':r['event_ref'], 'category':f['category']} for r, f in evidence],
        'unsupported_records':unsupported, 'experiment_correlations':correlations,
        'correlation_summary':{'verified_assignments':0, 'unresolved_event_refs':[r['event_ref'] for r in records],
            'without_candidate_experiment_refs':[r['event_ref'] for r in records if r['event_ref'] not in candidates],
            'missing_experiment_manifests':not bool(runs)},
        'readiness_blockers':checked['inventory'].get('planning_blockers', []),
        'event_labels_assigned':False, 'training_allowed':False, 'inference_allowed':False,
        'analysis_scope':'Only supplied collection evidence is analyzed; internal consistency is not independent validation'}


def markdown(report):
    lines = ['# SSH evidence review', '', 'Review scheme: '+VERSION, '',
             'Training allowed: false. Inference allowed: false. No event labels assigned.', '',
             'Integrity checks establish internal consistency, not independently authenticated ground truth.', '',
             '## Quality', '', '```json', json.dumps(report['quality'], indent=2), '```', '',
             '## Evidence categories', '']
    lines += [f'- {key}: {value}' for key, value in report['evidence_counts'].items()]
    lines += ['', '## Unsupported records', '', 'References replace sensitive raw message examples. Unsupported does not mean malicious.', '']
    lines += [f"- `{item['event_ref']}`: {item['category']}. {item['reason']}. Gap: {item['support_gap']}." for item in report['unsupported_records']]
    lines += ['', '## Experiment correlation', '', 'All event-to-experiment assignments remain unresolved. Candidate lists are not labels.', '']
    for item in report['experiment_correlations']:
        lines += [f"- Experiment `{item['experiment_id']}` ({item['scenario']}): expected {item['expected_result']}; status {item['manifest_status']}; {item['recorded_attempts']} attempts; client exits {item['client_exit_codes']}; confidence unresolved.",
                  '  Candidate references: '+(', '.join('`'+ref+'`' for ref in item['candidate_server_evidence_refs']) or 'none')+'.']
    if not report['experiment_correlations']:
        lines += ['No experiment manifests were supplied; per-experiment correlation is unavailable.']
    lines += ['', '## Limitations and readiness', '',
              'All records remain unassigned. Repeated messages can be separate events, not duplicate capture errors.',
              'No trusted original event times, independent labels, completeness certification or generalization evidence.', '']
    lines += ['- '+item for item in report['readiness_blockers']]
    return '\n'.join(lines)+'\n'


def review(collection_dir, output_dir):
    source, target = Path(collection_dir).resolve(), Path(output_dir).resolve()
    if target.exists() or target.is_relative_to(source) or source.is_relative_to(target):
        raise ValueError('Use a fresh output directory separate from evidence')
    report = verified_review(source)
    target.mkdir(parents=True, mode=0o700, exist_ok=False)
    (target/'review.json').write_text(json.dumps(report, indent=2)+'\n')
    (target/'review.md').write_text(markdown(report))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collection-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = review(args.collection_dir, args.output_dir)
        print(json.dumps({'review_version':VERSION, 'records':report['quality']['total_records'],
                          'training_allowed':False, 'inference_allowed':False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('Evidence review refused: check complete collection files, integrity, supported provenance and a fresh separate output directory. No raw evidence was changed.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
