"""Synthetic evidence snapshots; no root, live SSH, credentials or private data."""

import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from mini_siem.evidence_review import CLASSES, classify, main, review, verified_review
from mini_siem.native_lab.telemetry import canonical, csv_bytes, inventory, normalize, summary
from mini_siem.native_lab.safety import digest


@pytest.fixture
def capture(tmp_path):
    root = tmp_path/'capture'; root.mkdir(); (root/'experiments').mkdir()
    process = {'pid':12345,'start_ticks':'99','uid':0,'boot_id':'synthetic-boot','executable':'/usr/sbin/sshd'}
    account = 'msl0123456789'
    p = {'collection_id':'a7f1a38f-9556-400a-a012-0466ea703ff0',
         'environment_id':'981d567a-a41b-4419-aebf-18db9c4ac997',
         'server_identity':digest(canonical(process)), 'host_boot_id':process['boot_id'],
         'process':process,'account':account,'experiment_ids':[]}
    c = {'version':1,'adapter':'kali-sshd-native-v1','provenance':p,
         'collection_started_at':'2026-01-01T12:00:00+00:00','collection_finished_at':'2026-01-01T12:00:01+00:00',
         'configuration_sha256':'a'*64,'source':'dedicated native OpenSSH -E process log',
         'experiments':{},'training_allowed':False,'inference_allowed':False,'event_labels_assigned':False}
    for number, scenario in enumerate(('success','single-failure','three-failures','session-logout'), 1):
        identifier = f'00000000-0000-4000-a000-{number:012d}'
        good = scenario in ('success','session-logout')
        run = {'version':1,'experiment_id':identifier,'scenario':scenario,'environment_id':p['environment_id'],
               'server_identity':process,'account':account,'started_at':'2026-01-01T11:00:00Z','ended_at':'2026-01-01T11:00:10Z',
               'expected_result':'authentication_success' if good else 'authentication_rejection',
               'event_labels_assigned':False,'status':'completed_pending_evidence_review',
               'actions':[{'attempt':i+1,'started_at':'2026-01-01T11:00:01Z','ended_at':'2026-01-01T11:00:02Z',
                           'credential_role':'good' if good else 'wrong','client_exit_code':0 if good else 255}
                          for i in range(3 if scenario=='three-failures' else 1)]}
        name = 'experiment-'+identifier+'.json'; content=json.dumps(run).encode()
        (root/'experiments'/name).write_bytes(content); c['experiments'][name]=digest(content)
        p['experiment_ids'].append(identifier)
    raw = (f'Server listening on 127.0.0.1 port 2222.\n'
           f'Accepted publickey for {account} from 127.0.0.1 port 50000 ssh2: ED25519 SHA256:PrivateFingerprint\n'
           f'Failed publickey for {account} from 127.0.0.1 port 50001 ssh2\n'
           f'Failed publickey for {account} from 127.0.0.1 port 50001 ssh2\n'
           f'Starting session: command for {account} from 127.0.0.1 port 50000 id 0\n'
           f'Close session: user {account} from 127.0.0.1 port 50000 id 0\n'
           'pam_unix(sshd:session): private-marker 192.0.2.99\n'
           'Unknown PRIVATE-CONTENT\n').encode()
    records=normalize(raw,p); normalized=csv_bytes(records)
    c.update(raw_sha256=digest(raw), normalized_sha256=digest(normalized))
    (root/'raw-sshd.log').write_bytes(raw); (root/'events.csv').write_bytes(normalized)
    for name,value in (('collection.json',c),('inventory.json',inventory(records,normalized,raw,c)),('quality.json',summary(records))):
        (root/name).write_text(json.dumps(value))
    return root


def snapshot(root):
    return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_integrity_review_is_read_only_and_privacy_safe(capture,tmp_path,capsys):
    before=snapshot(capture); output=tmp_path/'reports'
    with patch('sqlite3.connect',side_effect=AssertionError('no SQLite')), patch('mini_siem.ml.model.predict_records',side_effect=AssertionError('no inference')), patch('subprocess.Popen',side_effect=AssertionError('no process')):
        assert main(['--collection-dir',str(capture),'--output-dir',str(output)])==0
    report=json.loads((output/'review.json').read_text())
    assert snapshot(capture)==before
    assert report['quality']['total_records']==8
    assert report['evidence_counts']['authentication_success_evidence']==1
    assert report['evidence_counts']['authentication_failure_evidence']==2
    assert report['evidence_counts']['session_open_evidence']==1
    assert report['evidence_counts']['session_close_evidence']==1
    assert report['quality']['repeated_message_occurrences']==1
    assert report['quality']['duplicate_event_refs']==0
    assert len(report['unsupported_records'])==2
    assert not report['training_allowed'] and not report['inference_allowed']
    all_output=(output/'review.json').read_text()+(output/'review.md').read_text()+capsys.readouterr().out
    for private in ('msl0123456789','127.0.0.1','192.0.2.99','PrivateFingerprint','private-marker','PRIVATE-CONTENT',str(capture)):
        assert private not in all_output


def test_correlation_without_event_times_remains_unresolved(capture):
    report=verified_review(capture)
    runs=report['experiment_correlations']
    assert len(runs)==4 and sum(r['recorded_attempts'] for r in runs)==6
    assert all(r['correlation_confidence']=='unresolved' for r in runs)
    assert runs[0]['candidate_server_evidence_refs']==runs[3]['candidate_server_evidence_refs']
    assert report['correlation_summary']['verified_assignments']==0
    assert len(report['correlation_summary']['unresolved_event_refs'])==8
    assert not report['event_labels_assigned']


@pytest.mark.parametrize('message', [
    'client says Accepted publickey for user from 127.0.0.1 port 22 ssh2',
    'Accepted publickey for user from host.invalid port 22 ssh2',
    'Accepted publickey for user from 127.0.0.1 port 99999 ssh2',
    'Accepted publickey for user from 127.0.0.1 port 22 ssh2 trailing invented text',
    'Failed publickey for invalid user user from 127.0.0.1 port 22 ssh2',
    'Failed publickey', 'pam_unix(sshd:session): session opened for user user',
    'Client exit code 0', 'Client exit code 255',
])
def test_ambiguous_messages_never_prove_authentication(message):
    assert classify(message)['category']==CLASSES[-1]


@pytest.mark.parametrize('file', ['raw-sshd.log','events.csv','quality.json','inventory.json','collection.json'])
def test_tampered_or_missing_files_refused(capture,tmp_path,file):
    path=capture/file; original=path.read_bytes()
    path.write_bytes(original+b'bad')
    assert main(['--collection-dir',str(capture),'--output-dir',str(tmp_path/'output')])==2
    assert not (tmp_path/'output').exists()
    path.unlink()
    with pytest.raises((ValueError,OSError)): verified_review(capture)


def test_missing_or_tampered_experiment_refused(capture):
    file=next((capture/'experiments').iterdir()); file.write_text('{}')
    with pytest.raises(ValueError): verified_review(capture)
    file.unlink()
    with pytest.raises((ValueError,OSError)): verified_review(capture)


def test_missing_experiment_index_is_unresolved_not_invented(capture):
    c=json.loads((capture/'collection.json').read_text())
    c['experiments']={}; c['provenance']['experiment_ids']=[]
    for p in (capture/'experiments').iterdir(): p.unlink()
    raw=(capture/'raw-sshd.log').read_bytes(); records=normalize(raw,c['provenance']); normalized=csv_bytes(records)
    c['normalized_sha256']=digest(normalized)
    (capture/'events.csv').write_bytes(normalized)
    (capture/'collection.json').write_text(json.dumps(c))
    (capture/'inventory.json').write_text(json.dumps(inventory(records,normalized,raw,c)))
    report=verified_review(capture)
    assert report['correlation_summary']['missing_experiment_manifests']
    assert report['experiment_correlations']==[]


def test_existing_output_and_evidence_nested_output_refused(capture,tmp_path):
    output=tmp_path/'output'; output.mkdir(); (output/'keep').write_text('unchanged')
    for path in (output,capture/'report'):
        with pytest.raises(ValueError): review(capture,path)
    assert (output/'keep').read_text()=='unchanged'
    assert not (capture/'report').exists()


def test_unindexed_experiment_refused(capture):
    (capture/'experiments'/'extra.json').write_text('{}')
    with pytest.raises(ValueError): verified_review(capture)


def test_pytest_discovery_is_confined_to_tests(tmp_path):
    repo=Path(__file__).resolve().parents[1]
    (tmp_path/'pytest.ini').write_bytes((repo/'pytest.ini').read_bytes())
    (tmp_path/'tests').mkdir(); (tmp_path/'data').mkdir()
    (tmp_path/'tests'/'test_safe.py').write_text('def test_safe(): pass\n')
    (tmp_path/'data'/'test_private.py').write_text('raise RuntimeError("private capture was inspected")\n')
    result=subprocess.run([sys.executable,'-m','pytest','--collect-only','-q'],cwd=tmp_path,capture_output=True,text=True,timeout=15)
    assert result.returncode==0 and 'test_safe' in result.stdout
    assert 'test_private' not in result.stdout+result.stderr


@pytest.mark.parametrize('file,mutate', [
    ('quality.json',lambda v:v.update(records=999)),
    ('inventory.json',lambda v:v['file'].update(record_count=999)),
    ('collection.json',lambda v:v.update(training_allowed=True)),
    ('collection.json',lambda v:v['provenance'].update(server_identity='f'*64)),
    ('collection.json',lambda v:v['provenance'].update(experiment_ids=[])),
])
def test_semantically_inconsistent_json_refused(capture,file,mutate):
    path=capture/file; value=json.loads(path.read_text()); mutate(value); path.write_text(json.dumps(value))
    with pytest.raises(ValueError): verified_review(capture)


def test_wrong_account_manifest_refused_even_if_hash_updated(capture):
    c=json.loads((capture/'collection.json').read_text()); name=next(iter(c['experiments']))
    path=capture/'experiments'/name; run=json.loads(path.read_text()); run['account']='foreign_account'
    path.write_text(json.dumps(run)); c['experiments'][name]=digest(path.read_bytes())
    (capture/'collection.json').write_text(json.dumps(c))
    raw=(capture/'raw-sshd.log').read_bytes(); rows=normalize(raw,c['provenance'])
    (capture/'inventory.json').write_text(json.dumps(inventory(rows,csv_bytes(rows),raw,c)))
    with pytest.raises(ValueError): verified_review(capture)
