"""Synthetic Docker states and native log fixtures; never start SSH services."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from mini_siem.evaluation.inventory import metadata_errors
from mini_siem.lab.control import SCENARIOS, prepare, scenario, validate_experiment
from mini_siem.lab.isolation import COMPOSE, validate_config, validate_state
from mini_siem.lab.telemetry import ADAPTER_VERSION, csv_bytes, inventory_for_collection, normalize, quality_summary, sha256
from mini_siem.ssh_lab import main


@pytest.fixture
def provenance():
    return {'collection_id':'synthetic-collection','environment_id':'mini-siem-ssh-012345abcdef',
            'server_container_id':'a'*64,'daemon_id':'synthetic-daemon','test_run_ids':['synthetic-run']}


@pytest.fixture
def raw():
    return (b'2026-01-01T12:00:00.123456789Z Server listening on 0.0.0.0 port 2222.\n'
            b'2026-01-01T12:00:01.123456789Z Accepted publickey for labuser from 192.0.2.1 port 12345 ssh2\n'
            b'2026-01-01T12:00:02.123456789Z Failed publickey for labuser from 192.0.2.1 port 12346 ssh2\n'
            b'2026-01-01T12:00:03Z future unknown message private-marker\n')


@pytest.fixture
def docker_state(tmp_path):
    state={'environment_id':'mini-siem-ssh-012345abcdef','keys_dir':str(tmp_path/'keys'),'uid':1000,'gid':1000,'configuration_sha256':'f'*64}
    network={'Name':'synthetic-internal','Id':'network-id','Internal':True,'Driver':'bridge','EnableIPv6':False,
             'Labels':{'com.docker.compose.project':state['environment_id']},'IPAM':{'Config':[{'Subnet':'172.20.0.0/16'}]},'Containers':{'a'*64:{},'b'*64:{}}}
    containers={}
    for index,name in enumerate(('ssh-server','ssh-client')):
        source=str(tmp_path/'keys/good.pub') if index==0 else str(tmp_path/'keys')
        containers[name]={'Id':('a' if index==0 else 'b')*64,'Image':'sha256:synthetic-image',
          'State':{'Running':True,'StartedAt':'2026-01-01T11:59:00Z'},
          'Config':{'User':'' if index==0 else '1000:1000','Labels':{'com.docker.compose.project':state['environment_id'],'com.docker.compose.service':name,'org.mini-siem.lab':'ssh-task-010','org.mini-siem.environment':state['environment_id']}},
          'HostConfig':{'NetworkMode':network['Name'],'Privileged':False,'PublishAllPorts':False,'PortBindings':{},'PidMode':'','UsernsMode':'','IpcMode':'private','ReadonlyRootfs':True,'CapDrop':['ALL'],'CapAdd':['SETUID','SETGID','SYS_CHROOT'] if index==0 else [],'SecurityOpt':['no-new-privileges:true']},
          'NetworkSettings':{'Ports':{},'Networks':{network['Name']:{'NetworkID':network['Id'],'IPAddress':f'172.20.0.{index+2}'}}},
          'Mounts':[{'Type':'bind','Source':source,'Destination':'/lab/authorized_key' if index==0 else '/lab-keys','RW':False}]}
    return state,containers,network


def test_native_normalization_preserves_messages_and_clock_semantics(raw,provenance):
    records=normalize(raw,provenance)
    assert len(records)==4
    assert records[1]['source_ip']=='192.0.2.1'
    assert records[0]['source_ip']==''
    assert records[1]['engine_recorded_at']=='2026-01-01T12:00:01.123456789Z'
    assert all(row['event_occurred_at']==row['event_label']=='' for row in records)
    assert records[3]['original_message']=='future unknown message private-marker'
    assert records[3]['format_status']=='unsupported_native_message'
    assert records[1]['original_line'].encode() in raw
    assert b'private-marker' in csv_bytes(records)
    assert quality_summary(records)['format_counts']['unsupported_native_message']==1


@pytest.mark.parametrize('text',[
    b'LineId,Date,Day,Time,Content\n1,Jun,1,12:00:00,example\n',
    b'Jan 1 12:00:00 Accepted publickey\n',
    b'2026-01-01T12:00:00 Accepted publickey\n',
    b'2026-99-01T12:00:00Z Accepted publickey\n',b'',b'\xff\n',
])
def test_incompatible_formats_rejected_without_historical_fallback(text,provenance):
    with pytest.raises(ValueError):normalize(text,provenance)


@pytest.mark.parametrize('message,ip,status',[
    ('Received disconnect from 192.0.2.1: 11: Bye Bye','192.0.2.1','observed_source'),
    ('Accepted publickey for labuser from 2001:db8::1 port 22','2001:db8::1','observed_source'),
    ('Accepted publickey for labuser from 999.0.2.1 port 22','','invalid_source_token'),
    ('Connection from 192.0.2.1 from 192.0.2.2','','ambiguous_source'),
    ('Disconnected from user labuser 192.0.2.1 port 22','192.0.2.1','observed_source'),
    ('Server listening on 0.0.0.0 port 2222.','','no_supported_source'),
])
def test_observable_source_addresses_only(message,ip,status,provenance):
    row=normalize(('2026-01-01T12:00:00Z '+message+'\n').encode(),provenance)[0]
    assert (row['source_ip'],row['source_status'])==(ip,status)


def test_identity_stable_for_overlapping_exports_not_new_independent_data(raw,provenance):
    first=normalize(raw,provenance)
    changed=dict(provenance,collection_id='another-collection')
    second=normalize(raw,changed)
    assert [row['event_ref'] for row in first]==[row['event_ref'] for row in second]
    different=normalize(raw,dict(provenance,server_container_id='b'*64))
    assert first[0]['event_ref']!=different[0]['event_ref']


def test_inventory_hashes_provenance_and_no_independent_review(raw,provenance):
    records=normalize(raw,provenance);normalized=csv_bytes(records)
    collection={'provenance':provenance,'experiments':[{'run_id':'synthetic-run','label_status':'intent_only'}]}
    inventory=inventory_for_collection(records,normalized,raw,collection)
    assert metadata_errors(inventory)==[]
    assert inventory['file']['sha256']==sha256(normalized)
    assert inventory['file']['record_count']==4
    assert inventory['provenance']['lineage_root_sha256']==[sha256(raw)]
    assert inventory['quality_review']['status']=='pending'
    assert inventory['labels']['reliability']=='unverified'
    assert inventory['timestamps']['confidence']=='unknown'
    assert inventory['observation']['duration_seconds'] is None
    assert inventory['schema']['parser_version']==ADAPTER_VERSION
    assert inventory['schema']['parser_version']!='ssh-historical-v2'
    assert 'docker-daemon:synthetic-daemon' in inventory['provenance']['dependence_groups']


def test_duplicate_identity_not_silently_disambiguated(provenance):
    raw=b'2026-01-01T12:00:00Z Server listening on 0.0.0.0 port 2222.\n'*2
    records=normalize(raw,provenance)
    inventory=inventory_for_collection(records,csv_bytes(records),raw,{'provenance':provenance,'experiments':[]})
    assert quality_summary(records)['duplicate_event_identities']==1
    assert len(records)==2 and not inventory['event_membership']['complete']


def test_static_isolation_configuration():
    config=json.loads(COMPOSE.read_text())
    assert validate_config(config)
    assert all('ports' not in service for service in config['services'].values())
    server=(COMPOSE.parent/'server/sshd_config').read_text()
    assert 'PasswordAuthentication no' in server and 'ForceCommand /bin/true' in server


@pytest.mark.parametrize('mutation',[
    lambda c:c['networks']['ssh-internal'].update(internal=False),
    lambda c:c['services']['ssh-server'].update(ports=['2222:2222']),
    lambda c:c['services']['ssh-client'].update(network_mode='host'),
    lambda c:c['services']['ssh-server'].update(privileged=True),
    lambda c:c['services']['ssh-server'].update(cap_add=['ALL']),
    lambda c:c['services']['ssh-client'].update(volumes=['/:/host:ro']),
    lambda c:c['services']['ssh-client'].update(dns=['8.8.8.8']),
])
def test_static_isolation_fail_closed(mutation):
    config=json.loads(COMPOSE.read_text());mutation(config)
    with pytest.raises(ValueError):validate_config(config)


def test_valid_runtime_isolation_state(docker_state):
    state,containers,network=docker_state
    assert validate_state(state,containers,network,'synthetic-daemon','unix:///var/run/docker.sock')


@pytest.mark.parametrize('change',['ports','extra-network','foreign-peer','privileged','writable','capability','public-subnet','remote-daemon','wrong-project'])
def test_runtime_isolation_fail_closed(docker_state,change):
    state,containers,network=deepcopy(docker_state)
    endpoint='unix:///var/run/docker.sock'
    server=containers['ssh-server']
    if change=='ports':server['HostConfig']['PortBindings']={'2222/tcp':[{'HostIp':'0.0.0.0','HostPort':'2222'}]}
    if change=='extra-network':server['NetworkSettings']['Networks']['external']={}
    if change=='foreign-peer':network['Containers']['foreign']={}
    if change=='privileged':server['HostConfig']['Privileged']=True
    if change=='writable':server['Mounts'][0]['RW']=True
    if change=='capability':server['HostConfig']['CapAdd'].append('NET_ADMIN')
    if change=='public-subnet':network['IPAM']['Config'][0]['Subnet']='8.0.0.0/8'
    if change=='remote-daemon':endpoint='tcp://remote:2375'
    if change=='wrong-project':server['Config']['Labels']['com.docker.compose.project']='other'
    with pytest.raises(ValueError):validate_state(state,containers,network,'synthetic-daemon',endpoint)


def test_preparation_requires_operator_host_attestation_without_actions(tmp_path):
    with patch('mini_siem.lab.control.execute',side_effect=AssertionError('No software or keys without attestation')):
        with pytest.raises(ValueError):prepare(tmp_path/'runtime')
    assert not (tmp_path/'runtime').exists()


def test_bounded_scenarios_fixed_target_and_intent_not_truth(tmp_path,docker_state):
    state,containers,_=docker_state
    root=tmp_path/'runtime';root.mkdir()
    with patch('mini_siem.lab.control.verify',return_value=(root,state,containers,'synthetic-daemon')),patch('mini_siem.lab.control.time.sleep'),patch('mini_siem.lab.control.subprocess.run',return_value=subprocess.CompletedProcess([],255)) as execute:
        result=scenario(root,'short-failure-sequence')
    assert result['attempts_recorded']==3
    assert execute.call_count==3
    for call in execute.call_args_list:
        command=call.args[0]
        assert 'labuser@ssh-server' in command and '8s' in command
        assert '/lab-keys/wrong' in command
        assert 'StrictHostKeyChecking=yes' in command
        assert call.kwargs['timeout']==10
    run=json.loads(next(root.glob('experiment-*.json')).read_text())
    assert not run['event_labels_assigned'] and not run['intent_is_verified_event_label']
    assert run['test_account']=='labuser' and len(run['actions'])==3
    assert validate_experiment(run,state,containers,'synthetic-daemon')
    changed=deepcopy(run);changed['event_labels_assigned']=True
    with pytest.raises(ValueError):validate_experiment(changed,state,containers,'synthetic-daemon')
    changed=deepcopy(run);changed['server_container_id']='other'
    with pytest.raises(ValueError):validate_experiment(changed,state,containers,'synthetic-daemon')


def test_operator_stop_and_timeout_recorded(tmp_path,docker_state):
    state,containers,_=docker_state
    stopped=tmp_path/'stopped';stopped.mkdir();(stopped/'STOP').touch()
    with patch('mini_siem.lab.control.verify',return_value=(stopped,state,containers,'daemon')),patch('mini_siem.lab.control.subprocess.run') as execute:
        assert scenario(stopped,'success')['status']=='operator_stopped'
        execute.assert_not_called()
    timed=tmp_path/'timed';timed.mkdir()
    with patch('mini_siem.lab.control.verify',return_value=(timed,state,containers,'daemon')),patch('mini_siem.lab.control.subprocess.run',side_effect=subprocess.TimeoutExpired([],10)):
        result=scenario(timed,'success')
    assert result['status']=='aborted_pending_review' and result['attempts_recorded']==1
    run=json.loads(next(timed.glob('experiment-*.json')).read_text())
    assert run['actions'][0]['ended_at_utc'] and run['actions'][0]['client_return_code'] is None


def test_read_only_analysis_no_model_sqlite_or_legacy_parser(raw,provenance,tmp_path,capsys):
    from mini_siem.lab.telemetry import canonical
    records=normalize(raw,provenance);normalized=csv_bytes(records)
    collection={'adapter_version':ADAPTER_VERSION,'provenance':provenance,'experiments':[], 'raw_sha256':sha256(raw),'normalized_sha256':sha256(normalized)}
    (tmp_path/'raw-docker.log').write_bytes(raw);(tmp_path/'events.csv').write_bytes(normalized)
    (tmp_path/'collection.json').write_text(json.dumps(collection))
    (tmp_path/'inventory.json').write_text(json.dumps(inventory_for_collection(records,normalized,raw,collection)))
    before={path:path.read_bytes() for path in tmp_path.iterdir()}
    with patch('sqlite3.connect',side_effect=AssertionError('No SQLite')),patch('mini_siem.ml.model.predict_records',side_effect=AssertionError('No inference')),patch('mini_siem.ingestion.ssh_events.parse_message',side_effect=AssertionError('No historical fallback')):
        assert main(['inspect','--collection-dir',str(tmp_path)])==0
    assert before=={path:path.read_bytes() for path in before}
    assert 'private-marker' not in capsys.readouterr().out
    (tmp_path/'events.csv').write_bytes(normalized+b'tampered')
    assert main(['inspect','--collection-dir',str(tmp_path)])==2


def test_mocked_collection_writes_raw_inventory_without_labels(raw,docker_state,tmp_path):
    from mini_siem.lab.control import collect
    state,containers,_=docker_state
    runtime=tmp_path/'runtime';runtime.mkdir()
    output=tmp_path/'collection'
    with patch('mini_siem.lab.control.verify',return_value=(runtime,state,containers,'synthetic-daemon')),patch('mini_siem.lab.control.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=raw)):
        result=collect(runtime,output,[])
    assert (output/'raw-docker.log').read_bytes()==raw
    assert result['records']==4 and not result['event_labels_assigned']
    inventory=json.loads((output/'inventory.json').read_text())
    assert inventory['quality_review']['status']=='pending'
    assert inventory['labels']['source']=='none'
    assert inventory['provenance']['acquisition_id']=='container:'+containers['ssh-server']['Id']
    assert main(['inspect','--collection-dir',str(output)])==0


def test_incompatible_collection_leaves_no_partial_output(docker_state,tmp_path):
    from mini_siem.lab.control import collect
    state,containers,_=docker_state
    runtime=tmp_path/'runtime';runtime.mkdir();output=tmp_path/'failed'
    with patch('mini_siem.lab.control.verify',return_value=(runtime,state,containers,'synthetic-daemon')),patch('mini_siem.lab.control.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=b'historical,csv\n')):
        with pytest.raises(ValueError):collect(runtime,output,[])
    assert not output.exists()


def test_wrong_lab_experiment_never_collected(docker_state,tmp_path):
    from mini_siem.lab.control import collect
    state,containers,_=docker_state
    root=tmp_path/'runtime';root.mkdir()
    fake={'manifest_version':1,'scenario_id':'success','environment_id':'different-lab','server_container_id':containers['ssh-server']['Id'],'client_container_id':containers['ssh-client']['Id'],'daemon_id':'synthetic-daemon','test_account':'labuser'}
    path=tmp_path/'wrong.json';path.write_text(json.dumps(fake))
    with patch('mini_siem.lab.control.verify',return_value=(root,state,containers,'synthetic-daemon')),patch('mini_siem.lab.control.subprocess.run',side_effect=AssertionError('No collection from wrong lab')):
        with pytest.raises(ValueError):collect(root,tmp_path/'output',[path])


def test_static_private_mount_and_sshd_parent_modes():
    config=json.loads(COMPOSE.read_text())
    assert '/run:rw,noexec,nosuid,size=16m,mode=0755' in config['services']['ssh-server']['tmpfs']
    assert 'UseDNS no' in (COMPOSE.parent/'server/sshd_config').read_text()
    assert all(service['read_only'] for service in config['services'].values())


def test_collection_archives_exact_experiment_evidence(raw,docker_state,tmp_path):
    from mini_siem.lab.control import collect
    state,containers,_=docker_state
    root=tmp_path/'runtime';root.mkdir();output=tmp_path/'capture'
    with patch('mini_siem.lab.control.verify',return_value=(root,state,containers,'synthetic-daemon')),patch('mini_siem.lab.control.subprocess.run',return_value=subprocess.CompletedProcess([],0)):
        scenario(root,'success')
    run_path=next(root.glob('experiment-*.json'));original=run_path.read_bytes()
    with patch('mini_siem.lab.control.verify',return_value=(root,state,containers,'synthetic-daemon')),patch('mini_siem.lab.control.subprocess.run',return_value=subprocess.CompletedProcess([],0,stdout=raw)):
        collect(root,output,[run_path])
    assert (output/'experiments'/run_path.name).read_bytes()==original
    collection=json.loads((output/'collection.json').read_text())
    assert collection['experiments'][0]['manifest_sha256']==sha256(original)
    assert not collection['event_labels_assigned']
