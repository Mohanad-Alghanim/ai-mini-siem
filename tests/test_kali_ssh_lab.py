"""Synthetic native-lab tests: never require root or launch an SSH daemon."""

import json
from pathlib import Path
import signal
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mini_siem.evaluation.inventory import metadata_errors
from mini_siem.kali_ssh_lab import inspect_collection, main
from mini_siem.native_lab import control, safety, telemetry


@pytest.fixture
def state(tmp_path):
    root = tmp_path/'runtime'; root.mkdir()
    value = {'environment_id':'synthetic-lab', 'account':'msl0123456789', 'uid':999, 'gid':65534,
             'files':{'sshd_config':'a'*64}}
    saved = {'pid':123456,'start_ticks':'42','uid':0,'boot_id':'synthetic-boot','executable':safety.SSHD}
    return root, value, saved


@pytest.fixture
def raw():
    return (b'Server listening on 127.0.0.1 port 2222.\n'
            b'Accepted publickey for msl0123456789 from 127.0.0.1 port 50000 ssh2: ED25519 key\n'
            b'Failed publickey for msl0123456789 from 127.0.0.1 port 50001 ssh2\n'
            b'future native message  unchanged \r\n')


@pytest.fixture
def provenance():
    return {'collection_id':'synthetic-collection', 'server_identity':'synthetic-server',
            'environment_id':'synthetic-lab', 'host_boot_id':'synthetic-boot', 'experiment_ids':[]}


def test_configuration_independent_and_restricted():
    text = safety.ssh_config(Path('/run/mini-siem-native-test'), 'msl0123456789')
    for expected in ('ListenAddress 127.0.0.1\n','AddressFamily inet\n','Port 2222\n',
                     'ForceCommand /bin/true\n','DisableForwarding yes\n','PermitUserRC no\n',
                     'PasswordAuthentication no\n','PermitRootLogin no\n','UsePAM no\n'):
        assert expected in text
    assert '/etc/ssh/' not in text and 'Include ' not in text


@pytest.mark.parametrize('address', ['0.0.0.0:2222','*:2222','[::]:2222','[::1]:2222','192.0.2.1:2222'])
def test_nonloopback_or_ipv6_listener_rejected(address):
    with pytest.raises(ValueError):
        safety.listeners(f'LISTEN 0 128 {address} 0.0.0.0:* users:(("sshd",pid=42,fd=3))', 42)


def test_owned_loopback_listener_and_duplicates():
    row = 'LISTEN 0 128 127.0.0.1:2222 0.0.0.0:* users:(("sshd",pid=42,fd=3))'
    assert safety.listeners(row, 42)
    for text in ('', row+'\n'+row, row.replace('pid=42','pid=421')):
        with pytest.raises(ValueError):
            safety.listeners(text, 42)


@pytest.mark.parametrize('path', ['/tmp/lab','/run/mini-siem-native-a/../x','/run/mini-siem-native-x/config','/run/other'])
def test_runtime_scope_fixed(path):
    with pytest.raises(ValueError):
        safety.runtime_path(path)


def test_no_live_action_without_root_kali():
    with patch('mini_siem.native_lab.safety.os.geteuid', return_value=1000), patch('subprocess.Popen', side_effect=AssertionError('no process')):
        assert main(['start','--runtime','/run/mini-siem-native-test']) == 2


def test_pidfd_shutdown_checks_identity_before_signal(state):
    _, _, saved = state
    with patch('os.pidfd_open', return_value=99), patch('mini_siem.native_lab.safety.process_identity', return_value=saved), patch('signal.pidfd_send_signal') as send, patch('os.close') as close:
        safety.terminate(saved)
    send.assert_called_once_with(99, signal.SIGTERM); close.assert_called_once_with(99)
    changed = dict(saved, start_ticks='43')
    with patch('os.pidfd_open', return_value=99), patch('mini_siem.native_lab.safety.process_identity', return_value=changed), patch('signal.pidfd_send_signal') as send, patch('os.close'):
        with pytest.raises(ValueError): safety.terminate(saved)
    send.assert_not_called()


@pytest.mark.parametrize('change', [{'uid':1000},{'executable':'/bin/sleep'},{'boot_id':'another'}])
def test_foreign_process_rejected(state, change):
    _, _, saved = state
    with patch('mini_siem.native_lab.safety.process_identity', return_value=dict(saved, **change)):
        with pytest.raises(ValueError): safety.process_check(saved)


def test_port_occupied_failure():
    with patch('socket.socket') as factory:
        factory.return_value.__enter__.return_value.bind.side_effect = OSError('occupied')
        with pytest.raises(OSError): safety.free_port()


def test_effective_listener_rejected_before_start(state):
    root, _, _ = state
    with patch('mini_siem.native_lab.safety.command', side_effect=['','listenaddress 0.0.0.0:2222\n']):
        with pytest.raises(ValueError): control.effective_config(root)


def test_native_preservation_no_invented_time_or_label(raw, provenance):
    records = telemetry.normalize(raw, provenance)
    assert len(records) == 4
    assert records[-1]['original_message'] == 'future native message  unchanged \r'
    assert records[1]['source_ip'] == '127.0.0.1'
    assert all(r['event_occurred_at'] == r['event_label'] == '' for r in records)
    assert records[0]['source_ip'] == ''
    assert telemetry.summary(records)['unsupported_records'] == 1
    assert not telemetry.summary(records)['inference_allowed']


@pytest.mark.parametrize('data', [b'', b'LineId,Content\n1,Accepted publickey\n',b'Jan 1 12:00 unrelated\n',b'Accepted publickey incomplete',b'\xff\n'])
def test_incompatible_or_partial_format_rejected(data, provenance):
    with pytest.raises((ValueError, UnicodeError)): telemetry.normalize(data, provenance)


@pytest.mark.parametrize('peer,expected', [('127.0.0.1','127.0.0.1'),('::1','::1'),('127.0.0.1:','127.0.0.1'),('999.0.0.1',''),('host.example','')])
def test_strict_source_mapping(peer, expected, provenance):
    rows = telemetry.normalize(f'Received disconnect from {peer} 11: Bye\n'.encode(), provenance)
    assert rows[0]['source_ip'] == expected


def test_overlap_identity_and_inventory(raw, provenance):
    first = telemetry.normalize(raw, provenance)
    second = telemetry.normalize(raw, dict(provenance, collection_id='new-collection'))
    assert [r['event_ref'] for r in first] == [r['event_ref'] for r in second]
    extended = telemetry.normalize(raw+b'Received signal 15; terminating.\n', provenance)
    assert extended[:4] == first
    collection = {'provenance':provenance}
    value = telemetry.inventory(first, telemetry.csv_bytes(first), raw, collection)
    assert not metadata_errors(value)
    assert value['file']['sha256'] == safety.digest(telemetry.csv_bytes(first))
    assert value['quality_review']['status'] == 'pending'
    assert value['timestamps']['fields'] == []
    assert not value['labels']['available']
    assert value['provenance']['dependence_groups'] == ['host:synthetic-boot','lab:synthetic-lab']


def test_fixed_scenarios_and_no_ssh_config_or_target_override(state):
    root, value, saved = state
    (root/'host.pub').write_text('ssh-ed25519 AAAAsynthetic comment\n')
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.verify', return_value=state), patch('mini_siem.native_lab.safety.owned'), patch('mini_siem.native_lab.control.time.sleep'), patch('mini_siem.native_lab.control.subprocess.run', return_value=subprocess.CompletedProcess([],255)) as run:
        result = control.scenario(root, 'three-failures')
    assert result['attempts'] == 3 and run.call_count == 3
    for call in run.call_args_list:
        args = call.args[0]
        assert 'msl0123456789@127.0.0.1' in args
        assert args[1:3] == ['-F','/dev/null']
        assert 'StrictHostKeyChecking=yes' in args
        assert 'ProxyCommand=none' in args and call.kwargs['timeout'] == 10
    manifest = json.loads(next(root.glob('experiment-*.json')).read_text())
    assert not manifest['event_labels_assigned']
    assert len(manifest['actions']) == 3
    assert manifest['server_identity'] == saved


def test_stop_marker_prevents_attempts(state):
    root, _, _ = state
    (root/'host.pub').write_text('ssh-ed25519 AAAAsynthetic comment\n'); (root/'STOP').touch()
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.verify', return_value=state), patch('mini_siem.native_lab.safety.owned'), patch('mini_siem.native_lab.control.subprocess.run') as run:
        result = control.scenario(root, 'success')
    assert result['attempts'] == 0 and result['status'] == 'operator_stopped'
    run.assert_not_called()


def test_timeout_retains_intent_manifest_not_verified_label(state):
    root, _, _ = state
    (root/'host.pub').write_text('ssh-ed25519 AAAAsynthetic comment\n')
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.verify', return_value=state), patch('mini_siem.native_lab.safety.owned'), patch('mini_siem.native_lab.control.subprocess.run', side_effect=subprocess.TimeoutExpired('ssh',10)):
        result = control.scenario(root, 'success')
    manifest = json.loads(next(root.glob('experiment-*.json')).read_text())
    assert result['status'] == 'aborted_pending_review'
    assert manifest['ended_at'] and manifest['actions'][0]['ended_at']
    assert manifest['actions'][0]['client_exit_code'] is None


def test_collection_and_inspection_without_legacy_components(state, raw, tmp_path):
    root, value, saved = state
    (root/'process.json').write_text(json.dumps(saved)); (root/'native.log').write_bytes(raw)
    output = tmp_path/'capture'
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load', return_value=(root,value)), patch('mini_siem.native_lab.safety.owned'), patch('sqlite3.connect', side_effect=AssertionError('no database')), patch('mini_siem.ml.model.predict_records', side_effect=AssertionError('no inference')):
        result = control.collect(root, output)
        assert inspect_collection(output)['quality'] == result
    assert (output/'raw-sshd.log').read_bytes() == raw
    collection = json.loads((output/'collection.json').read_text())
    assert collection['collection_started_at'].endswith('+00:00')
    assert not collection['training_allowed']
    (output/'raw-sshd.log').write_bytes(raw+b'changed\n')
    with pytest.raises(ValueError): inspect_collection(output)


def test_cleanup_refuses_live_listener(state):
    root, value, saved = state
    (root/'process.json').write_text(json.dumps(saved))
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load', return_value=(root,value)), patch('mini_siem.native_lab.safety.process_identity', return_value=saved), patch('mini_siem.native_lab.safety.command') as command:
        with pytest.raises(ValueError): control.cleanup(root)
    command.assert_not_called()


def test_start_refuses_busy_port_without_process_or_config_changes(state):
    root, value, _ = state
    original = 'independent config snapshot'
    (root/'sshd_config').write_text(original)
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load', return_value=(root,value)), patch('mini_siem.native_lab.safety.owned'), patch('mini_siem.native_lab.safety.free_port', side_effect=OSError('occupied')), patch('subprocess.Popen') as spawn:
        with pytest.raises(OSError): control.start(root)
    spawn.assert_not_called()
    assert (root/'sshd_config').read_text() == original


def test_start_verification_failure_only_terminates_own_child(state):
    root, value, saved = state
    child = MagicMock(pid=saved['pid']); child.poll.return_value = None
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load', return_value=(root,value)), patch('mini_siem.native_lab.safety.owned'), patch('mini_siem.native_lab.safety.free_port'), patch('mini_siem.native_lab.control.effective_config'), patch('subprocess.Popen', return_value=child) as spawn, patch('mini_siem.native_lab.safety.process_identity', return_value=saved), patch('mini_siem.native_lab.safety.verify', side_effect=ValueError('wrong address')), patch('mini_siem.native_lab.control.time.sleep'):
        with pytest.raises(ValueError): control.start(root)
    child.terminate.assert_called_once(); child.wait.assert_called_once_with(timeout=3)
    args = spawn.call_args.args[0]
    assert args == [safety.SSHD,'-D','-f',str(root/'sshd_config'),'-E',str(root/'native.log')]
    assert '/etc/ssh/sshd_config' not in args


def test_invalid_log_collection_creates_no_output(state, tmp_path):
    root, value, saved = state
    (root/'process.json').write_text(json.dumps(saved)); (root/'native.log').write_text('not native CSV\n')
    output = tmp_path/'capture'
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load', return_value=(root,value)), patch('mini_siem.native_lab.safety.owned'):
        with pytest.raises(ValueError): control.collect(root,output)
    assert not output.exists()


def test_account_restrictions_fail_closed(state):
    from types import SimpleNamespace
    root, value, _ = state
    user = SimpleNamespace(pw_uid=value['uid'],pw_gid=value['gid'],pw_dir=str(root/'home'),pw_shell='/bin/sh')
    with patch('pwd.getpwnam',return_value=user), patch('mini_siem.native_lab.safety.owned'), patch('os.getgrouplist',return_value=[value['gid'],27]):
        with pytest.raises(ValueError): safety.account_check(root,value)
    with patch('pwd.getpwnam',return_value=user), patch('mini_siem.native_lab.safety.owned'), patch('os.getgrouplist',return_value=[value['gid']]), patch('mini_siem.native_lab.safety.command',return_value='account:real-password:1:0:99999:7:::'):
        with pytest.raises(ValueError): safety.account_check(root,value)


def test_cleanup_refuses_changed_process_identity_to_signal(state):
    root, value, saved = state
    (root/'process.json').write_text(json.dumps(saved))
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load',return_value=(root,value)), patch('mini_siem.native_lab.safety.owned'), patch('mini_siem.native_lab.safety.terminate',side_effect=ValueError('reused PID')), patch('os.kill') as kill:
        with pytest.raises(ValueError): control.stop(root)
    kill.assert_not_called()


@pytest.mark.parametrize('prefix', ['Disconnected from user','Disconnected from authenticating user'])
def test_native_disconnection_source_is_not_username(prefix, provenance):
    record = telemetry.normalize((prefix+' msl0123456789 127.0.0.1 port 50000\n').encode(),provenance)[0]
    assert record['source_ip'] == '127.0.0.1'


def test_concurrent_scenario_refused_before_authentication(state):
    root, _, _ = state
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.verify',return_value=state), patch('mini_siem.native_lab.safety.owned'), patch('fcntl.flock',side_effect=BlockingIOError('busy')), patch('subprocess.run') as run:
        with pytest.raises(BlockingIOError): control.scenario(root,'success')
    run.assert_not_called()


def test_cleanup_removes_only_recorded_account_and_runtime(state):
    root, value, _ = state
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load',return_value=(root,value)), patch('pathlib.Path.iterdir',return_value=iter([])), patch('mini_siem.native_lab.safety.account_check'), patch('mini_siem.native_lab.safety.command') as command, patch('shutil.rmtree') as remove:
        assert control.cleanup(root)['cleaned']
    command.assert_called_once_with(['/usr/sbin/userdel',value['account']])
    remove.assert_called_once_with(root)


def test_collection_preserves_exact_experiment_evidence(state, raw, tmp_path):
    root, value, saved = state
    (root/'process.json').write_text(json.dumps(saved)); (root/'native.log').write_bytes(raw)
    identifier = 'b55327ef-65d8-4ae4-984a-1f93530bdac8'
    run = {'experiment_id':identifier,'environment_id':value['environment_id'],'server_identity':saved,
           'event_labels_assigned':False,'started_at':telemetry.now(),'ended_at':telemetry.now(),
           'version':1,'scenario':'success','account':value['account'],'actions':[],
           'expected_result':'authentication_success','status':'operator_stopped'}
    name = 'experiment-'+identifier+'.json'; original=json.dumps(run,indent=4).encode()
    (root/name).write_bytes(original)
    output = tmp_path/'capture'
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.safety.load',return_value=(root,value)), patch('mini_siem.native_lab.safety.owned'):
        control.collect(root,output)
    assert (output/'experiments'/name).read_bytes() == original
    assert inspect_collection(output)['quality']['records'] == 4
    (output/'experiments'/name).write_text('{}')
    with pytest.raises(ValueError): inspect_collection(output)


def test_preparation_only_creates_disposable_owned_environment(tmp_path):
    from types import SimpleNamespace
    root = tmp_path/'fresh-runtime'
    calls = []
    def local_command(args):
        calls.append(args)
        if args[0] == '/usr/bin/ssh-keygen':
            destination = Path(args[-1])
            destination.write_text('synthetic-private-key')
            Path(str(destination)+'.pub').write_text('ssh-ed25519 synthetic-public-key\n')
        return ''
    with patch('mini_siem.native_lab.safety.root_kali'), patch('mini_siem.native_lab.control.prerequisites',return_value={'tools_available':True}), patch('mini_siem.native_lab.safety.runtime_path',return_value=root), patch('pwd.getpwnam',side_effect=[KeyError('absent'),SimpleNamespace(pw_uid=999,pw_gid=65534)]), patch('mini_siem.native_lab.safety.command',side_effect=local_command), patch('mini_siem.native_lab.safety.load'), patch('subprocess.Popen',side_effect=AssertionError('prepare must not start a process')):
        assert control.prepare(root)['prepared']
    assert calls[0][0] == '/usr/sbin/useradd'
    assert '--system' in calls[0] and '--no-create-home' in calls[0]
    assert len(calls) == 4 and all('systemctl' not in args for args in calls)
    state = json.loads((root/'state.json').read_text())
    assert len(state['files']) == 8
    assert (root/'good').stat().st_mode & 0o777 == 0o600
    assert (root/'home').stat().st_mode & 0o777 == 0o755
    assert 'ListenAddress 127.0.0.1' in (root/'sshd_config').read_text()
