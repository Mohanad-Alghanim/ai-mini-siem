"""Explicit Kali-only lifecycle; fixed commands touch only lab-owned resources."""

import fcntl
import json
import os
from pathlib import Path
import pwd
import resource
import shutil
import subprocess
import time
import uuid

from mini_siem.evaluation.inventory import utc_timestamp
from mini_siem.native_lab import safety
from mini_siem.native_lab.telemetry import VERSION, canonical, csv_bytes, inventory, normalize, now, summary

SCENARIOS = {'success': ('good', 1, 0), 'single-failure': ('wrong', 1, 255),
             'three-failures': ('wrong', 3, 255), 'session-logout': ('good', 1, 0)}
TOOLS = ('/usr/sbin/sshd','/usr/bin/ssh','/usr/bin/ssh-keygen','/usr/bin/ss',
         '/usr/sbin/useradd','/usr/sbin/userdel','/usr/bin/getent')


def write_json(path, value):
    # Root-only files; a torn write fails closed on subsequent inspection.
    with open(path, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def prerequisites():
    return {'tools_available': all(Path(p).is_file() and os.access(p, os.X_OK) for p in TOOLS),
            'root_required_for_lifecycle': True, 'platform_required': 'Kali Linux',
            'pidfd_available': hasattr(os, 'pidfd_open'),
            'privilege_separation_directory_exists': Path('/run/sshd').is_dir(),
            'real_security_validation': 'pending on Kali; no live server started by this check'}


def prepare(runtime):
    safety.root_kali()
    if not prerequisites()['tools_available']:
        raise ValueError('Install prerequisites manually before preparation')
    root = safety.runtime_path(runtime)
    root.mkdir(mode=0o711, exist_ok=False)
    os.chmod(root, 0o711)
    account = 'msl'+uuid.uuid4().hex[:10]
    try:
        pwd.getpwnam(account)
    except KeyError:
        pass
    else:
        raise ValueError('Refuse to reuse an existing account')
    # Save ownership intent before account creation so a failed preparation can
    # be inspected manually. Never claim a pre-existing account as ours.
    write_json(root/'preparation.json', {'account': account, 'status': 'account_creation_requested'})
    safety.command(['/usr/sbin/useradd', '--system', '--no-create-home', '--no-user-group',
                    '--gid', 'nogroup', '--home-dir', str(root/'home'), '--shell', '/bin/sh',
                    '--password', 'x', account])
    user = pwd.getpwnam(account)
    state = {'version': 1, 'runtime': str(root), 'environment_id': str(uuid.uuid4()),
             'account': account, 'uid': user.pw_uid, 'gid': user.pw_gid, 'created_at': now(), 'files': {}}
    write_json(root/'preparation.json', dict(state, status='account_created_pending_keys'))
    # Home is root-owned and not writable by the disposable account. It holds
    # only the public authorized key; private keys stay root-only in runtime.
    (root/'home').mkdir(mode=0o755); os.chmod(root/'home', 0o755)
    for key in ('host', 'good', 'wrong'):
        safety.command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C',
                        'disposable-native-lab', '-f', str(root/key)])
        (root/key).chmod(0o600); (root/(key+'.pub')).chmod(0o600)
    shutil.copyfile(root/'good.pub', root/'home/authorized_keys')
    (root/'home/authorized_keys').chmod(0o644)
    (root/'sshd_config').write_text(safety.ssh_config(root, account)); (root/'sshd_config').chmod(0o600)
    for name in ('host','host.pub','good','good.pub','wrong','wrong.pub','sshd_config','home/authorized_keys'):
        state['files'][name] = safety.digest((root/name).read_bytes())
    write_json(root/'state.json', state)
    safety.load(root)
    return {'prepared': True, 'account': account, 'software_installed': False, 'server_started': False}


def effective_config(root):
    safety.command([safety.SSHD, '-t', '-f', str(root/'sshd_config')])
    lines = safety.command([safety.SSHD, '-T', '-f', str(root/'sshd_config')]).splitlines()
    addresses = [line.split(maxsplit=1)[1] for line in lines if line.startswith('listenaddress ')]
    if addresses != ['127.0.0.1:2222']:
        raise ValueError('Effective SSH listener must be IPv4 loopback only')


def child_limits():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (5*1024*1024, 5*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def start(runtime):
    safety.root_kali()
    root, state = safety.load(runtime)
    if (root/'process.json').exists() or (root/'native.log').exists():
        raise ValueError('Use a fresh runtime; process/log histories cannot be overwritten')
    safety.owned(Path('/run/sshd'), private=False)
    safety.free_port()
    effective_config(root)
    # Fixed -f and -E, no global config edits, no systemctl/service invocation.
    with open(root/'startup-error.log', 'xb', opener=lambda p, f: os.open(p, f, 0o600)) as error:
        process = subprocess.Popen([safety.SSHD, '-D', '-f', str(root/'sshd_config'), '-E', str(root/'native.log')],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=error,
                    start_new_session=True, preexec_fn=child_limits,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    try:
        saved = safety.process_identity(process.pid)
        write_json(root/'process.json', saved)
        for _ in range(20):
            if process.poll() is not None:
                raise ValueError('Dedicated SSH process exited during startup')
            try:
                safety.verify(root)
                return {'started': True, 'listener': '127.0.0.1:2222', 'pid': process.pid}
            except (ValueError, FileNotFoundError):
                time.sleep(.1)
        raise ValueError('Dedicated listener verification timed out')
    except BaseException:
        # Popen still owns this unreaped child, so its PID cannot be recycled.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        raise


def scenario(runtime, name):
    safety.root_kali()
    root, _, _ = safety.verify(runtime)
    # Serialize scenario execution; no queued/concurrent authentication bursts.
    descriptor = os.open(root/'scenario.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        safety.owned(root/'scenario.lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _scenario(runtime, name)
    finally:
        os.close(descriptor)


def _scenario(runtime, name):
    safety.root_kali()
    root, state, saved = safety.verify(runtime)
    key, limit, expected = SCENARIOS[name]
    host_type, host_blob, *_ = (root/'host.pub').read_text().split()
    known = root/'known_hosts'
    pinned = f'[127.0.0.1]:2222 {host_type} {host_blob}\n'
    if known.exists():
        safety.owned(known)
        if known.read_text() != pinned:
            raise ValueError('Pinned host key changed')
    else:
        known.write_text(pinned); known.chmod(0o600)
    run = {'version':1, 'experiment_id':str(uuid.uuid4()), 'scenario':name,
           'environment_id':state['environment_id'], 'server_identity':saved,
           'account':state['account'], 'started_at':now(), 'ended_at':None,
           'expected_result':'authentication_success' if key=='good' else 'authentication_rejection',
           'event_labels_assigned':False, 'actions':[], 'status':'in_progress',
           'evidence':'native.log from this process; collection and manual correlation required'}
    path = root/('experiment-'+run['experiment_id']+'.json')
    write_json(path, run)
    try:
        for index in range(limit):
            if (root/'STOP').exists():
                run['status'] = 'operator_stopped'; break
            _, _, current = safety.verify(root)
            if current != saved:
                raise ValueError('SSH process changed during scenario')
            args = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', '2222',
                    '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
                    '-o','ProxyCommand=none','-o','ProxyJump=none','-o','ConnectionAttempts=1',
                    '-o','ConnectTimeout=3','-o','ServerAliveInterval=2','-o','ServerAliveCountMax=1',
                    '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
                    '-o','StrictHostKeyChecking=yes','-o','GlobalKnownHostsFile=/dev/null',
                    '-o','UserKnownHostsFile='+str(known),'-i',str(root/key),
                    state['account']+'@127.0.0.1','/bin/true']
            action = {'attempt':index+1, 'started_at':now(), 'ended_at':None,
                      'credential_role':key, 'client_exit_code':None,
                      'authorized_action':'one key authentication; forced /bin/true session'}
            run['actions'].append(action); write_json(path, run)
            try:
                result = subprocess.run(args, capture_output=True, timeout=10,
                                        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                action['client_exit_code'] = result.returncode
            finally:
                action['ended_at'] = now()
            if result.returncode != expected:
                run['status'] = 'unexpected_client_result'; break
            if index+1 < limit:
                for _ in range(20):
                    if (root/'STOP').exists():
                        break
                    time.sleep(.1)
        else:
            run['status'] = 'completed_pending_evidence_review'
    except KeyboardInterrupt:
        run['status'] = 'operator_interrupted'
    except (OSError, ValueError, subprocess.SubprocessError):
        run['status'] = 'aborted_pending_review'
    finally:
        run['ended_at'] = now(); write_json(path, run)
    return {'experiment_id':run['experiment_id'], 'status':run['status'],
            'attempts':len(run['actions']), 'event_labels_assigned':False}


def stop(runtime):
    safety.root_kali()
    root, _ = safety.load(runtime)
    (root/'STOP').touch(mode=0o600)
    safety.owned(root/'process.json')
    saved = json.loads((root/'process.json').read_text())
    try:
        safety.terminate(saved)
    except (FileNotFoundError, ProcessLookupError):
        return {'stopped': True, 'already_exited': True}
    for _ in range(30):
        try:
            current = safety.process_identity(saved['pid'])
            if current != saved:
                break
        except (FileNotFoundError, ProcessLookupError):
            break
        time.sleep(.1)
    else:
        raise ValueError('Process has not exited; manual review required, no broad kill used')
    return {'stopped': True}



def validate_experiment(run, state, saved):
    if run['version'] != 1 or run['scenario'] not in SCENARIOS:
        raise ValueError('Unsupported experiment format')
    if run['environment_id'] != state['environment_id'] or run['server_identity'] != saved or run['account'] != state['account'] or run['event_labels_assigned'] is not False:
        raise ValueError('Foreign experiment or unsupported event labels')
    uuid.UUID(run['experiment_id'])
    start, end = utc_timestamp(run['started_at']), utc_timestamp(run['ended_at'])
    key, limit, _ = SCENARIOS[run['scenario']]
    expected = 'authentication_success' if key == 'good' else 'authentication_rejection'
    if end < start or run['expected_result'] != expected or len(run['actions']) > limit or run['status'] not in ('operator_stopped','operator_interrupted','aborted_pending_review','unexpected_client_result','completed_pending_evidence_review'):
        raise ValueError('Inconsistent experiment intent or completion state')
    for number, action in enumerate(run['actions'], 1):
        if action['attempt'] != number or action['credential_role'] != key or not start <= utc_timestamp(action['started_at']) <= utc_timestamp(action['ended_at']) <= end:
            raise ValueError('Invalid bounded action provenance')
        if action['client_exit_code'] is not None and type(action['client_exit_code']) is not int:
            raise ValueError('Invalid client return code')


def collect(runtime, output):
    safety.root_kali()
    root, state = safety.load(runtime)
    safety.owned(root/'process.json')
    saved = json.loads((root/'process.json').read_text())
    # Snapshot after stop is allowed. Provenance identifies the process that
    # created the log; an exited server is not silently replaced or restarted.
    safety.owned(root/'native.log')
    started = now(); raw = (root/'native.log').read_bytes()
    experiments = {}
    for path in sorted(root.glob('experiment-*.json')):
        safety.owned(path); content = path.read_bytes(); run = json.loads(content)
        validate_experiment(run, state, saved)
        if path.name != 'experiment-'+str(uuid.UUID(run['experiment_id']))+'.json':
            raise ValueError('Invalid experiment identity')
        experiments[path.name] = content
    provenance = {'collection_id':str(uuid.uuid4()), 'environment_id':state['environment_id'],
        'server_identity':safety.digest(canonical(saved)), 'host_boot_id':saved['boot_id'],
        'process':saved, 'account':state['account'],
        'experiment_ids':[json.loads(data)['experiment_id'] for data in experiments.values()]}
    records = normalize(raw, provenance); normalized = csv_bytes(records)
    collection = {'version':1, 'adapter':VERSION, 'provenance':provenance,
        'collection_started_at':started, 'collection_finished_at':now(),
        'configuration_sha256':state['files']['sshd_config'],
        'raw_sha256':safety.digest(raw), 'normalized_sha256':safety.digest(normalized),
        'experiments':{name:safety.digest(data) for name,data in experiments.items()},
        'source':'dedicated native OpenSSH -E process log', 'event_labels_assigned':False,
        'limitations':['native messages have no asserted original event timestamps',
                      'run references are collection-level intent, not event labels',
                      'snapshot completeness and clock validity require review'],
        'training_allowed':False, 'inference_allowed':False}
    draft = inventory(records, normalized, raw, collection)
    target = Path(output)
    if target.exists() or target.resolve().is_relative_to(root):
        raise ValueError('Use a fresh output directory outside runtime')
    target.mkdir(parents=True, mode=0o700, exist_ok=False)
    (target/'raw-sshd.log').write_bytes(raw); (target/'events.csv').write_bytes(normalized)
    for name, value in (('collection.json',collection),('inventory.json',draft),('quality.json',summary(records))):
        write_json(target/name, value)
    if experiments:
        (target/'experiments').mkdir(mode=0o700)
        for name, data in experiments.items():
            (target/'experiments'/name).write_bytes(data)
    return summary(records)


def cleanup(runtime):
    safety.root_kali()
    root, state = safety.load(runtime)
    # Never delete an account while any process runs under its UID, or while
    # its listener is still alive. No userdel -f / -r, no process-group signals.
    if (root/'process.json').exists():
        saved = json.loads((root/'process.json').read_text())
        try:
            current = safety.process_identity(saved['pid'])
            if all(current[key] == saved[key] for key in ('pid','start_ticks','boot_id')):
                raise ValueError('Stop and verify the dedicated SSH process before cleanup')
        except (FileNotFoundError, ProcessLookupError):
            pass
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit():
            try:
                if proc.stat().st_uid == state['uid']:
                    raise ValueError('Account still has processes; cleanup refused')
            except FileNotFoundError:
                continue
    if any(path.is_symlink() for path in root.rglob('*')):
        raise ValueError('Runtime symlinks require manual review')
    safety.account_check(root, state)
    safety.command(['/usr/sbin/userdel', state['account']])
    shutil.rmtree(root)
    return {'cleaned':True, 'account_removed':True, 'captures_outside_runtime_preserved':True}
