"""Fail-closed checks for a dedicated root-owned loopback SSH process."""

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess

SSHD = '/usr/sbin/sshd'
PORT = 2222


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=15,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode:
        raise ValueError('Local prerequisite or SSH validation failed')
    return result.stdout


def root_kali():
    if os.geteuid() != 0 or 'ID=kali' not in Path('/etc/os-release').read_text().splitlines():
        raise ValueError('Lifecycle actions require explicit root execution on Kali Linux')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise ValueError('Linux pidfd support is required for safe shutdown')


def runtime_path(value):
    path = Path(value)
    if not re.fullmatch(r'/run/mini-siem-native-[a-z0-9-]{1,40}', str(path)):
        raise ValueError('Use a fresh direct /run/mini-siem-native-NAME directory')
    if path.is_symlink() or path.resolve() != path:
        raise ValueError('Runtime symlinks are forbidden')
    return path


def digest(content):
    return hashlib.sha256(content).hexdigest()


def owned(path, private=True):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & (0o077 if private else 0o022):
        raise ValueError('Lab resource ownership or permissions changed')
    return info


def load(runtime):
    root = runtime_path(runtime)
    owned(root, private=False)
    owned(root/'state.json')
    state = json.loads((root/'state.json').read_text())
    if state['runtime'] != str(root) or not re.fullmatch(r'msl[0-9a-f]{10}', state['account']):
        raise ValueError('Invalid lab resource identity')
    for name, expected in state['files'].items():
        if name not in ('sshd_config', 'host', 'host.pub', 'good', 'good.pub', 'wrong', 'wrong.pub', 'home/authorized_keys'):
            raise ValueError('Unrecognized prepared file')
        owned(root/name, private=name != 'home/authorized_keys')
        if digest((root/name).read_bytes()) != expected:
            raise ValueError('Prepared SSH configuration/key changed')
    if set(state['files']) != {'sshd_config','host','host.pub','good','good.pub','wrong','wrong.pub','home/authorized_keys'}:
        raise ValueError('Incomplete prepared environment')
    if (root/'sshd_config').read_text() != ssh_config(root, state['account']):
        raise ValueError('Independent SSH configuration does not match fixed policy')
    account_check(root, state)
    return root, state


def account_check(root, state):
    account = pwd.getpwnam(state['account'])
    if account.pw_uid != state['uid'] or account.pw_uid == 0 or account.pw_dir != str(root/'home') or account.pw_shell != '/bin/sh':
        raise ValueError('Disposable account identity changed')
    owned(root/'home', private=False)
    groups = os.getgrouplist(state['account'], account.pw_gid)
    if set(groups) != {state['gid']} or account.pw_gid != state['gid']:
        raise ValueError('Disposable account must not have supplementary privileges')
    # Invalid password hash is intentionally not prefixed with !: public-key
    # authentication must remain usable, while all password methods are disabled.
    shadow = command(['/usr/bin/getent', 'shadow', state['account']]).strip().split(':')
    if len(shadow) != 9 or shadow[1] != 'x' or shadow[7] not in ('', '-1'):
        raise ValueError('Disposable account password policy changed')


def ssh_config(root, account):
    return f'''AddressFamily inet
ListenAddress 127.0.0.1
Port {PORT}
HostKey {root}/host
PidFile {root}/sshd.pid
AuthorizedKeysFile {root}/home/authorized_keys
AllowUsers {account}
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
UseDNS no
StrictModes yes
DisableForwarding yes
PermitTTY no
PermitUserRC no
PermitUserEnvironment no
ForceCommand /bin/true
MaxAuthTries 1
MaxSessions 1
MaxStartups 2
LoginGraceTime 10
LogLevel VERBOSE
'''


def free_port():
    # A wildcard bind also rejects an occupied loopback address. sshd performs
    # the final exclusive bind; a race cannot be treated as successful startup.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('0.0.0.0', PORT))


def process_identity(pid):
    if type(pid) is not int or pid <= 1:
        raise ValueError('Invalid process identifier')
    proc = Path('/proc')/str(pid)
    fields = (proc/'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': fields[19],
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'uid': proc.stat().st_uid, 'executable': os.readlink(proc/'exe')}


def process_check(saved):
    current = process_identity(saved['pid'])
    if current != saved or current['uid'] != 0 or current['executable'] != SSHD:
        raise ValueError('Process identity changed; refuse to signal or trust it')


def listeners(text, pid):
    rows = [line.split() for line in text.splitlines() if line.strip()]
    matching = [row for row in rows if len(row) >= 5 and row[3].endswith(':'+str(PORT))]
    if len(matching) != 1 or matching[0][3] != f'127.0.0.1:{PORT}' or not re.search(r'pid='+str(pid)+r'\b', ' '.join(matching[0][5:])):
        raise ValueError('Expected exactly one owned IPv4 loopback listener, no wildcard/IPv6 listener')
    return True


def verify(runtime):
    root, state = load(runtime)
    owned(root/'process.json')
    saved = json.loads((root/'process.json').read_text())
    process_check(saved)
    listeners(command(['/usr/bin/ss', '-H', '-ltnp']), saved['pid'])
    return root, state, saved


def terminate(saved):
    # Open a pidfd first, then validate /proc identity: PID reuse cannot redirect
    # the subsequent signal to an unrelated process.
    descriptor = os.pidfd_open(saved['pid'])
    try:
        process_check(saved)
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
    finally:
        os.close(descriptor)
